"""
NetShadow Live Dashboard
Sniffs traffic in real-time and shows a high-level view of all external
connections — who you're talking to, how much data, which direction.
Designed to give a quick gut-check for unexpected outbound beaconing.
"""

import os
import queue
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from enricher import get_ipinfo


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_external(ip: str) -> bool:
    """Return True if the IP is NOT a private/loopback/link-local address."""
    if ip.startswith("10.") or ip.startswith("127.") or ip.startswith("169.254."):
        return False
    if ip.startswith("192.168."):
        return False
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                if 16 <= int(parts[1]) <= 31:
                    return False
            except ValueError:
                pass
    if ip.lower() in ("::1", "0.0.0.0") or ip.lower().startswith(("fc", "fd", "fe80")):
        return False
    return True


def _human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / 1024 ** 2:.1f} MB"
    return f"{n / 1024 ** 3:.1f} GB"


def _get_local_ips() -> set:
    local = {"127.0.0.1", "::1", "0.0.0.0"}
    try:
        from scapy.all import get_if_list, get_if_addr
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
                if addr:
                    local.add(addr)
            except Exception:
                pass
    except Exception:
        pass
    return local


# ── data model ───────────────────────────────────────────────────────────────

@dataclass
class EndpointStats:
    ip: str
    pkts_out: int = 0
    pkts_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    protocols: set = field(default_factory=set)
    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    hostname: Optional[str] = None   # None = pending, "" = no rDNS
    country: str = "…"
    org: str = "…"


# ── dashboard ─────────────────────────────────────────────────────────────────

class LiveDashboard:
    def __init__(self, iface: str = None):
        self.iface = iface or str(conf.iface)
        self.endpoints: dict[str, EndpointStats] = {}
        self.lock = threading.Lock()
        self.total_pkts = 0
        self.total_bytes_in = 0
        self.total_bytes_out = 0
        self.start_time = time.monotonic()
        self.local_ips = _get_local_ips()
        self._resolve_q: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self.console = Console()

    # ── packet processing ──────────────────────────────────────────────────

    def _process(self, pkt):
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        pkt_len = len(pkt)

        src_local = (src in self.local_ips) or (not _is_external(src))
        dst_local = (dst in self.local_ips) or (not _is_external(dst))

        if src_local and not dst_local:
            remote, direction = dst, "out"
        elif dst_local and not src_local:
            remote, direction = src, "in"
        else:
            return  # both internal or both external — skip

        # Protocol / port string
        if pkt.haslayer(TCP):
            port = pkt[TCP].dport if direction == "out" else pkt[TCP].sport
            proto_str = f"TCP/{port}"
        elif pkt.haslayer(UDP):
            port = pkt[UDP].dport if direction == "out" else pkt[UDP].sport
            proto_str = f"UDP/{port}"
        elif pkt.haslayer(ICMP):
            proto_str = "ICMP"
        else:
            proto_str = "IP"

        with self.lock:
            self.total_pkts += 1
            if direction == "out":
                self.total_bytes_out += pkt_len
            else:
                self.total_bytes_in += pkt_len

            if remote not in self.endpoints:
                self.endpoints[remote] = EndpointStats(ip=remote)
                self._resolve_q.put(remote)

            ep = self.endpoints[remote]
            ep.last_seen = time.monotonic()
            ep.protocols.add(proto_str)
            if direction == "out":
                ep.pkts_out += 1
                ep.bytes_out += pkt_len
            else:
                ep.pkts_in += 1
                ep.bytes_in += pkt_len

    # ── background enrichment ──────────────────────────────────────────────

    def _enricher(self):
        seen: set = set()
        while not self._stop.is_set():
            try:
                ip = self._resolve_q.get(timeout=1.0)
            except queue.Empty:
                continue
            if ip in seen:
                self._resolve_q.task_done()
                continue
            seen.add(ip)

            # Reverse DNS (local, fast)
            try:
                hostname = socket.getfqdn(ip)
                hostname = "" if hostname == ip else hostname
            except Exception:
                hostname = ""

            # ipinfo enrichment (only if token is set)
            country, org = "?", "?"
            if os.getenv("IPINFO_TOKEN"):
                try:
                    info = get_ipinfo(ip)
                    country = info.get("country", "?")
                    org = info.get("org", "?")
                except Exception:
                    pass

            with self.lock:
                if ip in self.endpoints:
                    self.endpoints[ip].hostname = hostname
                    self.endpoints[ip].country = country
                    self.endpoints[ip].org = org

            self._resolve_q.task_done()

    # ── rendering ─────────────────────────────────────────────────────────

    def _header(self) -> Panel:
        elapsed = time.monotonic() - self.start_time
        h = int(elapsed // 3600)
        m = int((elapsed % 3600) // 60)
        s = int(elapsed % 60)

        with self.lock:
            n_ep = len(self.endpoints)
            pkts = self.total_pkts
            b_in = self.total_bytes_in
            b_out = self.total_bytes_out

        # Separate incoming-only count (potential unsolicited connections)
        with self.lock:
            unsolicited = sum(
                1 for ep in self.endpoints.values()
                if ep.pkts_in > 0 and ep.pkts_out == 0
            )

        warn = f"  [bold yellow]⚠ {unsolicited} unsolicited incoming[/bold yellow]" if unsolicited else ""
        body = (
            f"[bold cyan]Interface:[/bold cyan] {self.iface}  "
            f"[bold cyan]Runtime:[/bold cyan] {h:02d}:{m:02d}:{s:02d}  "
            f"[bold cyan]Packets:[/bold cyan] {pkts:,}  "
            f"[bold cyan]↑[/bold cyan] {_human_bytes(b_out)}  "
            f"[bold cyan]↓[/bold cyan] {_human_bytes(b_in)}  "
            f"[bold cyan]Endpoints:[/bold cyan] {n_ep}"
            f"{warn}"
        )
        return Panel(body, title="[bold]NetShadow Live Monitor[/bold]", border_style="cyan")

    def _table(self) -> Table:
        with self.lock:
            items = sorted(
                self.endpoints.items(),
                key=lambda x: x[1].bytes_in + x[1].bytes_out,
                reverse=True,
            )

        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            expand=True,
            show_lines=False,
        )
        table.add_column("Dir", width=4, justify="center", no_wrap=True)
        table.add_column("Remote IP", min_width=16, no_wrap=True)
        table.add_column("Hostname", min_width=24)
        table.add_column("CC", width=4, justify="center", no_wrap=True)
        table.add_column("Org / ASN", min_width=22)
        table.add_column("↑ Pkts", width=7, justify="right", no_wrap=True)
        table.add_column("↓ Pkts", width=7, justify="right", no_wrap=True)
        table.add_column("↑ Sent", width=9, justify="right", no_wrap=True)
        table.add_column("↓ Recv", width=9, justify="right", no_wrap=True)
        table.add_column("Protocols", min_width=18)

        for ip, ep in items:
            if ep.pkts_out > 0 and ep.pkts_in > 0:
                dir_cell = Text("↔", style="bold white")
                row_style = ""
            elif ep.pkts_out > 0:
                dir_cell = Text("→", style="bold green")
                row_style = ""
            else:
                # Incoming only — highlight as potentially unsolicited
                dir_cell = Text("←", style="bold red")
                row_style = "yellow"

            hostname = (
                ep.hostname if ep.hostname is not None
                else Text("resolving…", style="dim")
            )

            # Show up to 4 protocol/port combos, sorted
            protocols = "  ".join(sorted(ep.protocols)[:4])
            if len(ep.protocols) > 4:
                protocols += f" +{len(ep.protocols) - 4}"

            table.add_row(
                dir_cell,
                ip,
                str(hostname) if isinstance(hostname, str) else hostname,
                ep.country,
                ep.org[:30],
                str(ep.pkts_out),
                str(ep.pkts_in),
                _human_bytes(ep.bytes_out),
                _human_bytes(ep.bytes_in),
                protocols,
                style=row_style,
            )

        if not items:
            table.add_row("", "[dim]Waiting for traffic…[/dim]", "", "", "", "", "", "", "", "")

        return table

    def _legend(self) -> str:
        return (
            "[dim]  [bold green]→[/bold green] outgoing  "
            "[bold red]←[/bold red] incoming (unsolicited = [yellow]highlighted[/yellow])  "
            "[bold white]↔[/bold white] bidirectional  │  "
            "Sorted by total bytes  │  Ctrl+C to stop[/dim]"
        )

    # ── main loop ─────────────────────────────────────────────────────────

    def run(self):
        # Start enrichment thread
        threading.Thread(target=self._enricher, daemon=True).start()

        # Start sniffer thread — surface permission errors early
        sniffer_error: list = []

        def _sniffer():
            try:
                sniff(
                    iface=self.iface,
                    prn=self._process,
                    store=False,
                    stop_filter=lambda _: self._stop.is_set(),
                )
            except PermissionError:
                sniffer_error.append("permission")
                self._stop.set()
            except (OSError, ValueError) as e:
                sniffer_error.append(str(e))
                self._stop.set()

        sniffer_thread = threading.Thread(target=_sniffer, daemon=True)
        sniffer_thread.start()

        # Give sniffer a moment to fail if it's going to
        time.sleep(0.4)
        if sniffer_error:
            err = sniffer_error[0]
            if err == "permission":
                self.console.print("[red][!] Permission denied — run with sudo.[/red]")
            elif "not found" in err.lower():
                self.console.print(
                    f"[red][!] Interface '[bold]{self.iface}[/bold]' not found.[/red]\n"
                    f"[yellow]Available interfaces:[/yellow]"
                )
                from scapy.all import get_if_list
                for iface in get_if_list():
                    self.console.print(f"  {iface}")
            else:
                self.console.print(f"[red][!] Capture error: {err}[/red]")
            sys.exit(1)

        self.console.print(
            f"[green][+] Monitoring [bold]{self.iface}[/bold] — Ctrl+C to stop[/green]\n"
        )

        try:
            with Live(console=self.console, refresh_per_second=2, screen=True) as live:
                while not self._stop.is_set():
                    live.update(Group(
                        self._header(),
                        self._table(),
                        self._legend(),
                    ))
                    time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()
            self.console.print("\n[yellow][*] Stopped.[/yellow]")


def run_dashboard(iface: str = None):
    LiveDashboard(iface=iface).run()
