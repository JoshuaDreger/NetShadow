"""
NetShadow Live Dashboard
Sniffs traffic in real-time and shows a high-level view of all external
connections — who you're talking to, how much data, which direction.
Designed to give a quick gut-check for unexpected outbound beaconing.

Keyboard shortcuts:
  i      — toggle interface picker
  1–9    — switch to interface (while picker is open)
  r      — reset stats for current interface
  q / ^C — quit
"""

import os
import queue
import select
import socket
import sys
import termios
import threading
import time
import tty
from dataclasses import dataclass, field
from typing import Optional

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list, get_if_addr
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from enricher import get_ipinfo


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_external(ip: str) -> bool:
    if ip.startswith(("10.", "127.", "169.254.")):
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
    if n < 1024:        return f"{n} B"
    if n < 1024 ** 2:   return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:   return f"{n / 1024 ** 2:.1f} MB"
    return f"{n / 1024 ** 3:.1f} GB"


def _get_local_ips() -> set:
    local = {"127.0.0.1", "::1", "0.0.0.0"}
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
            if addr:
                local.add(addr)
        except Exception:
            pass
    return local


def _list_interfaces() -> list[tuple[str, str]]:
    """Return [(name, ip), ...] for all available interfaces."""
    result = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface) or ""
        except Exception:
            ip = ""
        result.append((iface, ip))
    return result


# ── keyboard reader ───────────────────────────────────────────────────────────

class _KeyboardReader:
    """Non-blocking single-character reader using cbreak mode."""

    def __enter__(self):
        self._fd = sys.stdin.fileno()
        self._old = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)
        return self

    def __exit__(self, *_):
        termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)

    def read(self, timeout: float = 0.1) -> Optional[str]:
        """Return next key or None if nothing pressed within timeout."""
        if select.select([sys.stdin], [], [], timeout)[0]:
            return sys.stdin.read(1)
        return None


# ── data model ────────────────────────────────────────────────────────────────

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
    hostname: Optional[str] = None
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
        self._stop = threading.Event()           # exit the whole dashboard
        self._sniffer_stop = threading.Event()   # stop only the current sniffer
        self._show_picker = False
        self._interfaces = _list_interfaces()
        self.console = Console()

    # ── sniffer ────────────────────────────────────────────────────────────

    def _start_sniffer(self) -> tuple[threading.Thread, list]:
        """Spawn a sniffer thread for self.iface. Returns (thread, error_list)."""
        self._sniffer_stop = threading.Event()
        errors: list = []

        def _run():
            try:
                sniff(
                    iface=self.iface,
                    prn=self._process,
                    store=False,
                    stop_filter=lambda _: self._sniffer_stop.is_set() or self._stop.is_set(),
                )
            except PermissionError:
                errors.append("permission")
                self._stop.set()
            except (OSError, ValueError) as e:
                errors.append(str(e))
                self._stop.set()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t, errors

    def _switch_iface(self, new_iface: str):
        """Stop current sniffer, reset stats, restart on new_iface."""
        self._sniffer_stop.set()          # stop current sniffer
        time.sleep(0.15)                  # let it drain
        with self.lock:
            self.endpoints.clear()
            self.total_pkts = 0
            self.total_bytes_in = 0
            self.total_bytes_out = 0
            self.start_time = time.monotonic()
        self.iface = new_iface
        self.local_ips = _get_local_ips()
        self._start_sniffer()

    def _reset_stats(self):
        with self.lock:
            self.endpoints.clear()
            self.total_pkts = 0
            self.total_bytes_in = 0
            self.total_bytes_out = 0
            self.start_time = time.monotonic()

    # ── packet processing ──────────────────────────────────────────────────

    def _process(self, pkt):
        if not pkt.haslayer(IP):
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        pkt_len = len(pkt)

        src_local = (src in self.local_ips) or (not _is_external(src))
        dst_local = (dst in self.local_ips) or (not _is_external(dst))

        if src_local and not dst_local:
            remote, direction = dst, "out"
        elif dst_local and not src_local:
            remote, direction = src, "in"
        else:
            return

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

    # ── enrichment ─────────────────────────────────────────────────────────

    def _enricher(self):
        import cache as _cache
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

            cached = _cache.get(ip)

            # Hostname — use cache, then DNS
            hostname = cached.get("hostname", None) if cached else None
            if hostname is None:
                try:
                    hostname = socket.getfqdn(ip)
                    hostname = "" if hostname == ip else hostname
                except Exception:
                    hostname = ""
                _cache.put(ip, hostname=hostname)

            # Country / org — use cache, then ipinfo API
            country = cached.get("country", None) if cached else None
            org = cached.get("org", None) if cached else None
            if country is None:
                if os.getenv("IPINFO_TOKEN"):
                    try:
                        info = get_ipinfo(ip)   # get_ipinfo also writes cache
                        country = info.get("country", "?")
                        org = info.get("org", "?")
                    except Exception:
                        country, org = "?", "?"
                else:
                    country, org = "?", "?"

            with self.lock:
                if ip in self.endpoints:
                    self.endpoints[ip].hostname = hostname
                    self.endpoints[ip].country = country or "?"
                    self.endpoints[ip].org = org or "?"
            self._resolve_q.task_done()

    # ── rendering ──────────────────────────────────────────────────────────

    def _header(self) -> Panel:
        elapsed = time.monotonic() - self.start_time
        h, m, s = int(elapsed // 3600), int((elapsed % 3600) // 60), int(elapsed % 60)
        with self.lock:
            n_ep = len(self.endpoints)
            pkts = self.total_pkts
            b_in, b_out = self.total_bytes_in, self.total_bytes_out
            unsolicited = sum(
                1 for ep in self.endpoints.values()
                if ep.pkts_in > 0 and ep.pkts_out == 0
            )
        warn = f"  [bold yellow]⚠ {unsolicited} unsolicited[/bold yellow]" if unsolicited else ""
        body = (
            f"[bold cyan]Interface:[/bold cyan] [bold]{self.iface}[/bold]  "
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
            box=box.SIMPLE_HEAD, show_header=True,
            header_style="bold cyan", expand=True, show_lines=False,
        )
        table.add_column("Dir",       width=4,  justify="center", no_wrap=True)
        table.add_column("Remote IP", min_width=16, no_wrap=True)
        table.add_column("Hostname",  min_width=24)
        table.add_column("CC",        width=4,  justify="center", no_wrap=True)
        table.add_column("Org / ASN", min_width=22)
        table.add_column("↑ Pkts",    width=7,  justify="right",  no_wrap=True)
        table.add_column("↓ Pkts",    width=7,  justify="right",  no_wrap=True)
        table.add_column("↑ Sent",    width=9,  justify="right",  no_wrap=True)
        table.add_column("↓ Recv",    width=9,  justify="right",  no_wrap=True)
        table.add_column("Protocols", min_width=18)

        for ip, ep in items:
            if ep.pkts_out > 0 and ep.pkts_in > 0:
                dir_cell, row_style = Text("↔", style="bold white"), ""
            elif ep.pkts_out > 0:
                dir_cell, row_style = Text("→", style="bold green"), ""
            else:
                dir_cell, row_style = Text("←", style="bold red"), "yellow"

            hostname = (
                ep.hostname if ep.hostname is not None
                else Text("resolving…", style="dim")
            )
            protocols = "  ".join(sorted(ep.protocols)[:4])
            if len(ep.protocols) > 4:
                protocols += f" +{len(ep.protocols) - 4}"

            table.add_row(
                dir_cell, ip,
                str(hostname) if isinstance(hostname, str) else hostname,
                ep.country, ep.org[:30],
                str(ep.pkts_out), str(ep.pkts_in),
                _human_bytes(ep.bytes_out), _human_bytes(ep.bytes_in),
                protocols,
                style=row_style,
            )

        if not items:
            table.add_row("", "[dim]Waiting for traffic…[/dim]", "", "", "", "", "", "", "", "")
        return table

    def _picker(self) -> Panel:
        """Interface picker overlay."""
        table = Table(box=box.SIMPLE, show_header=False, expand=False, padding=(0, 1))
        table.add_column("Key",   style="bold cyan",  width=4,  no_wrap=True)
        table.add_column("Name",  style="bold",        min_width=16, no_wrap=True)
        table.add_column("IP",    style="dim",         min_width=16, no_wrap=True)
        table.add_column("",      width=10)

        for idx, (name, ip) in enumerate(self._interfaces, start=1):
            key = str(idx) if idx <= 9 else " "
            marker = "[bold green] ◀ active[/bold green]" if name == self.iface else ""
            table.add_row(f"[{key}]", name, ip or "—", marker)

        return Panel(
            table,
            title="[bold cyan]Switch Interface[/bold cyan]",
            subtitle="[dim]press number to switch  │  [i] to close[/dim]",
            border_style="cyan",
            expand=False,
        )

    def _statusbar(self) -> Panel:
        picker_hint = "[bold cyan]\\[i][/bold cyan] close picker" if self._show_picker else "[bold cyan]\\[i][/bold cyan] interfaces"
        keys = (
            f" [bold green]→[/bold green] outgoing  "
            f"[bold red]←[/bold red] incoming (unsolicited=[yellow]yellow[/yellow])  "
            f"[bold white]↔[/bold white] bidirectional"
            f"  [dim]│[/dim]  "
            f"{picker_hint}  "
            f"[bold cyan]\\[r][/bold cyan] reset stats  "
            f"[bold cyan]\\[q][/bold cyan] quit"
        )
        return Panel(keys, border_style="dim", padding=(0, 1))

    def _render(self):
        parts = [self._header(), self._table(), self._statusbar()]
        if self._show_picker:
            parts.insert(1, self._picker())
        return Group(*parts)

    # ── main loop ──────────────────────────────────────────────────────────

    def run(self):
        threading.Thread(target=self._enricher, daemon=True).start()

        _, errors = self._start_sniffer()
        time.sleep(0.4)
        if errors:
            self._handle_sniffer_error(errors[0])

        self.console.print(
            f"[green][+] Monitoring [bold]{self.iface}[/bold]  —  "
            f"[bold cyan]i[/bold cyan]=interfaces  "
            f"[bold cyan]r[/bold cyan]=reset  "
            f"[bold cyan]q[/bold cyan]=quit[/green]\n"
        )

        try:
            with _KeyboardReader() as kbd, Live(
                console=self.console, refresh_per_second=2, screen=True
            ) as live:
                while not self._stop.is_set():
                    live.update(self._render())
                    key = kbd.read(timeout=0.1)
                    if key:
                        self._handle_key(key)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()
            self._sniffer_stop.set()
            import cache as _cache
            _cache.flush()
            total, fresh = _cache.stats()
            self.console.print(f"[yellow][*] Stopped.[/yellow]  [dim](cache: {fresh}/{total} fresh entries)[/dim]")

    def _handle_key(self, key: str):
        if key in ("q", "\x03"):          # q or Ctrl+C
            self._stop.set()
        elif key == "i":
            self._show_picker = not self._show_picker
        elif key == "r":
            self._reset_stats()
        elif key.isdigit() and self._show_picker:
            idx = int(key) - 1
            if 0 <= idx < len(self._interfaces):
                new_iface = self._interfaces[idx][0]
                if new_iface != self.iface:
                    self._switch_iface(new_iface)
                self._show_picker = False

    def _handle_sniffer_error(self, err: str):
        if err == "permission":
            self.console.print("[red][!] Permission denied — run with sudo.[/red]")
        elif "not found" in err.lower():
            self.console.print(f"[red][!] Interface '[bold]{self.iface}[/bold]' not found.[/red]")
            self.console.print("[yellow]Available interfaces:[/yellow]")
            for name, ip in self._interfaces:
                self.console.print(f"  {name}  {ip or ''}")
        else:
            self.console.print(f"[red][!] Capture error: {err}[/red]")
        sys.exit(1)


def run_dashboard(iface: str = None):
    LiveDashboard(iface=iface).run()
