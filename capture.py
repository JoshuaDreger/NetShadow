"""Live packet capture to pcap file."""

import sys
import time
import threading

from scapy.all import sniff, wrpcap, conf, get_if_list
from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn, TextColumn,
)

console = Console()


def _default_iface() -> str:
    return str(conf.iface)


def list_interfaces():
    console.print("[bold cyan]Available interfaces:[/bold cyan]")
    for iface in get_if_list():
        console.print(f"  {iface}")


def capture_to_pcap(
    output_path: str,
    duration: int = None,
    count: int = None,
    iface: str = None,
) -> int:
    """
    Capture live traffic and write to pcap.
    Specify duration (seconds) OR count (packets), or both.
    Returns number of packets captured.
    """
    if not duration and not count:
        duration = 60  # default

    iface = iface or _default_iface()
    result: list = []
    error: list = []

    def _sniff():
        kwargs = {"iface": iface, "store": True}
        if duration:
            kwargs["timeout"] = duration
        if count:
            kwargs["count"] = count
        try:
            result.append(sniff(**kwargs))
        except PermissionError:
            error.append("permission")
        except (OSError, ValueError) as e:
            error.append(str(e))

    t = threading.Thread(target=_sniff, daemon=True)

    if duration and not count:
        # Show a time-based progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Capturing on [bold]{iface}[/bold]", total=duration)
            t.start()

            # Give the thread a moment to start and surface any permission error
            time.sleep(0.3)
            if error:
                _handle_error(error[0], iface)

            start = time.monotonic()
            while t.is_alive():
                elapsed = time.monotonic() - start
                progress.update(task, completed=min(elapsed, duration))
                time.sleep(0.2)
            progress.update(task, completed=duration)
    else:
        console.print(f"[cyan][*] Capturing {count} packets on [bold]{iface}[/bold]...[/cyan]")
        t.start()
        t.join()

    if error:
        _handle_error(error[0], iface)

    pkts = result[0] if result else []
    wrpcap(output_path, pkts)
    n = len(pkts)
    console.print(f"[green][+] Captured {n} packets → {output_path}[/green]")
    return n


def _handle_error(err: str, iface: str):
    if err == "permission":
        console.print("[red][!] Permission denied — packet capture requires root.[/red]")
        console.print("    [dim]sudo python netshadow.py ...[/dim]")
    elif "No such device" in err or "no such device" in err.lower():
        console.print(f"[red][!] Interface '[bold]{iface}[/bold]' not found.[/red]")
        list_interfaces()
    else:
        console.print(f"[red][!] Capture error: {err}[/red]")
    sys.exit(1)
