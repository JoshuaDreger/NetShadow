#!/usr/bin/env python3
"""
NetShadow — network threat analysis CLI

Commands:
  analyze   Analyze an existing pcap file and generate an HTML report
  capture   Capture live traffic to a pcap file
  monitor   Capture live traffic then immediately analyze it (one-shot check)
  dashboard Live terminal dashboard of all external connections
"""

import argparse
import sys
import tempfile
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


# ── subcommand handlers ───────────────────────────────────────────────────────

def cmd_analyze(args):
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"[error] File not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing {pcap_path} ...")
    from parser import extract_external_ips
    ips = extract_external_ips(str(pcap_path))
    if not ips:
        print("[!] No external IPs found in capture.")
        sys.exit(0)
    print(f"[+] Found {len(ips)} unique external IP(s).")

    print("[*] Enriching IPs (ipinfo + VirusTotal) ...")
    from enricher import enrich
    enriched = enrich(ips)

    print("[*] Scoring IPs ...")
    from scorer import score_ips
    scored, summary = score_ips(enriched)

    print("[*] Generating HTML report ...")
    from reporter import generate_html
    html = generate_html(pcap_path.name, scored, summary)

    out = Path(args.output)
    out.write_text(html, encoding="utf-8")
    print(f"[+] Report saved to: {out.resolve()}")


def cmd_capture(args):
    from capture import capture_to_pcap, list_interfaces

    if args.list_interfaces:
        list_interfaces()
        return

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    capture_to_pcap(
        output_path=str(out),
        duration=args.duration,
        count=args.count,
        iface=args.iface,
    )


def cmd_monitor(args):
    """Capture live traffic, then run the full analysis pipeline."""
    from capture import capture_to_pcap, list_interfaces
    from rich.console import Console
    console = Console()

    if args.list_interfaces:
        list_interfaces()
        return

    # Capture to a temp file or named output
    if args.pcap_output:
        pcap_path = Path(args.pcap_output)
    else:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False, dir="pcap")
        pcap_path = Path(tmp.name)
        tmp.close()

    pcap_path.parent.mkdir(parents=True, exist_ok=True)

    n = capture_to_pcap(
        output_path=str(pcap_path),
        duration=args.duration,
        count=args.count,
        iface=args.iface,
    )

    if n == 0:
        console.print("[yellow][!] No packets captured — nothing to analyze.[/yellow]")
        sys.exit(0)

    console.print("\n[bold cyan][*] Running analysis...[/bold cyan]")

    from parser import extract_external_ips
    ips = extract_external_ips(str(pcap_path))
    if not ips:
        console.print("[yellow][!] No external IPs found in capture.[/yellow]")
        sys.exit(0)
    console.print(f"[green][+] Found {len(ips)} unique external IP(s).[/green]")

    console.print("[cyan][*] Enriching IPs...[/cyan]")
    from enricher import enrich
    enriched = enrich(ips)

    console.print("[cyan][*] Scoring IPs...[/cyan]")
    from scorer import score_ips
    scored, summary = score_ips(enriched)

    console.print("[cyan][*] Generating report...[/cyan]")
    from reporter import generate_html
    html = generate_html(pcap_path.name, scored, summary)

    out = Path(args.output)
    out.write_text(html, encoding="utf-8")
    console.print(f"\n[bold green][+] Report saved to: {out.resolve()}[/bold green]")

    # Print a quick risk summary to the terminal
    from collections import Counter
    dist = Counter(ip["risk_level"] for ip in scored)
    _colors = {"Critical": "red", "High": "yellow", "Medium": "cyan", "Low": "blue", "Clean": "green"}
    console.print("\n[bold]Risk summary:[/bold]")
    for level in ("Critical", "High", "Medium", "Low", "Clean"):
        count = dist.get(level, 0)
        if count:
            color = _colors[level]
            console.print(f"  [{color}]{level}[/{color}]: {count}")


def cmd_dashboard(args):
    from dashboard import run_dashboard
    run_dashboard(iface=args.iface)


# ── CLI definition ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="netshadow",
        description="NetShadow — network threat analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # ── analyze ──
    p_analyze = sub.add_parser("analyze", help="Analyze a pcap file → HTML report")
    p_analyze.add_argument("pcap", help="Path to the .pcap file")
    p_analyze.add_argument("--output", default="report.html", metavar="FILE",
                           help="Output HTML report path (default: report.html)")

    # ── capture ──
    p_capture = sub.add_parser("capture", help="Capture live traffic to a pcap file")
    p_capture.add_argument("--duration", type=int, default=60, metavar="SECS",
                           help="Capture duration in seconds (default: 60)")
    p_capture.add_argument("--count", type=int, metavar="N",
                           help="Stop after N packets (overrides --duration)")
    p_capture.add_argument("--iface", metavar="IF",
                           help="Network interface (default: auto-detect)")
    p_capture.add_argument("--output", default="pcap/capture.pcap", metavar="FILE",
                           help="Output pcap path (default: pcap/capture.pcap)")
    p_capture.add_argument("--list-interfaces", action="store_true",
                           help="List available network interfaces and exit")

    # ── monitor ──
    p_monitor = sub.add_parser("monitor",
                                help="Capture live traffic then analyze it (one-shot check)")
    p_monitor.add_argument("--duration", type=int, default=60, metavar="SECS",
                            help="Capture duration in seconds (default: 60)")
    p_monitor.add_argument("--count", type=int, metavar="N",
                            help="Stop after N packets (overrides --duration)")
    p_monitor.add_argument("--iface", metavar="IF",
                            help="Network interface (default: auto-detect)")
    p_monitor.add_argument("--output", default="report.html", metavar="FILE",
                            help="Output HTML report path (default: report.html)")
    p_monitor.add_argument("--save-pcap", dest="pcap_output", metavar="FILE",
                            help="Also save the capture to this pcap file")
    p_monitor.add_argument("--list-interfaces", action="store_true",
                            help="List available network interfaces and exit")

    # ── dashboard ──
    p_dash = sub.add_parser("dashboard",
                             help="Live terminal dashboard of external connections")
    p_dash.add_argument("--iface", metavar="IF",
                        help="Network interface (default: auto-detect)")

    args = parser.parse_args()

    dispatch = {
        "analyze":   cmd_analyze,
        "capture":   cmd_capture,
        "monitor":   cmd_monitor,
        "dashboard": cmd_dashboard,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
