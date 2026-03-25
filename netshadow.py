#!/usr/bin/env python3
"""NetShadow — pcap threat analysis CLI."""

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def main():
    parser = argparse.ArgumentParser(
        prog="netshadow",
        description="Analyze a pcap file for network threats using VirusTotal, ipinfo, and Claude AI.",
    )
    parser.add_argument("pcap", help="Path to the .pcap file")
    parser.add_argument("--output", default="report.html", help="Output HTML report path (default: report.html)")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"[error] File not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing {pcap_path} ...")
    from parser import extract_external_ips
    ips = extract_external_ips(str(pcap_path))
    if not ips:
        print("[!] No external IPs found in capture. Nothing to analyze.")
        sys.exit(0)
    print(f"[+] Found {len(ips)} unique external IP(s).")

    print("[*] Enriching IPs (ipinfo + VirusTotal) ...")
    from enricher import enrich
    enriched = enrich(ips)

    print("[*] Scoring IPs with Claude AI ...")
    from scorer import score_ips
    scored, summary = score_ips(enriched)

    print("[*] Generating HTML report ...")
    from reporter import generate_html
    html_content = generate_html(pcap_path.name, scored, summary)

    output_path = Path(args.output)
    output_path.write_text(html_content, encoding="utf-8")
    print(f"[+] Report saved to: {output_path.resolve()}")


if __name__ == "__main__":
    main()
