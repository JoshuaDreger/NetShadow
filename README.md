# NetShadow

A Python CLI tool for network threat analysis with two modes: **static analysis** of packet captures and a **live terminal dashboard** for real-time connection monitoring. Built to answer the question *"who is my machine actually talking to right now?"*

---

## Static Analysis — pcap → HTML Report

Parse a `.pcap` file, enrich every external IP via VirusTotal and ipinfo.io, score each endpoint by risk, and generate a self-contained HTML report.

![NetShadow static analysis report](screenshot.png)

> Open [`report_demo.html`](report_demo.html) in your browser to explore a fully interactive example.

```bash
python netshadow.py analyze capture.pcap --output report.html
```

The report includes a sortable risk table, color-coded rows, and an executive summary generated from the scoring results.

---

## Live Dashboard — real-time connection monitor

Sniff live traffic and see every external connection update in real time — direction, hostname, country, org, bytes transferred, and protocols. Designed for a quick gut-check: *is anything on this machine phoning home that shouldn't be?*

```bash
sudo python netshadow.py dashboard --iface wlp4s0
```

```
╭──────────────────────────────────── NetShadow Live Monitor ─────────────────────────────────────╮
│ Interface: wlp4s0  Runtime: 00:03:47  Packets: 3,241  ↑ 1.1 MB  ↓ 4.8 MB  Endpoints: 14        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────╯

  Dir   Remote IP         Hostname                      CC   Org / ASN              ↑ Pkts  ↓ Pkts   ↑ Sent    ↓ Recv   Protocols
 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ↔     142.250.x.x       muc11s23-in-f14.1e100.net     DE   AS15169 Google LLC        412     891   243.1 KB    1.2 MB  TCP/443  UDP/443
  ↔     140.82.x.x        lb-140-82-x-x.github.com      US   AS36459 GitHub, Inc.      208     275   530.8 KB   76.7 KB  TCP/443
  ↔     104.16.x.x        —                             US   AS13335 Cloudflare         91     144    48.2 KB   312.5 KB  UDP/443
  ↔     13.107.x.x        —                             US   AS8075 Microsoft Corp.      31      38     5.3 KB   70.3 KB  TCP/443
  →     34.x.x.x          ec2-34-x.compute-1.aws.com    US   AS14618 Amazon AWS          22       0    14.1 KB       0 B  TCP/443
  ←     185.220.x.x       tor-exit.example.net          DE   AS208323 (Hosting)           0      11        0 B    6.2 KB  TCP/443

╭─────────────────────────────────────────────────────────────────────────────────────────────────╮
│  → outgoing  ← incoming (unsolicited=yellow)  ↔ bidirectional  │  [i] interfaces  [r] reset  [q] quit  │
╰─────────────────────────────────────────────────────────────────────────────────────────────────╯
```

> Incoming-only rows (`←`) are highlighted yellow — data arriving without an outbound connection initiated from this machine is the primary signal for unexpected C2 beaconing.

### Interface Switcher

Press `i` to open the interface picker mid-session. All stats reset instantly on switch.

```
╭─ Switch Interface ──────────────────────────╮
│  [1]  lo        127.0.0.1                   │
│  [2]  enp2s0    —                           │
│  [3]  wlp4s0    192.168.1.x   ◀ active      │
│  [4]  docker0   172.17.0.1                  │
╰──  press number to switch  │  [i] to close  ╯
```

### Keyboard Shortcuts

| Key     | Action                                              |
|---------|-----------------------------------------------------|
| `i`     | Toggle interface picker                             |
| `1`–`9` | Switch to interface by number (picker must be open) |
| `r`     | Reset stats for the current interface               |
| `q`     | Quit                                                |

---

## One-shot Botnet Check

Capture live traffic, enrich all IPs, and get a full HTML report in one command:

```bash
sudo python netshadow.py monitor --duration 120 --output report.html
```

```
[+] Captured 4,892 packets → pcap/tmp.pcap
[*] Running analysis...
[+] Found 23 unique external IP(s).
[*] Enriching IPs...
[*] Scoring IPs...
[*] Generating report...

[+] Report saved to: /home/user/NetShadow/report.html

Risk summary:
  Critical: 1
  High: 2
  Medium: 3
  Low: 8
  Clean: 9
```

---

## Installation

```bash
git clone https://github.com/yourname/NetShadow
cd NetShadow
pip install -r requirements.txt
cp .env.example .env   # add API keys (optional)
```

### API Keys

Both are optional — the tool degrades gracefully without them.

| Variable             | Source                      | Effect if missing             |
|----------------------|-----------------------------|-------------------------------|
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/ | VT detections show as 0/0     |
| `IPINFO_TOKEN`       | https://ipinfo.io/          | Country / Org show as Unknown |

> The free VirusTotal tier allows 4 requests/minute. NetShadow rate-limits automatically.

---

## All Commands

```
python netshadow.py analyze   <pcap> [--output FILE]
sudo python netshadow.py capture   [--duration SECS] [--count N] [--iface IF] [--output FILE]
sudo python netshadow.py monitor   [--duration SECS] [--count N] [--iface IF] [--output FILE]
sudo python netshadow.py dashboard [--iface IF]
```

| Command     | Flag           | Default             | Description                            |
|-------------|----------------|---------------------|----------------------------------------|
| `analyze`   | `pcap`         | —                   | Path to `.pcap` file (required)        |
| `analyze`   | `--output`     | `report.html`       | Output HTML report path                |
| `capture`   | `--duration`   | `60`                | Capture duration in seconds            |
| `capture`   | `--count`      | —                   | Stop after N packets                   |
| `capture`   | `--iface`      | auto                | Network interface                      |
| `capture`   | `--output`     | `pcap/capture.pcap` | Output pcap path                       |
| `monitor`   | `--duration`   | `60`                | Capture duration in seconds            |
| `monitor`   | `--save-pcap`  | —                   | Also save the raw capture              |
| `dashboard` | `--iface`      | auto                | Network interface                      |

---

## Scoring Logic

Risk levels are assigned by rule-based logic — no external AI API required.

| Condition                        | Risk Level |
|----------------------------------|------------|
| VT detections ≥ 10               | Critical   |
| VT detections 5–9                | High       |
| VT detections 2–4                | Medium     |
| VT detections = 1                | Low        |
| VT reputation ≤ −50              | Critical   |
| VT reputation ≤ −20              | High       |
| VT reputation < 0                | Medium     |
| High-risk country (CN/RU/KP/IR…) | Medium/Low |
| Hosting / VPN / proxy ASN        | Low        |
| No VT data available             | Low        |
| No detections, no flags          | Clean      |

---

## IP Enrichment Cache

Resolved hostnames, ipinfo.io results, and VirusTotal lookups are cached at `~/.cache/netshadow/ip_cache.json` with a 24-hour TTL. Repeated runs and dashboard sessions skip API calls for already-known IPs. Override the TTL with `NETSHADOW_CACHE_TTL=<seconds>`.

---

## Project Structure

```
NetShadow/
├── netshadow.py       # CLI entrypoint (analyze / capture / monitor / dashboard)
├── parser.py          # pcap parsing and IP extraction (scapy)
├── capture.py         # live packet capture with progress bar
├── dashboard.py       # live terminal dashboard with keyboard controls
├── enricher.py        # ipinfo.io + VirusTotal enrichment
├── scorer.py          # rule-based risk scoring
├── reporter.py        # standalone HTML report generation
├── cache.py           # persistent IP enrichment cache
├── report_demo.html   # interactive demo report (example data)
├── requirements.txt
└── .env.example
```
