# NetShadow

A Python CLI tool that analyzes `.pcap` files for network threats using VirusTotal and ipinfo.io enrichment with rule-based risk scoring.

## Demo

Open [`report_demo.html`](report_demo.html) in your browser to see a sample report, or preview below:

![NetShadow demo report](screenshot.png)

## Features

- Extracts all unique external IPs from a packet capture (filters RFC1918/loopback)
- Enriches each IP with geolocation and ASN data via ipinfo.io
- Checks each IP against VirusTotal v3 for malicious detection counts
- Assigns a risk level (Critical / High / Medium / Low / Clean) per IP using rule-based logic
- Generates a standalone, sortable HTML report with color-coded risk rows and an executive summary

## Requirements

- Python 3.10+
- API keys for VirusTotal and ipinfo.io

## Installation

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

## Usage

```bash
python netshadow.py pcap/capture.pcap --output report.html
```

### Options

| Argument   | Description                              | Default       |
|------------|------------------------------------------|---------------|
| `pcap`     | Path to the `.pcap` file (required)      | —             |
| `--output` | Output path for the HTML report          | `report.html` |

## API Keys

Set these environment variables (or put them in a `.env` file):

| Variable              | Source                          |
|-----------------------|---------------------------------|
| `VIRUSTOTAL_API_KEY`  | https://www.virustotal.com/     |
| `IPINFO_TOKEN`        | https://ipinfo.io/              |

> **Note:** The free VirusTotal tier allows 4 requests/minute. NetShadow automatically rate-limits to stay within this quota.

## Scoring Logic

Risk is determined by the following rules, evaluated in priority order:

| Condition                               | Risk Level |
|-----------------------------------------|------------|
| VT detections ≥ 10                      | Critical   |
| VT detections 5–9                       | High       |
| VT detections 2–4                       | Medium     |
| VT detections = 1                       | Low        |
| Reputation ≤ −50                        | Critical   |
| Reputation ≤ −20                        | High       |
| Reputation < 0                          | Medium     |
| High-risk country (CN/RU/KP/IR…)        | Medium/Low |
| Hosting / VPN / proxy ASN               | Low        |
| No VT data                              | Low        |
| No detections, no flags                 | Clean      |

## Output

The HTML report includes:

- **Header** — filename, timestamp, total endpoints found
- **Executive Summary** — overview of the capture with threat highlights
- **Risk Table** — sortable table with IP, hostname, country, org, VT detections, risk level, and reasoning
- **Risk Distribution** — color-coded summary cards at the bottom

### Risk Level Colors

| Level    | Color  |
|----------|--------|
| Critical | Red    |
| High     | Orange |
| Medium   | Yellow |
| Low      | Blue   |
| Clean    | Green  |

## Project Structure

```
NetShadow/
├── netshadow.py       # CLI entrypoint
├── parser.py          # pcap parsing (scapy)
├── enricher.py        # ipinfo.io + VirusTotal enrichment
├── scorer.py          # rule-based risk scoring
├── reporter.py        # HTML report generation
├── report_demo.html   # sample report (demo data)
├── requirements.txt
├── .env.example
└── pcap/              # put your .pcap files here (gitignored)
```
