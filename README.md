```
███╗   ██╗ ██╗   ██╗ ██╗      ██╗      ███████╗ ███████╗  ██████╗
████╗  ██║ ██║   ██║ ██║      ██║      ██╔════╝ ██╔════╝ ██╔════╝
██╔██╗ ██║ ██║   ██║ ██║      ██║      ███████╗ █████╗   ██║
██║╚██╗██║ ██║   ██║ ██║      ██║      ╚════██║ ██╔══╝   ██║
██║ ╚████║ ╚██████╔╝ ███████╗ ███████╗ ███████║ ███████╗ ╚██████╗
╚═╝  ╚═══╝  ╚═════╝  ╚══════╝ ╚══════╝ ╚══════╝ ╚══════╝  ╚═════╝
```

# NullSec — Bug Bounty Reconnaissance Automation Framework

**A complete 12-phase recon pipeline for bug bounty hunters and security researchers.**  
Written in Bash. Runs on Kali Linux. Built for real engagements.

[![Language](https://img.shields.io/badge/language-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/author-NullSecHQ-cyan?style=flat-square)](https://github.com/NullSecHQ)

---

## Overview

NullSec automates the full recon lifecycle — from passive subdomain discovery through active vulnerability confirmation — in a single script. It is designed to run unattended, resume from checkpoints, and deliver a structured report at the end.

The pipeline supports three scan modes tuned for different cadences: **fast** for hourly runs, **normal** for daily coverage, and **deep** for thorough weekly audits or first-time target onboarding.

---

## Features

- **12-phase pipeline** covering the complete recon methodology
- **3 scan modes** — fast / normal / deep — each with pre-tuned settings
- **Checkpoint & resume** — interrupted scans pick up where they left off (`-c` flag)
- **Parallel execution** — Phases 8–11 run concurrently for speed
- **Asset scoring** — ranks hosts by attack potential so you focus where it counts
- **Cloud storage enumeration** — AWS S3, GCS, and Azure Blob tested in parallel
- **JS secret extraction** — TruffleHog (verified) + targeted regex for AWS, GitHub, Stripe, Slack, Google keys
- **Telegram notifications** — real-time alerts on critical findings and scan completion
- **Rate limiting mode** — polite delays between phases for sensitive targets (`-r` flag)
- **Optional tools** — script degrades gracefully when optional tools are absent

---

## Pipeline Overview

| Phase | Name | Key Tools | Mode |
|-------|------|-----------|------|
| 1 | Subdomain Discovery | subfinder, amass, assetfinder, puredns, hakrawler | All |
| 2 | Validation & Resolution | dnsx, nuclei (takeovers) | All |
| 2.5 | Cloud Storage Enumeration | curl, s3scanner, cloud_enum | Normal + Deep |
| 3 | Live Web Service Probing | httpx-toolkit, ffuf (vhosts) | All |
| 4 | Port Scanning | naabu, httpx-toolkit | Normal + Deep |
| 5 | URL Discovery & Crawling | katana, hakrawler, cariddi, waybackurls, gau, gf | All |
| 6 | Parameter Discovery | unfurl, arjun | All |
| 6b | Asset Scoring & Prioritization | bash (local computation) | Normal + Deep |
| 7 | Vulnerability Scanning | nuclei | All |
| 8 | JavaScript Analysis | trufflehog, httpx-toolkit | Normal + Deep |
| 9 | Vulnerability Pattern Hunting | dalfox, sqlmap, curl | Normal + Deep |
| 10 | Screenshots | gowitness | Normal + Deep |
| 11 | Directory & Content Fuzzing | ffuf | Deep |
| 12 | Active Vulnerability Confirmation | nuclei | Deep |

---

## Scan Modes

```
fast    Passive sources only, critical-only Nuclei, no bruteforce or active steps
        Skips: DNS bruteforce, port scan, JS analysis, fuzzing, active confirmation
        Runtime: ~5–15 min   |   Good for: hourly scheduled runs

normal  Full discovery + JS analysis + pattern hunting, skips heaviest active steps
        Skips: permutations, Arjun, directory fuzzing, active confirmation
        Runtime: ~30–60 min  |   Good for: daily scheduled runs

deep    Full 12-phase pipeline — everything enabled, all caps raised
        Runtime: 1–4+ hours  |   Good for: weekly runs, new target onboarding
```

---

## Requirements

### System

- **OS:** Kali Linux (recommended) or any Debian-based distro
- **Shell:** Bash 4.x+
- **Permissions:** root or sudo for some tools (naabu, puredns)

### Required Tools

These must be installed before running. The script will exit if any are missing.

| Tool | Install |
|------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [amass](https://github.com/owasp-amass/amass) | `go install github.com/owasp-amass/amass/v4/...@master` |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | `go install github.com/tomnomnom/assetfinder@latest` |
| [puredns](https://github.com/d3mondev/puredns) | `go install github.com/d3mondev/puredns/v2@latest` |
| [dnsx](https://github.com/projectdiscovery/dnsx) | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| [httpx-toolkit](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [naabu](https://github.com/projectdiscovery/naabu) | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| [katana](https://github.com/projectdiscovery/katana) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | `go install github.com/tomnomnom/waybackurls@latest` |
| [gau](https://github.com/lc/gau) | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [unfurl](https://github.com/tomnomnom/unfurl) | `go install github.com/tomnomnom/unfurl@latest` |
| [arjun](https://github.com/s0md3v/Arjun) | `pip3 install arjun` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [ffuf](https://github.com/ffuf/ffuf) | `go install github.com/ffuf/ffuf/v2@latest` |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| [jq](https://stedolan.github.io/jq/) | `apt install jq` |
| [curl](https://curl.se/) | `apt install curl` |

### Optional Tools

These enhance results but are not required — the script skips relevant steps if they are absent.

| Tool | Purpose | Install |
|------|---------|---------|
| [gotator](https://github.com/Josue87/gotator) | Subdomain permutation generation | `go install github.com/Josue87/gotator@latest` |
| [gowitness](https://github.com/sensepost/gowitness) | Screenshots of live hosts | `go install github.com/sensepost/gowitness@latest` |
| [dalfox](https://github.com/hahwul/dalfox) | Automated XSS confirmation | `go install github.com/hahwul/dalfox/v2@latest` |
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | SQL injection testing | `apt install sqlmap` |
| [gf](https://github.com/tomnomnom/gf) | High-signal URL pattern matching | `go install github.com/tomnomnom/gf@latest` |
| [anew](https://github.com/tomnomnom/anew) | Efficient deduplication / append-new | `go install github.com/tomnomnom/anew@latest` |
| [qsreplace](https://github.com/tomnomnom/qsreplace) | Query string replacement | `go install github.com/tomnomnom/qsreplace@latest` |
| [hakrawler](https://github.com/hakluke/hakrawler) | Lightweight HTTP spider | `go install github.com/hakluke/hakrawler@latest` |
| [cariddi](https://github.com/edoardottt/cariddi) | Crawler with built-in secret detection | `go install github.com/edoardottt/cariddi/cmd/cariddi@latest` |
| [s3scanner](https://github.com/sa7mon/S3Scanner) | Comprehensive S3 bucket checks | `pip3 install s3scanner` |
| [cloud_enum](https://github.com/initstring/cloud_enum) | Multi-cloud asset enumeration | `pip3 install cloud-enum` |
| [dig](https://linux.die.net/man/1/dig) | DNS resolution (vhost scanning) | `apt install dnsutils` |

---

## Wordlists

NullSec expects wordlists under `/usr/share/wordlists/`. The following are required for full functionality.

### SecLists (primary)

```bash
git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
```

> **[SecLists](https://github.com/danielmiessler/SecLists)** — the definitive wordlist collection for security assessments.  
> Used for: DNS bruteforce, permutation generation, directory fuzzing, backup file discovery.

Specific lists used by the script:

| Variable | Path | Purpose |
|----------|------|---------|
| `DNS_WORDLIST` | `SecLists/Discovery/DNS/subdomains-top1million-110000.txt` | DNS bruteforce (Phase 1) |
| `PERM_WORDLIST` | `SecLists/Discovery/DNS/subdomains-top1million-5000.txt` | Permutation base (Phase 1) |
| `WEB_WORDLIST` | `SecLists/Discovery/Web-Content/raft-large-directories.txt` | Directory fuzzing (Phase 11) |

### DNS Resolvers

```bash
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
  -O /usr/share/wordlists/resolvers.txt
```

> **[trickest/resolvers](https://github.com/trickest/resolvers)** — curated list of reliable public DNS resolvers.  
> Used by puredns and dnsx for fast, accurate resolution.

---

## GF Patterns

[GF patterns](https://github.com/tomnomnom/gf) are used in Phase 5 to pre-filter URLs by vulnerability class before testing, dramatically reducing noise in Phases 9 and 12. Install the patterns alongside the `gf` tool.

```bash
# Install gf
go install github.com/tomnomnom/gf@latest

# Install community pattern collection (1Ndianl33t)
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
```

> **[1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns)** — community-maintained GF pattern set covering XSS, SQLi, SSRF, IDOR, LFI, and open redirects.

Patterns used by NullSec:

| Pattern | Matches | Phase |
|---------|---------|-------|
| `xss` | Reflection parameter candidates | Phase 5 → 9 |
| `sqli` | SQL injection parameter candidates | Phase 5 → 9 |
| `ssrf` | Server-side request forgery candidates | Phase 5 → 9 |
| `redirect` | Open redirect candidates | Phase 5 → 9 |
| `lfi` | Local file inclusion candidates | Phase 5 → 9 |
| `idor` | Insecure direct object reference candidates | Phase 5 → 9 |

The script falls back to regex-based matching if a pattern is not installed.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/NullSecHQ/nullsec-framework.git
cd nullsec-framework

# Make executable
chmod +x nullsec.sh

# Install Go tools (example — adjust GOPATH as needed)
export PATH=$PATH:$(go env GOPATH)/bin

# Verify all required tools are present
./nullsec.sh -d example.com -s   # -s skips tool check; remove to validate
```

---

## Usage

```
Usage: ./nullsec.sh -d <target-domain> [options]

Options:
  -d <domain>       Target domain (required)
  -o <dir>          Output directory (default: ./recon-<domain>-<timestamp>)
  -m <mode>         Scan mode: fast | normal | deep  (default: normal)
  -s                Skip tool checking
  -u                Update Nuclei templates before scanning
  -r                Enable rate limiting / polite delays between phases
  -c <dir>          Resume scan from checkpoint in existing output directory
  -h                Show this help message
```

### Examples

```bash
# Quick passive scan (hourly cadence)
./nullsec.sh -d example.com -m fast

# Standard daily scan
./nullsec.sh -d example.com

# Full deep scan with template update and rate limiting
./nullsec.sh -d example.com -m deep -u -r

# Resume an interrupted scan
./nullsec.sh -d example.com -c ./recon-example.com-20250520-143022

# Custom output directory
./nullsec.sh -d example.com -m normal -o /opt/recon/example
```

---

## Output Structure

```
recon-example.com-<timestamp>/
├── phase1-subdomains/
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── assetfinder.txt
│   ├── crtsh.txt
│   ├── puredns.txt
│   ├── hakrawler.txt
│   ├── permutations-resolved.txt
│   └── all-subdomains.txt
├── phase2-validation/
│   ├── resolved.txt
│   ├── valid-subdomains.txt
│   ├── wildcards.txt
│   └── takeover-findings.txt
├── phase2.5-cloud/
│   ├── s3/          (exists, readable, writable)
│   ├── gcs/         (exists, readable, writable)
│   ├── azure/       (exists, readable)
│   └── exposed/     (all-exposed-buckets, critical-writable)
├── phase3-probing/
│   ├── live-hosts.txt
│   ├── live-hosts-detailed.txt
│   ├── status-200/403/401/500.txt
│   └── status-redirects.txt
├── phase4-portscan/
│   ├── open-ports.txt
│   └── services-on-ports.txt
├── phase5-urls/
│   ├── all-urls.txt
│   ├── api-endpoints.txt
│   ├── sensitive-endpoints.txt
│   ├── live-js-files.txt
│   └── gf-{xss,sqli,ssrf,redirect,lfi,idor}.txt
├── phase6-parameters/
│   ├── parameters.txt
│   └── arjun-all-params.txt
├── asset-scoring/
│   ├── scored-targets.txt
│   ├── top-targets.txt
│   └── scoring-summary.txt
├── phase7-vulns/
│   ├── all-findings.json
│   ├── critical-findings.txt
│   ├── high-medium-findings.txt
│   ├── cve-findings.txt
│   └── exposure-findings.txt
├── phase8-javascript/
│   ├── trufflehog-secrets.json
│   ├── trufflehog-summary.txt
│   ├── aws-access-keys.txt
│   ├── github-tokens.txt
│   ├── google-api-keys.txt
│   ├── slack-tokens.txt
│   ├── stripe-keys.txt
│   └── private-keys.txt
├── phase9-patterns/
│   ├── ssrf-candidates.txt
│   ├── xss-candidates.txt
│   ├── sqli-candidates.txt
│   ├── lfi-candidates.txt
│   ├── idor-candidates.txt
│   ├── redirect-candidates.txt
│   ├── cors-findings.txt
│   ├── host-injection-findings.txt
│   └── dalfox-xss-confirmed.txt
├── phase10-screenshots/
│   ├── 403/
│   ├── admin/
│   ├── interesting/
│   └── all/
├── phase11-fuzzing/
│   ├── dirs/
│   └── vhosts/
├── phase12-active-vulns/
│   ├── ssrf-confirmed.txt
│   ├── redirect-confirmed.txt
│   ├── lfi-confirmed.txt
│   ├── 403-bypass-confirmed.txt
│   └── graphql-findings.txt
└── reports/
    └── recon-report.txt
```

---

## Configuration

All settings are at the top of `nullsec.sh`. Key variables to review before first run:

```bash
# Wordlist paths — update if your SecLists is in a different location
WORDLIST_DIR="/usr/share/wordlists"
RESOLVERS="$WORDLIST_DIR/resolvers.txt"

# Nuclei templates — update if installed elsewhere
NUCLEI_TEMPLATES="$HOME/nuclei-templates"

# Telegram alerts — fill in for real-time notifications
TELEGRAM_TOKEN=""
TELEGRAM_CHAT_ID=""

# Concurrency — lower these on resource-constrained machines
HTTPX_THREADS=30
NUCLEI_RATE_LIMIT=50    # req/s — lower for sensitive targets
CLOUD_ENUM_THREADS=20
```

### Telegram Setup

To receive real-time alerts on findings and scan completion:

1. Message [@BotFather](https://t.me/BotFather) → `/newbot` → copy the token into `TELEGRAM_TOKEN`
2. Send any message to your bot, then run:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | jq '.result[0].message.chat.id'
   ```
3. Copy the chat ID into `TELEGRAM_CHAT_ID`

Leave both empty to run silently (default).

---

## Asset Scoring

Phase 6b scores every live host by attack potential using signals from Phases 1–6. This lets you focus expensive downstream phases (Nuclei, JS analysis, fuzzing) on the most valuable targets.

| Signal | Points |
|--------|--------|
| Status 200 (reachable) | +5 |
| Status 401 (auth required) | +15 |
| Status 403 (forbidden) | +15 |
| Status 500 (server error) | +20 |
| Non-standard port web service | +10 per port |
| API endpoint on this host | +3 per path |
| Sensitive endpoint (admin/debug) | +5 per path |
| Interesting file (config/bak/env) | +4 per file |
| GF pattern match URL | +2 per match |
| Live JS file | +2 per file |
| Discovered parameter | +1 per param |
| Interesting tech stack keyword | +10 per tech (cap 3) |

Output: `asset-scoring/top-targets.txt` — the top 25% of hosts ranked by score.

---

## Cloud Storage Enumeration

Phase 2.5 generates bucket name candidates from the target domain and discovered subdomains, then tests each against AWS S3, Google Cloud Storage, and Azure Blob Storage in parallel.

**Findings classification:**

- **Readable** — publicly accessible bucket (information disclosure)
- **Writable (CRITICAL)** — allUsers has write-granting IAM role; arbitrary file upload

The write check uses a read-only IAM probe (no objects are created on the target).

**Adjustable limits in config:**

```bash
MAX_BUCKET_MUTATIONS=200    # deep mode raises this to 500
CLOUD_ENUM_THREADS=20
AWS_REGIONS=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")
```

---

## Checkpoint & Resume

For long deep scans, NullSec writes a checkpoint file after each phase. If the scan is interrupted (Ctrl+C, system sleep, timeout), resume with:

```bash
./nullsec.sh -d example.com -c ./recon-example.com-20250520-143022
```

The scan will skip all completed phases and continue from where it left off. On resume, any phase that produced output has its results backed up and merged with the new run (deduplicated).

---

## Legal Notice

This tool is intended for authorized security testing only. Only run NullSec against targets you have explicit written permission to test, including bug bounty programs within their defined scope.

Unauthorized use against systems you do not own or have permission to test is illegal and unethical. The author assumes no liability for misuse.

---

## Author

**NullSec** — Bug Bounty Researcher & Security Practitioner

- GitHub: [@NullSecHQ](https://github.com/NullSecHQ)
- YouTube: [@NullSecHQ](https://youtube.com/@NullSecHQ)
- X / Twitter: [@NullSecHQ](https://x.com/NullSecHQ)

---

## License

This project is licensed under the [MIT License](LICENSE).

---

*Happy Hunting 🐛*
