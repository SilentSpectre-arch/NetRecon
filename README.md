# NetRecon — Bash Network Reconnaissance Automation

A Bash-first project for authorized network penetration-testing reconnaissance:
scope validation → host discovery → TCP/UDP scanning → service enumeration →
DNS checks → optional Nmap NSE/Nuclei checks → Markdown/HTML report + raw evidence.

## Requirements

- Kali Linux / Debian-based Linux
- Bash 4+
- `nmap`
- `python3`
- `timeout` (usually supplied by coreutils)
- Optional: `dnsutils` (`dig`), `nuclei`

Install on Kali:

```bash
sudo apt update
sudo apt install -y nmap dnsutils python3
```

Nuclei is optional. Install it from its official project distribution and verify
`nuclei -version` before using `--nuclei`.

## Configure scope first

Edit `scope.txt`. Remove the examples and add only explicitly authorized targets.
Supported entries:

```text
192.0.2.10
192.0.2.0/24
host.example.org
*.lab.example.org
```

- IP addresses must be inside an allowlisted IP/CIDR.
- CIDR targets must be fully contained by an allowlisted CIDR.
- Domains must match an exact domain entry or a `*.domain` entry.
- A wildcard matches subdomains, not the bare parent domain.

The scope check is a local guardrail, not a substitute for written authorization.

## Run

```bash
chmod +x netrecon.sh
./netrecon.sh --help
./netrecon.sh -t 192.0.2.10
./netrecon.sh -t 192.0.2.10 -p 22,80,443
./netrecon.sh -t 192.0.2.10 --udp --udp-ports 53,123,161
./netrecon.sh -t 192.0.2.10 --vuln
./netrecon.sh -t lab.example.org --nuclei
```

For a full internal lab subnet, add that exact subnet to `scope.txt` first, then:

```bash
./netrecon.sh -t 192.0.2.0/24 --udp
```

NSE `vuln` and Nuclei perform active checks. Use them only when explicitly
authorized and when the engagement rules permit that activity.

## Output structure

Every run creates a timestamped directory:

```text
reports/
└── 20261107_235000_192.0.2.10/
    ├── report.md
    ├── report.html
    └── raw/
        ├── run_metadata.txt
        ├── host_discovery.nmap
        ├── host_discovery.xml
        ├── tcp_scan.nmap
        ├── tcp_scan.xml
        ├── dns_records.txt
        └── ...
```

Nmap `-oA` preserves normal, XML, and grepable output. The report parser uses
XML, while the raw files remain available for verification and future parsing.

## Design notes / known limitations

- TCP uses a SYN scan (`-sS`), so run with sufficient privileges; otherwise
  Nmap may fall back or report a permission error. Use `sudo` if your lab setup
  requires it.
- UDP defaults to the top 100 ports because full UDP scans can be slow.
- The Nuclei stage derives HTTP(S) endpoints from Nmap XML. It does not crawl
  every virtual host or discover every web application path.
- Network mapping in this first release is represented through discovered
  hosts, addresses, ports, and service relationships in the evidence/report.
  It does not attempt intrusive traceroute or topology inference.
- The report is a preliminary technical summary, not a final professional
  penetration-test deliverable. Add manual validation, risk ratings, impact,
  remediation, and client-approved evidence before issuing a client report.

## Suggested GitHub improvements

1. Add unit tests for scope matching (IPv4, IPv6, CIDR, wildcard domains).
2. Add JSON report output and CVSS mapping after manual validation.
3. Add asset inventory import (CSV) and exclusions.
4. Add a separate `--safe-only` profile and engagement rate limits.
5. Add screenshots and sanitized sample reports from a legal lab (never publish
   client data or secrets).
