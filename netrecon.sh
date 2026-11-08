#!/usr/bin/env bash
#
# NetRecon - authorized network penetration-testing reconnaissance
# Bash orchestrator using Nmap, dig, and optional Nuclei.
#
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION="1.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_FILE="${SCOPE_FILE:-$SCRIPT_DIR/scope.txt}"
OUT_BASE="${OUT_BASE:-$SCRIPT_DIR/reports}"
TARGET=""
RUN_UDP=0
RUN_VULN=0
RUN_NUCLEI=0
TIMING="${TIMING:-3}"
PORTS="${PORTS:-}"
UDP_PORTS="${UDP_PORTS:-}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-medium,high,critical}"

usage() {
  cat <<'EOF'
NetRecon - authorized network reconnaissance and reporting

Usage:
  ./netrecon.sh -t <IP|CIDR|domain> [options]

Required:
  -t, --target TARGET       Target must be covered by scope.txt

Options:
  -s, --scope FILE          Scope allowlist file (default: ./scope.txt)
  -o, --output DIR          Report root (default: ./reports)
      --udp                 Run UDP scan (top 100 ports unless UDP_PORTS set)
      --vuln                Run Nmap NSE vulnerability checks
      --nuclei              Run Nuclei against discovered HTTP(S) services
  -p, --ports PORTS         TCP ports, e.g. 22,80,443 or 1-1000
      --udp-ports PORTS     UDP ports, e.g. 53,123,161
  -T, --timing 0..5          Nmap timing template (default: 3)
  -h, --help                Show help

Scope file format (one entry per line; # comments allowed):
  192.0.2.10
  192.0.2.0/24
  example.org
  *.lab.example.org

Examples:
  ./netrecon.sh -t 192.0.2.10
  ./netrecon.sh -t lab.example.org --udp --vuln --nuclei

Safety:
  Only scan systems you own or are explicitly authorized to assess.
  The target must match an entry in scope.txt. DNS names are checked against
  exact names or *.domain entries; IPs/CIDRs are checked against IP/CIDR entries.
EOF
}

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die()  { printf '[!] %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while (($#)); do
  case "$1" in
    -t|--target) [[ $# -ge 2 ]] || die "Missing target"; TARGET="$2"; shift 2 ;;
    -s|--scope) [[ $# -ge 2 ]] || die "Missing scope file"; SCOPE_FILE="$2"; shift 2 ;;
    -o|--output) [[ $# -ge 2 ]] || die "Missing output directory"; OUT_BASE="$2"; shift 2 ;;
    --udp) RUN_UDP=1; shift ;;
    --vuln) RUN_VULN=1; shift ;;
    --nuclei) RUN_NUCLEI=1; shift ;;
    -p|--ports) [[ $# -ge 2 ]] || die "Missing TCP ports"; PORTS="$2"; shift 2 ;;
    --udp-ports) [[ $# -ge 2 ]] || die "Missing UDP ports"; UDP_PORTS="$2"; shift 2 ;;
    -T|--timing) [[ $# -ge 2 ]] || die "Missing timing value"; TIMING="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
done

[[ -n "$TARGET" ]] || { usage; die "Target is required"; }
[[ -f "$SCOPE_FILE" ]] || die "Scope file not found: $SCOPE_FILE"
[[ "$TIMING" =~ ^[0-5]$ ]] || die "Timing must be 0..5"
have nmap || die "nmap is required. Install it first."
have python3 || die "python3 is required."
have timeout || die "timeout is required."

# Validate syntax and enforce allowlist before invoking any scanner.
# Python's ipaddress module provides reliable IPv4/IPv6/CIDR parsing.
python3 - "$TARGET" "$SCOPE_FILE" <<'PY'
import ipaddress, re, sys
target, scope_path = sys.argv[1:3]
try:
    entries = []
    with open(scope_path, encoding="utf-8") as f:
        for raw in f:
            s = raw.split("#", 1)[0].strip().lower()
            if not s:
                continue
            if s.startswith("*."):
                suffix = s[2:].rstrip(".")
                if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", suffix):
                    raise ValueError(f"Invalid wildcard domain in scope: {s}")
                entries.append(("wildcard", suffix))
                continue
            try:
                entries.append(("net", ipaddress.ip_network(s, strict=False)))
                continue
            except ValueError:
                pass
            d = s.rstrip(".")
            if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", d):
                raise ValueError(f"Invalid scope entry: {s}")
            entries.append(("domain", d))

    try:
        requested_net = ipaddress.ip_network(target, strict=False)
        is_network = "/" in target
        if is_network:
            allowed = any(k == "net" and requested_net.subnet_of(v) for k, v in entries)
        else:
            ip = ipaddress.ip_address(target)
            allowed = any(k == "net" and ip in v for k, v in entries)
    except ValueError:
        domain = target.rstrip(".").lower()
        if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", domain):
            raise SystemExit("Target is not a valid IP, CIDR, or DNS name.")
        allowed = any((k == "domain" and domain == v) or
                      (k == "wildcard" and domain.endswith("." + v))
                      for k, v in entries)
    if not allowed:
        raise SystemExit("SCOPE DENIED: target is not covered by the allowlist.")
except (OSError, ValueError) as e:
    raise SystemExit(f"Scope validation failed: {e}")
PY

STAMP="$(date '+%Y%m%d_%H%M%S')"
SAFE_TARGET="$(printf '%s' "$TARGET" | tr '/:' '__' | tr -cd '[:alnum:]_.-')"
RUN_DIR="$OUT_BASE/${STAMP}_${SAFE_TARGET}"
RAW="$RUN_DIR/raw"
mkdir -p "$RAW"
REPORT_MD="$RUN_DIR/report.md"
REPORT_HTML="$RUN_DIR/report.html"
START_EPOCH="$(date +%s)"
START_HUMAN="$(date '+%F %T %Z')"

# Record tool versions and exact scope/arguments for reproducibility.
{
  printf 'NetRecon %s\nTarget: %s\nScope file: %s\nStarted: %s\n' "$VERSION" "$TARGET" "$SCOPE_FILE" "$START_HUMAN"
  printf 'Options: UDP=%s NSE=%s Nuclei=%s TCP_PORTS=%s UDP_PORTS=%s Timing=%s\n' \
    "$RUN_UDP" "$RUN_VULN" "$RUN_NUCLEI" "${PORTS:-nmap-default}" "${UDP_PORTS:-top-100}" "$TIMING"
  nmap --version | head -n 2
  if have nuclei; then nuclei -version 2>&1 | head -n 1 || true; fi
} > "$RAW/run_metadata.txt"

log "Target passed scope validation."
log "Evidence directory: $RUN_DIR"

# DNS reconnaissance: only meaningful for a DNS name.
if ! python3 - "$TARGET" <<'PY'
import ipaddress,sys
try: ipaddress.ip_address(sys.argv[1]); sys.exit(0)
except ValueError: 
    try: ipaddress.ip_network(sys.argv[1], strict=False); sys.exit(0)
    except ValueError: sys.exit(1)
PY
then
  if have dig; then
    log "Collecting DNS records..."
    for type in A AAAA MX NS TXT CNAME SOA; do
      {
        echo "### $type"
        dig +time=3 +tries=1 "$TARGET" "$type" +noall +answer
        echo
      } >> "$RAW/dns_records.txt" 2>&1 || true
    done
  else
    log "dig not found; skipping DNS record collection."
  fi
fi

# Host discovery. -sn avoids port scanning during this phase.
log "Host discovery..."
nmap -sn -n -T"$TIMING" --reason -oA "$RAW/host_discovery" "$TARGET" \
  > "$RAW/host_discovery_console.txt" 2>&1 || log "Host discovery returned a non-zero status; inspect raw output."

# TCP scan. For a CIDR this scans the specified network; for a domain/IP it scans that host.
TCP_ARGS=(-sS -n -T"$TIMING" --reason -sV)
[[ -n "$PORTS" ]] && TCP_ARGS+=(-p "$PORTS") || TCP_ARGS+=(-p-)
log "TCP port scan and service enumeration..."
nmap "${TCP_ARGS[@]}" -oA "$RAW/tcp_scan" "$TARGET" \
  > "$RAW/tcp_scan_console.txt" 2>&1 || log "TCP scan returned a non-zero status; inspect raw output."

if (( RUN_UDP )); then
  UDP_ARGS=(-sU -n -T"$TIMING" --reason)
  [[ -n "$UDP_PORTS" ]] && UDP_ARGS+=(-p "$UDP_PORTS") || UDP_ARGS+=(--top-ports 100)
  log "UDP scan..."
  nmap "${UDP_ARGS[@]}" -sV -oA "$RAW/udp_scan" "$TARGET" \
    > "$RAW/udp_scan_console.txt" 2>&1 || log "UDP scan returned a non-zero status; inspect raw output."
fi

if (( RUN_VULN )); then
  log "Running Nmap NSE vulnerability-category checks..."
  # This is an active check. Run only with explicit authorization.
  nmap -sV -n -T"$TIMING" --script vuln -oA "$RAW/nse_vuln" "$TARGET" \
    > "$RAW/nse_vuln_console.txt" 2>&1 || log "NSE checks returned a non-zero status; inspect raw output."
fi

if (( RUN_NUCLEI )); then
  have nuclei || die "--nuclei was requested, but nuclei is not installed."
  # Nuclei is limited to web services identified by Nmap's XML output.
  python3 - "$RAW/tcp_scan.xml" "$RAW/http_targets.txt" <<'PY'
import sys, xml.etree.ElementTree as ET
src, dst = sys.argv[1:3]
urls = set()
try:
    root = ET.parse(src).getroot()
    for host in root.findall("host"):
        addrs = [a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4","ipv6")]
        for port in host.findall(".//port"):
            state = port.find("state")
            svc = port.find("service")
            if state is None or state.get("state") != "open" or svc is None:
                continue
            name = (svc.get("name") or "").lower()
            tunnel = (svc.get("tunnel") or "").lower()
            p = port.get("portid")
            if name in ("http","https","http-proxy") or tunnel == "ssl":
                scheme = "https" if p == "443" or tunnel == "ssl" else "http"
                for addr in addrs:
                    host = f"[{addr}]" if ":" in addr else addr
                    urls.add(f"{scheme}://{host}:{p}")
except Exception as e:
    print(f"Could not parse Nmap XML: {e}", file=sys.stderr)
with open(dst, "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(urls)) + ("\n" if urls else ""))
PY
  if [[ -s "$RAW/http_targets.txt" ]]; then
    log "Running Nuclei against discovered HTTP(S) endpoints..."
    nuclei -l "$RAW/http_targets.txt" -severity "$NUCLEI_SEVERITY" \
      -rate-limit 5 -retries 1 -timeout 8 -no-color \
      -jsonl -o "$RAW/nuclei.jsonl" \
      > "$RAW/nuclei_console.txt" 2>&1 || log "Nuclei returned a non-zero status; inspect raw output."
  else
    log "No HTTP(S) endpoints found; skipping Nuclei."
  fi
fi

END_EPOCH="$(date +%s)"
END_HUMAN="$(date '+%F %T %Z')"
DURATION=$((END_EPOCH - START_EPOCH))

# Build a readable Markdown report from Nmap XML and evidence files.
python3 - "$TARGET" "$START_HUMAN" "$END_HUMAN" "$DURATION" "$RAW" "$REPORT_MD" "$REPORT_HTML" <<'PY'
import html, os, sys, xml.etree.ElementTree as ET
target, started, ended, duration, raw, md_path, html_path = sys.argv[1:]
def read(name):
    p = os.path.join(raw, name)
    try:
        with open(p, encoding="utf-8", errors="replace") as f: return f.read().strip()
    except OSError: return ""
def parse_nmap(name):
    p = os.path.join(raw, name + ".xml")
    hosts = []
    if not os.path.exists(p): return hosts
    try:
        root = ET.parse(p).getroot()
        for h in root.findall("host"):
            addrs = [a.get("addr","") for a in h.findall("address")]
            names = [n.get("name","") for n in h.findall(".//hostname")]
            status = h.find("status")
            ports = []
            for port in h.findall(".//port"):
                state = port.find("state")
                svc = port.find("service")
                ports.append((port.get("protocol",""), port.get("portid",""),
                              state.get("state","") if state is not None else "",
                              svc.get("name","") if svc is not None else "",
                              svc.get("version","") if svc is not None else ""))
            hosts.append({"addr":", ".join(addrs), "names":", ".join(names),
                          "status":status.get("state","unknown") if status is not None else "unknown",
                          "ports":ports})
    except ET.ParseError:
        pass
    return hosts

tcp = parse_nmap("tcp_scan")
udp = parse_nmap("udp_scan")
alive = parse_nmap("host_discovery")
lines = [
    "# NetRecon Network Assessment Report", "",
    f"- **Target:** `{target}`",
    f"- **Started:** {started}",
    f"- **Finished:** {ended}",
    f"- **Duration:** {duration} seconds",
    "- **Authorization:** Target was required to match the local scope allowlist before scanning.",
    "", "## Executive summary", "",
    f"- Hosts reported by discovery: **{len(alive)}**",
    f"- Hosts represented in TCP scan: **{len(tcp)}**",
    f"- Hosts represented in UDP scan: **{len(udp)}**",
    "- This is an automated preliminary assessment; validate findings manually.",
    "", "## Host discovery", ""
]
for h in alive:
    lines.append(f"- `{h['addr']}` — {h['status']} {('('+h['names']+')') if h['names'] else ''}")
if not alive: lines.append("No host records were parsed. Review `raw/host_discovery.*`.")
def add_scan(title, hosts):
    lines.extend(["", f"## {title}", ""])
    if not hosts:
        lines.append("No parsed results. Review the raw Nmap XML and console output.")
        return
    for h in hosts:
        lines.append(f"### {h['addr']} {('('+h['names']+')') if h['names'] else ''}")
        found = [p for p in h["ports"] if p[2] == "open"]
        if not found:
            lines.append("- No open ports reported.")
        else:
            lines.append("| Port | State | Service | Version |")
            lines.append("|---|---|---|---|")
            for proto, port, state, service, version in found:
                lines.append(f"| {port}/{proto} | {state} | {service or 'unknown'} | {version or 'not identified'} |")
add_scan("TCP ports and services", tcp)
if os.path.exists(os.path.join(raw, "udp_scan.xml")): add_scan("UDP ports and services", udp)
dns = read("dns_records.txt")
if dns: lines.extend(["", "## DNS reconnaissance", "", "```text", dns, "```"])
nse = read("nse_vuln.nmap")
if nse: lines.extend(["", "## Nmap NSE vulnerability checks", "", "```text", nse[:20000], "```"])
nuclei = read("nuclei.jsonl")
if nuclei: lines.extend(["", "## Nuclei findings (JSONL)", "", "```json", nuclei[:20000], "```"])
lines.extend([
    "", "## Evidence index", "",
    "- `raw/run_metadata.txt` — tool versions and run configuration",
    "- `raw/host_discovery.*` — host discovery output (Nmap normal/XML/grepable)",
    "- `raw/tcp_scan.*` — TCP scan and service enumeration",
    "- `raw/udp_scan.*` — UDP scan, if enabled",
    "- `raw/nse_vuln.*` — NSE results, if enabled",
    "- `raw/nuclei.jsonl` — Nuclei results, if enabled",
    "- `raw/dns_records.txt` — DNS answers, if applicable",
    "", "## Limitations and next steps", "",
    "1. Confirm that every discovered asset is in the approved engagement scope.",
    "2. Manually validate service versions and potential vulnerabilities.",
    "3. Correlate results with asset ownership, business impact, and patch status.",
    "4. Do not treat absence of a scanner finding as proof that a system is secure.",
    "", "## Disclaimer", "",
    "This report contains automated scan output. It is not a substitute for manual testing,",
    "and must only be used for systems for which written authorization exists.", ""
])
md = "\n".join(lines)
with open(md_path, "w", encoding="utf-8") as f: f.write(md)
# Lightweight standalone HTML report; Markdown is escaped and kept readable.
page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetRecon Report</title><style>
body{font:15px/1.6 system-ui,sans-serif;max-width:1050px;margin:40px auto;padding:0 20px;color:#20242a}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:18px;border-radius:8px}
h1,h2{line-height:1.25}code{background:#f1f3f5;padding:2px 4px;border-radius:4px}
</style></head><body><pre>""" + html.escape(md) + """</pre></body></html>"""
with open(html_path, "w", encoding="utf-8") as f: f.write(page)
PY

log "Assessment complete."
log "Markdown report: $REPORT_MD"
log "HTML report:     $REPORT_HTML"
log "Raw evidence:    $RAW"
