#!/usr/bin/env python3
"""
Vulnerability Scanner CVE Edition
=================================
 
An educational cybersecurity project in Python.
 
NEW IN THIS VERSION:
  * LIVE CVE LOOKUP: pulls real bug data from the NVD
    (US National Vulnerability Database) over the internet.
  * PLAIN-LANGUAGE HTML REPORT: simple words, clear actions.
 
WHAT IT DOES:
  1. Scans ports fast with threads (or quick "top ports" mode).
  2. Reads each service banner and detects software + version.
  3. Matches a built-in CVE list, AND (with --online) the live NVD.
  4. Checks SSL/TLS certificates and HTTP security headers.
  5. Scores findings LOW / MEDIUM / HIGH and grades the host A-F.
  6. Writes JSON, text, and an easy-to-read HTML report.
 
WHAT IT DOES NOT DO:
  It only FINDS weak spots. It never attacks or exploits them.
  It never guesses passwords. That keeps it legal and safe.
 
ETHICS:
  Only scan a host you OWN or have written PERMISSION to scan.
  Safe practice target: 127.0.0.1 (your own computer).
 
HOW TO RUN:
  python3 vuln_scanner_cve.py 127.0.0.1 --top
  python3 vuln_scanner_cve.py example.com --web --online
  python3 vuln_scanner_cve.py example.com --online --api-key YOUR_NVD_KEY
 
A free NVD API key (optional, but faster) is available here:
  https://nvd.nist.gov/developers/request-an-api-key
 
Uses only the Python standard library. No extra installs needed.
"""
 
import time
import socket
import ssl
import json
import html
import argparse
import http.client
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
 
 
# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------
 
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}
 
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
             1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
 
RISKY_PORTS = {
    21: ("MEDIUM", "FTP often sends passwords in clear text. Use SFTP instead."),
    23: ("HIGH", "Telnet has no encryption. Anyone watching can read it. Use SSH."),
    445: ("HIGH", "SMB is a common malware target. Limit who can reach it."),
    3389: ("HIGH", "Remote Desktop is heavily attacked. Put it behind a VPN."),
    6379: ("HIGH", "Redis often has no password. Add a password and a firewall."),
    9200: ("HIGH", "Elasticsearch is often left open. Restrict access to it."),
    27017: ("HIGH", "MongoDB is often open with no login. Lock it down."),
}
 
SERVICE_PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    25: b"EHLO scanner.local\r\n",
    110: b"", 143: b"", 21: b"", 22: b"",
}
 
# Built-in CVE list (used always; live NVD adds more with --online).
CVE_DATABASE = {
    "OpenSSH": [
        ("7.7", "CVE-2018-15473", "MEDIUM", "Lets attackers guess valid usernames."),
        ("8.4", "CVE-2020-15778", "MEDIUM", "Command injection through scp."),
    ],
    "Apache": [
        ("2.4.49", "CVE-2021-41773", "HIGH", "Attacker can read files and run code."),
        ("2.4.50", "CVE-2021-42013", "HIGH", "Attacker can read files and run code."),
    ],
    "nginx": [
        ("1.20.0", "CVE-2021-23017", "HIGH", "Memory bug that can crash or be abused."),
    ],
    "vsftpd": [
        ("2.3.4", "CVE-2011-2523", "HIGH", "This version shipped with a hidden backdoor."),
    ],
    "ProFTPD": [
        ("1.3.5", "CVE-2015-3306", "HIGH", "Attacker can copy files and run code."),
    ],
    "Exim": [
        ("4.91", "CVE-2019-10149", "HIGH", "Attacker can run commands on the server."),
    ],
}
 
# Map our internal software names to NVD keyword search terms.
NVD_KEYWORDS = {
    "OpenSSH": "openssh", "Apache": "apache http server",
    "nginx": "nginx", "vsftpd": "vsftpd", "ProFTPD": "proftpd",
    "Exim": "exim", "MySQL": "mysql",
}
 
 
# ---------------------------------------------------------------------------
# Banner parsing
# ---------------------------------------------------------------------------
 
def _clean_version(token):
    cleaned = token.strip("vV")
    if cleaned and cleaned[0].isdigit() and "." in cleaned:
        cleaned = "".join(c for c in cleaned if c.isdigit() or c == ".")
        return cleaned.strip(".") or None
    return None
 
 
def parse_service_version(banner):
    """Get a software name and version from a banner. Reads the version
    that sits next to the name, not the first number in the line."""
    if not banner:
        return None, None
 
    known = ["OpenSSH", "Apache", "nginx", "vsftpd", "ProFTPD",
             "Postfix", "Exim", "MySQL"]
 
    banner_norm = banner
    for ch in "/_-()[]":
        banner_norm = banner_norm.replace(ch, " ")
    pieces = banner_norm.split()
 
    name = None
    name_index = None
    for i, p in enumerate(pieces):
        for k in known:
            if p.lower().startswith(k.lower()):
                name, name_index = k, i
                break
        if name:
            break
 
    version = None
    if name is not None:
        for p in pieces[name_index:name_index + 3]:
            v = _clean_version(p)
            if v:
                version = v
                break
 
    return name, version
 
 
def version_is_le(found, bad):
    def parts(v):
        out = []
        for piece in v.split("."):
            num = "".join(ch for ch in piece if ch.isdigit())
            out.append(int(num) if num else 0)
        return out
    fa, ba = parts(found), parts(bad)
    n = max(len(fa), len(ba))
    fa += [0] * (n - len(fa))
    ba += [0] * (n - len(ba))
    return fa <= ba
 
 
# ---------------------------------------------------------------------------
# Live CVE lookup (NVD API 2.0)
# ---------------------------------------------------------------------------
 
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cve_cache = {}
 
 
def _cvss_to_severity(cve):
    """Read the CVSS score from an NVD record and bucket it."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            entry = arr[0]
            data = entry.get("cvssData", {})
            base = data.get("baseSeverity") or entry.get("baseSeverity")
            score = data.get("baseScore")
            if base:
                base = base.upper()
                if base in ("CRITICAL", "HIGH"):
                    return "HIGH"
                if base == "MEDIUM":
                    return "MEDIUM"
                return "LOW"
            if score is not None:
                if score >= 7:
                    return "HIGH"
                if score >= 4:
                    return "MEDIUM"
                return "LOW"
    return "MEDIUM"
 
 
def lookup_cves_online(software, version, api_key=None,
                       max_results=4, timeout=12):
    """Ask the live NVD database for CVEs about this software+version.
 
    Returns a list of issue dicts. Falls back gracefully on any error.
    NOTE: keyword search is broad, so results are a starting point,
    not a precise match. Always verify a CVE before acting on it.
    """
    if not software:
        return []
 
    keyword = NVD_KEYWORDS.get(software, software.lower())
    query = f"{keyword} {version}".strip()
    if query in _cve_cache:
        return _cve_cache[query]
 
    params = {"keywordSearch": query, "resultsPerPage": 20}
    url = NVD_URL + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "EduVulnScanner/1.0 (educational)"}
    if api_key:
        headers["apiKey"] = api_key
 
    findings = []
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
 
        for item in data.get("vulnerabilities", [])[:max_results]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if len(desc) > 160:
                desc = desc[:157] + "..."
            findings.append({
                "severity": _cvss_to_severity(cve),
                "type": cve_id,
                "detail": desc or "See the NVD page for details.",
                "source": "NVD (live)",
            })
 
        # Be polite to the NVD API rate limit.
        time.sleep(0.8 if api_key else 6.5)
 
    except Exception as err:  # network, timeout, parse, etc.
        findings.append({
            "severity": "LOW", "type": "Live CVE lookup failed",
            "detail": f"Could not reach NVD: {err}", "source": "NVD (live)",
        })
 
    _cve_cache[query] = findings
    return findings
 
 
# ---------------------------------------------------------------------------
# Scanning core
# ---------------------------------------------------------------------------
 
def scan_port(host, port, timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) != 0:
            return port, None
        try:
            probe = SERVICE_PROBES.get(port)
            if probe:
                sock.send(probe)
            banner = sock.recv(1024).decode(errors="ignore").strip()
        except socket.error:
            banner = ""
        return port, banner
    except socket.error:
        return port, None
    finally:
        sock.close()
 
 
def analyze_port(port, banner):
    service = COMMON_PORTS.get(port, "Unknown")
    name, version = parse_service_version(banner)
    finding = {
        "port": port, "service": service,
        "banner": (banner or "").splitlines()[0][:90] if banner else "",
        "detected_software": name, "detected_version": version,
        "issues": [],
    }
    if port in RISKY_PORTS:
        sev, note = RISKY_PORTS[port]
        finding["issues"].append(
            {"severity": sev, "type": "Risky service", "detail": note,
             "source": "built-in"}
        )
    if name and version and name in CVE_DATABASE:
        for bad_ver, cve, sev, note in CVE_DATABASE[name]:
            if version_is_le(version, bad_ver):
                finding["issues"].append({
                    "severity": sev, "type": cve,
                    "detail": f"{name} {version}: {note}",
                    "source": "built-in",
                })
    return finding
 
 
def enrich_with_online_cves(finding, api_key):
    """Add live NVD CVEs to a port finding, skipping duplicates."""
    name = finding["detected_software"]
    version = finding["detected_version"]
    if not (name and version):
        return
    have = {i["type"] for i in finding["issues"]}
    for issue in lookup_cves_online(name, version, api_key):
        if issue["type"] not in have:
            finding["issues"].append(issue)
            have.add(issue["type"])
 
 
# ---------------------------------------------------------------------------
# Web checks
# ---------------------------------------------------------------------------
 
def check_ssl(host, port=443, timeout=4.0):
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append({
                "severity": "HIGH", "type": "Old encryption (TLS)",
                "detail": f"The server still allows {proto}, which is unsafe.",
                "source": "built-in"})
        expires = cert.get("notAfter")
        if expires:
            exp = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
            exp = exp.replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append({
                    "severity": "HIGH", "type": "Expired certificate",
                    "detail": f"The HTTPS certificate expired {abs(days)} days ago.",
                    "source": "built-in"})
            elif days < 15:
                findings.append({
                    "severity": "MEDIUM", "type": "Certificate expiring soon",
                    "detail": f"The HTTPS certificate expires in {days} days.",
                    "source": "built-in"})
    except (ssl.SSLError, socket.error, ValueError) as err:
        findings.append({
            "severity": "MEDIUM", "type": "Could not check encryption",
            "detail": str(err), "source": "built-in"})
    return findings
 
 
def check_http_headers(host, port=443, use_https=True, timeout=4.0):
    findings = []
    wanted = {
        "strict-transport-security": "Forces visitors to use safe HTTPS.",
        "content-security-policy": "Blocks many code-injection attacks.",
        "x-frame-options": "Stops the page being hidden inside a fake site.",
        "x-content-type-options": "Stops the browser guessing file types.",
        "referrer-policy": "Limits private link data sent to other sites.",
    }
    try:
        if use_https:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        for header, why in wanted.items():
            if header not in headers:
                findings.append({
                    "severity": "LOW",
                    "type": f"Missing safety header ({header})",
                    "detail": why, "source": "built-in"})
    except (socket.error, http.client.HTTPException) as err:
        findings.append({
            "severity": "LOW", "type": "Could not check headers",
            "detail": str(err), "source": "built-in"})
    return findings
 
 
# ---------------------------------------------------------------------------
# Scoring + recommendations
# ---------------------------------------------------------------------------
 
def count_severities(results):
    high = med = low = 0
    blocks = list(results["open_ports"]) + [{"issues": results["web_findings"]}]
    for block in blocks:
        for issue in block["issues"]:
            sev = issue["severity"]
            high += sev == "HIGH"
            med += sev == "MEDIUM"
            low += sev == "LOW"
    return high, med, low
 
 
def compute_grade(high, med, low):
    score = high * 5 + med * 2 + low * 1
    if high == 0 and med == 0 and low == 0:
        return "A", score
    if score >= 15 or high >= 2:
        return "F", score
    if score >= 8 or high >= 1:
        return "D", score
    if score >= 4:
        return "C", score
    if score >= 1:
        return "B", score
    return "A", score
 
 
def build_recommendations(results):
    rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    recs = {}
    blocks = list(results["open_ports"]) + [{"issues": results["web_findings"]}]
    for block in blocks:
        for issue in block["issues"]:
            recs[issue["detail"]] = issue["severity"]
    ordered = sorted(recs.items(), key=lambda kv: rank[kv[1]], reverse=True)
    return [{"severity": sev, "detail": text} for text, sev in ordered]
 
 
# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
 
def run_scan(host, ports, threads, do_web, online, api_key):
    target_ip = socket.gethostbyname(host)
    results = {
        "target": host, "ip": target_ip,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "open_ports": [], "web_findings": [],
    }
 
    print(f"\nScanning {host} ({target_ip})")
    print(f"Checking {len(ports)} ports with {threads} threads...\n")
 
    done, total = 0, len(ports)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(scan_port, target_ip, p) for p in ports]
        for fut in as_completed(futures):
            done += 1
            if done % 100 == 0 or done == total:
                print(f"  progress: {done}/{total} ports")
            port, banner = fut.result()
            if banner is not None:
                results["open_ports"].append(analyze_port(port, banner))
 
    results["open_ports"].sort(key=lambda f: f["port"])
 
    if online:
        print("\nLooking up live CVEs from NVD (this can be slow)...")
        for finding in results["open_ports"]:
            if finding["detected_software"] and finding["detected_version"]:
                print(f"  querying {finding['detected_software']} "
                      f"{finding['detected_version']}...")
                enrich_with_online_cves(finding, api_key)
 
    if do_web:
        print("\nRunning SSL and HTTP header checks...")
        results["web_findings"].extend(check_ssl(host))
        results["web_findings"].extend(check_http_headers(host))
 
    high, med, low = count_severities(results)
    grade, score = compute_grade(high, med, low)
    results["summary"] = {"high": high, "medium": med, "low": low,
                          "grade": grade, "score": score}
    results["recommendations"] = build_recommendations(results)
    return results
 
 
# ---------------------------------------------------------------------------
# Console + JSON + text reports
# ---------------------------------------------------------------------------
 
def print_report(results):
    s = results["summary"]
    print("\n" + "=" * 60)
    print(f" RESULTS for {results['target']} ({results['ip']})")
    print("=" * 60)
    for f in results["open_ports"]:
        ver = f"  v{f['detected_version']}" if f["detected_version"] else ""
        print(f"\n[PORT {f['port']}] {f['service']}{ver}")
        if f["banner"]:
            print(f"   banner: {f['banner']}")
        for issue in f["issues"]:
            print(f"   [{issue['severity']}] {issue['type']} - {issue['detail']}")
    if results["web_findings"]:
        print("\n[WEB CHECKS]")
        for issue in results["web_findings"]:
            print(f"   [{issue['severity']}] {issue['type']} - {issue['detail']}")
    print("\n" + "-" * 60)
    print(f" Open ports: {len(results['open_ports'])}")
    print(f" Findings -> HIGH: {s['high']}  MEDIUM: {s['medium']}  LOW: {s['low']}")
    print(f" RISK GRADE: {s['grade']}  (score {s['score']})")
    print("-" * 60)
 
 
def save_json_text(results, base):
    with open(f"{base}.json", "w") as jf:
        json.dump(results, jf, indent=2)
    with open(f"{base}.txt", "w") as tf:
        s = results["summary"]
        tf.write(f"Scan report for {results['target']} ({results['ip']})\n")
        tf.write(f"Time: {results['scanned_at']}\n")
        tf.write(f"Grade: {s['grade']}  HIGH {s['high']} MED {s['medium']} "
                 f"LOW {s['low']}\n\n")
        for f in results["open_ports"]:
            tf.write(f"Port {f['port']} ({f['service']})\n")
            for issue in f["issues"]:
                tf.write(f"  [{issue['severity']}] {issue['type']}: "
                         f"{issue['detail']}\n")
            tf.write("\n")
        for issue in results["web_findings"]:
            tf.write(f"[WEB][{issue['severity']}] {issue['type']}: "
                     f"{issue['detail']}\n")
 
 
# ---------------------------------------------------------------------------
# Plain-language HTML report
# ---------------------------------------------------------------------------
 
# Turn tech severity into plain words.
PLAIN_SEVERITY = {"HIGH": "Fix now", "MEDIUM": "Fix soon", "LOW": "Minor"}
SEV_COLOR = {"HIGH": "#ff5c5c", "MEDIUM": "#f5c518", "LOW": "#5ab0ff"}
GRADE_COLOR = {"A": "#3ddc84", "B": "#9ad84f", "C": "#f5c518",
               "D": "#ff8c42", "F": "#ff5c5c"}
GRADE_PLAIN = {
    "A": "Looks safe. No problems found.",
    "B": "Almost clean. Just small things to check.",
    "C": "Some problems. Worth fixing.",
    "D": "Several problems. Fix them soon.",
    "F": "Serious problems. Fix them now.",
}
 
 
def _sev_tag(sev):
    color = SEV_COLOR.get(sev, "#8a8f98")
    label = PLAIN_SEVERITY.get(sev, sev)
    return (f'<span class="tag" style="background:{color}1a;color:{color};'
            f'border:1px solid {color}66">{label}</span>')
 
 
def _plain_title(issue):
    t = issue["type"]
    if t.startswith("CVE-"):
        return f"Known security bug ({t})"
    return t
 
 
def _all_issues_with_context(results):
    """Flatten every issue with its location, worst first."""
    rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    rows = []
    for f in results["open_ports"]:
        for issue in f["issues"]:
            rows.append((issue, f"Port {f['port']} ({f['service']})"))
    for issue in results["web_findings"]:
        rows.append((issue, "Website (HTTPS)"))
    rows.sort(key=lambda r: rank[r[0]["severity"]], reverse=True)
    return rows
 
 
def save_html(results, base):
    s = results["summary"]
    grade = s["grade"]
    gcolor = GRADE_COLOR.get(grade, "#8a8f98")
    esc = html.escape
 
    # Plain one-line summary.
    summary_line = (
        f"We checked <b>{esc(results['target'])}</b>. "
        f"We found <b style='color:{SEV_COLOR['HIGH']}'>{s['high']}</b> "
        f"serious problems, "
        f"<b style='color:{SEV_COLOR['MEDIUM']}'>{s['medium']}</b> to fix soon, "
        f"and <b style='color:{SEV_COLOR['LOW']}'>{s['low']}</b> minor ones."
    )
 
    # Problem cards.
    cards = []
    for issue, where in _all_issues_with_context(results):
        src = issue.get("source", "")
        src_note = (f'<span class="src">{esc(src)}</span>' if src else "")
        cards.append(f"""
      <div class="card">
        <div class="card-top">{_sev_tag(issue['severity'])}
          <span class="where">{esc(where)}</span>{src_note}</div>
        <div class="prob">{esc(_plain_title(issue))}</div>
        <div class="means"><span class="lbl">What it means:</span>
          {esc(issue['detail'])}</div>
      </div>""")
    if not cards:
        cards.append('<div class="card"><div class="prob">'
                     'No problems found. </div></div>')
 
    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Report &mdash; {esc(results['target'])}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<style>
:root {{ --bg:#0d1117; --panel:#161b22; --line:#26303b;
  --text:#e9eef4; --muted:#9aa3ad; --accent:#58e1c0; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font-family:"IBM Plex Sans","Segoe UI",sans-serif; font-size:17px;
  line-height:1.6; }}
.wrap {{ max-width:820px; margin:0 auto; padding:46px 22px 80px; }}
.kicker {{ color:var(--accent); letter-spacing:.26em; font-size:12px;
  text-transform:uppercase; }}
h1 {{ font-size:30px; margin:8px 0 6px;
  font-family:"IBM Plex Mono",monospace; word-break:break-all; }}
.sub {{ color:var(--muted); font-size:14px;
  font-family:"IBM Plex Mono",monospace; }}
.summary {{ font-size:20px; margin:26px 0 8px; }}
.grade {{ display:flex; align-items:center; gap:20px; background:var(--panel);
  border:1px solid var(--line); border-radius:16px; padding:20px 24px;
  margin:24px 0 14px; }}
.grade .big {{ font-size:58px; font-weight:800; line-height:1;
  font-family:"IBM Plex Mono",monospace; color:{gcolor};
  text-shadow:0 0 28px {gcolor}55; }}
.grade .txt b {{ font-size:17px; }}
.grade .txt div.small {{ color:var(--muted); font-size:14px; }}
.legend {{ display:flex; gap:10px; flex-wrap:wrap; margin:18px 0 30px;
  color:var(--muted); font-size:14px; align-items:center; }}
h2 {{ font-size:14px; letter-spacing:.16em; text-transform:uppercase;
  color:var(--muted); margin:34px 0 14px; }}
.card {{ background:var(--panel); border:1px solid var(--line);
  border-radius:14px; padding:16px 18px; margin-bottom:12px; }}
.card-top {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap;
  margin-bottom:8px; }}
.where {{ color:var(--accent); font-size:13px;
  font-family:"IBM Plex Mono",monospace; }}
.src {{ color:var(--muted); font-size:12px; margin-left:auto; }}
.prob {{ font-weight:600; font-size:18px; margin-bottom:4px; }}
.means {{ color:#cdd5de; }}
.means .lbl {{ color:var(--muted); }}
.tag {{ display:inline-block; padding:3px 11px; border-radius:999px;
  font-size:13px; font-weight:700; }}
footer {{ margin-top:46px; color:var(--muted); font-size:13px;
  border-top:1px solid var(--line); padding-top:18px; }}
</style>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=IBM+Plex+Sans:wght@400;600;700&display=swap" rel="stylesheet">
</head>
<body>
<div class="wrap">
  <div class="kicker">Security Check Report</div>
  <h1>{esc(results['target'])}</h1>
  <div class="sub">{esc(results['ip'])} &middot; {esc(results['scanned_at'])}</div>
 
  <p class="summary">{summary_line}</p>
 
  <div class="grade">
    <div class="big">{grade}</div>
    <div class="txt">
      <b>Overall safety grade: {grade}</b>
      <div class="small">{esc(GRADE_PLAIN.get(grade, ''))}
        A is best. F is worst.</div>
    </div>
  </div>
 
  <div class="legend">
    <span>What the labels mean:</span>
    {_sev_tag('HIGH')} = serious, do it first &nbsp;
    {_sev_tag('MEDIUM')} = important &nbsp;
    {_sev_tag('LOW')} = small
  </div>
 
  <h2>Problems we found</h2>
  {''.join(cards)}
 
  <footer>
    Made by Vulnerability Scanner CVE Edition.
    For computers you own or may test only.
    This tool finds weak spots. It does not attack them.
    Live bug data comes from the NVD (nvd.nist.gov).
  </footer>
</div>
</body>
</html>"""
 
    with open(f"{base}.html", "w") as hf:
        hf.write(doc)
 
 
# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
 
def main():
    parser = argparse.ArgumentParser(
        description="Educational vulnerability scanner with live CVE lookup.")
    parser.add_argument("host", help="Target host, e.g. 127.0.0.1")
    parser.add_argument("--start", type=int, default=1, help="First port")
    parser.add_argument("--end", type=int, default=1024, help="Last port")
    parser.add_argument("--top", action="store_true",
                        help="Scan only the common 'top' ports (fast)")
    parser.add_argument("--threads", type=int, default=100, help="Threads")
    parser.add_argument("--web", action="store_true",
                        help="Also check SSL and HTTP headers")
    parser.add_argument("--online", action="store_true",
                        help="Look up live CVEs from the NVD (needs internet)")
    parser.add_argument("--api-key", default=None,
                        help="Optional NVD API key (makes --online faster)")
    parser.add_argument("--out", default="scan_report",
                        help="Base name for the output files")
    args = parser.parse_args()
 
    print("=" * 60)
    print(" Vulnerability Scanner CVE Edition")
    print(" Only scan systems you own or may test. Finds, does not attack.")
    print("=" * 60)
 
    try:
        socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Error: could not resolve host '{args.host}'.")
        return
 
    ports = TOP_PORTS if args.top else list(range(args.start, args.end + 1))
    results = run_scan(args.host, ports, args.threads,
                       args.web, args.online, args.api_key)
    print_report(results)
    save_json_text(results, args.out)
    save_html(results, args.out)
    print(f"\nSaved: {args.out}.json, {args.out}.txt, {args.out}.html")
    print("Open the .html file in a browser to read the easy report.")
 
 
if __name__ == "__main__":
    main()
 