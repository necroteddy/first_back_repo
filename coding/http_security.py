#!/usr/bin/env python3
"""
HTTP Security Headers Scanner
Usage: python security_headers_scan.py https://example.com
"""
 
import sys
import urllib.request
import urllib.error
import json
import ssl
 
HEADERS_TO_CHECK = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]
 
HEADER_INFO = {
    "content-security-policy":       ("CSP",   "HIGH",   "Prevents XSS and injection attacks"),
    "strict-transport-security":     ("HSTS",  "HIGH",   "Forces HTTPS connections"),
    "x-frame-options":               ("XFO",   "HIGH",   "Prevents clickjacking"),
    "x-content-type-options":        ("XCTO",  "MEDIUM", "Stops MIME-type sniffing"),
    "referrer-policy":               ("RP",    "MEDIUM", "Controls referrer information"),
    "permissions-policy":            ("PP",    "MEDIUM", "Restricts browser features"),
    "x-xss-protection":              ("XSS",   "LOW",    "Legacy XSS filter (mostly deprecated)"),
    "cross-origin-embedder-policy":  ("COEP",  "MEDIUM", "Controls cross-origin embedding"),
    "cross-origin-opener-policy":    ("COOP",  "MEDIUM", "Isolates browsing context"),
    "cross-origin-resource-policy":  ("CORP",  "MEDIUM", "Restricts cross-origin resource loads"),
}
 
# --- Colors ---
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"
 
 
def fetch_headers(url: str) -> dict:
    """Fetch HTTP headers from a URL. Returns a dict of lowercase header names."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "SecurityHeadersScanner/1.0"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        # Some servers reject HEAD — try GET
        req2 = urllib.request.Request(url, headers={"User-Agent": "SecurityHeadersScanner/1.0"})
        with urllib.request.urlopen(req2, context=ctx, timeout=10) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
 
 
def score_headers(found: dict) -> tuple[int, list]:
    """
    Score the headers. Returns (score 0-100, list of result dicts).
    HIGH missing = -15, MEDIUM missing = -8, LOW missing = -2
    """
    penalties = {"HIGH": 15, "MEDIUM": 8, "LOW": 2}
    score = 100
    results = []
 
    for header in HEADERS_TO_CHECK:
        abbr, importance, desc = HEADER_INFO[header]
        value = found.get(header)
        present = value is not None
 
        if not present:
            score -= penalties[importance]
            status = "MISSING"
        else:
            status = "PRESENT"
 
        results.append({
            "header":     header,
            "abbr":       abbr,
            "importance": importance,
            "desc":       desc,
            "value":      value,
            "status":     status,
        })
 
    score = max(0, score)
    return score, results
 
 
def score_to_grade(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 85: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 45: return "D"
    return "F"
 
 
def grade_color(grade: str) -> str:
    if grade in ("A+", "A"): return GREEN
    if grade == "B":         return CYAN
    if grade == "C":         return YELLOW
    return RED
 
 
def status_icon(status: str) -> str:
    if status == "PRESENT": return f"{GREEN}✔{RESET}"
    return f"{RED}✘{RESET}"
 
 
def importance_color(importance: str) -> str:
    if importance == "HIGH":   return RED
    if importance == "MEDIUM": return YELLOW
    return DIM
 
 
def print_report(url: str, score: int, grade: str, results: list):
    width = 72
    line  = "─" * width
 
    print(f"\n{BOLD}{line}{RESET}")
    print(f"{BOLD}  HTTP Security Headers Report{RESET}")
    print(f"  {DIM}{url}{RESET}")
    print(f"{BOLD}{line}{RESET}")
 
    gc = grade_color(grade)
    print(f"\n  Grade:  {gc}{BOLD}{grade}{RESET}   Score: {BOLD}{score}/100{RESET}\n")
 
    print(f"  {'HEADER':<42} {'IMP':<7} {'STATUS'}")
    print(f"  {'─'*42} {'─'*7} {'─'*8}")
 
    for r in results:
        icon = status_icon(r["status"])
        imp_c = importance_color(r["importance"])
        name_col = f"{r['header']}"
        print(f"  {icon} {name_col:<40} {imp_c}{r['importance']:<7}{RESET} {r['status']}")
        if r["value"]:
            val = r["value"]
            if len(val) > 60:
                val = val[:57] + "..."
            print(f"     {DIM}{val}{RESET}")
 
    print(f"\n{BOLD}{line}{RESET}")
 
    missing_high = [r for r in results if r["status"] == "MISSING" and r["importance"] == "HIGH"]
    missing_med  = [r for r in results if r["status"] == "MISSING" and r["importance"] == "MEDIUM"]
    present      = [r for r in results if r["status"] == "PRESENT"]
 
    print(f"\n  {BOLD}Summary{RESET}")
    print(f"  Present : {GREEN}{len(present)}/{len(results)}{RESET} headers found")
 
    if missing_high:
        names = ", ".join(r["header"] for r in missing_high)
        print(f"  {RED}Missing HIGH priority:{RESET} {names}")
    if missing_med:
        names = ", ".join(r["header"] for r in missing_med)
        print(f"  {YELLOW}Missing MEDIUM priority:{RESET} {names}")
 
    if grade in ("A+", "A"):
        print(f"\n  {GREEN}✔ Good security posture!{RESET}")
    elif grade == "B":
        print(f"\n  {CYAN}ℹ A few headers missing. Review above.{RESET}")
    else:
        print(f"\n  {RED}⚠ Significant headers missing. Fix HIGH priority first.{RESET}")
 
    print(f"\n{BOLD}{line}{RESET}\n")
 
 
def export_json(url: str, score: int, grade: str, results: list, path: str):
    data = {
        "url":     url,
        "score":   score,
        "grade":   grade,
        "headers": results,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Report saved to: {path}\n")
 
 
def main():
    args = sys.argv[1:]
    if not args:
        print(f"\nUsage: python security_headers_scan.py <URL> [--json report.json]\n")
        sys.exit(1)
 
    url        = args[0]
    json_out   = None
 
    if "--json" in args:
        idx = args.index("--json")
        json_out = args[idx + 1] if idx + 1 < len(args) else "report.json"
 
    if not url.startswith("http"):
        url = "https://" + url
 
    print(f"\n  Scanning {url} ...")
 
    try:
        found = fetch_headers(url)
    except Exception as e:
        print(f"\n  {RED}Error fetching URL:{RESET} {e}\n")
        sys.exit(1)
 
    score, results = score_headers(found)
    grade          = score_to_grade(score)
 
    print_report(url, score, grade, results)
 
    if json_out:
        export_json(url, score, grade, results, json_out)
 
 
if __name__ == "__main__":
    main()