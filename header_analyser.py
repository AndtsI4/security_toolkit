"""
header_analyser.py — HTTP Security Header Analyser
====================================================
Fetches a URL and grades its HTTP security headers.
Shows what's present, what's missing, why it matters, and how to fix it.

SETUP:
    pip install requests rich

USAGE:
    python header_analyser.py example.com
    python header_analyser.py https://example.com --export json
    python header_analyser.py example.com --export html
"""

import sys
import json
import argparse
import datetime

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


# ─── Header Definitions ─────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces browsers to use HTTPS only, preventing SSL stripping attacks.",
        "fix":         "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "critical":    True,
        "check":       lambda v: "max-age" in v.lower(),
    },
    "Content-Security-Policy": {
        "description": "Restricts content sources to prevent XSS and data injection.",
        "fix":         "Content-Security-Policy: default-src 'self'",
        "critical":    True,
        "check":       lambda v: len(v) > 0,
    },
    "X-Frame-Options": {
        "description": "Prevents your page being embedded in iframes — blocks clickjacking.",
        "fix":         "X-Frame-Options: DENY",
        "critical":    True,
        "check":       lambda v: v.upper().strip() in ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "description": "Stops browsers guessing the content type (MIME-sniffing attacks).",
        "fix":         "X-Content-Type-Options: nosniff",
        "critical":    True,
        "check":       lambda v: v.lower().strip() == "nosniff",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer info leaks to other sites.",
        "fix":         "Referrer-Policy: strict-origin-when-cross-origin",
        "critical":    False,
        "check":       lambda v: len(v.strip()) > 0,
    },
    "Permissions-Policy": {
        "description": "Restricts which browser APIs and features the page can use.",
        "fix":         "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "critical":    False,
        "check":       lambda v: len(v.strip()) > 0,
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter — still useful for older browsers.",
        "fix":         "X-XSS-Protection: 1; mode=block",
        "critical":    False,
        "check":       lambda v: v.strip().startswith("1"),
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates the browsing context to prevent cross-origin attacks like Spectre.",
        "fix":         "Cross-Origin-Opener-Policy: same-origin",
        "critical":    False,
        "check":       lambda v: len(v.strip()) > 0,
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls which origins can load your resources.",
        "fix":         "Cross-Origin-Resource-Policy: same-origin",
        "critical":    False,
        "check":       lambda v: len(v.strip()) > 0,
    },
    "Cache-Control": {
        "description": "Controls caching to prevent sensitive data being stored.",
        "fix":         "Cache-Control: no-store, max-age=0",
        "critical":    False,
        "check":       lambda v: len(v.strip()) > 0,
    },
}

# Headers that leak info about the server — should be removed
LEAKY_HEADERS = {
    "Server":               "Reveals server software/version. Attackers use this for targeted exploits.",
    "X-Powered-By":         "Reveals backend tech (e.g. PHP/7.4). Remove this header entirely.",
    "X-AspNet-Version":     "Reveals ASP.NET version. Remove this header entirely.",
    "X-AspNetMvc-Version":  "Reveals ASP.NET MVC version. Remove this header entirely.",
    "X-Generator":          "Reveals CMS or framework. Remove this header entirely.",
}


# ─── Grading ─────────────────────────────────────────────────────────────────

def calculate_grade(results: dict) -> tuple[str, str]:
    critical = [k for k, v in SECURITY_HEADERS.items() if v["critical"]]
    optional = [k for k, v in SECURITY_HEADERS.items() if not v["critical"]]

    crit_pass  = sum(1 for k in critical if results[k]["present"] and results[k]["valid"])
    opt_pass   = sum(1 for k in optional if results[k]["present"] and results[k]["valid"])

    score = (crit_pass / len(critical)) * 80 + (opt_pass / len(optional)) * 20

    if   score >= 90: return "A+", "bright_green"
    elif score >= 75: return "A",  "green"
    elif score >= 60: return "B",  "yellow"
    elif score >= 40: return "C",  "dark_orange"
    elif score >= 20: return "D",  "red"
    else:             return "F",  "bright_red"


# ─── Fetch & Analyse ─────────────────────────────────────────────────────────

def fetch(url: str) -> tuple[dict, str, int]:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    resp = requests.get(
        url,
        timeout=10,
        allow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (SecurityHeaderCheck/1.0)"},
    )
    return dict(resp.headers), resp.url, resp.status_code


def analyse(raw: dict) -> tuple[dict, dict]:
    lower = {k.lower(): v for k, v in raw.items()}

    results = {}
    for name, meta in SECURITY_HEADERS.items():
        val     = lower.get(name.lower(), "")
        present = bool(val)
        valid   = meta["check"](val) if present else False
        results[name] = {
            "present":     present,
            "valid":       valid,
            "value":       val,
            "description": meta["description"],
            "fix":         meta["fix"],
            "critical":    meta["critical"],
        }

    leaky = {}
    for name, warning in LEAKY_HEADERS.items():
        val = lower.get(name.lower(), "")
        if val:
            leaky[name] = {"value": val, "warning": warning}

    return results, leaky


# ─── Display ─────────────────────────────────────────────────────────────────

def display(url: str, final_url: str, status: int, results: dict, leaky: dict) -> None:
    grade, color = calculate_grade(results)

    passing = sum(1 for r in results.values() if r["present"] and r["valid"])
    total   = len(results)

    console.print()
    console.print(Panel.fit(
        f"[bold]HTTP Security Header Analyser[/bold]\n[dim]{final_url}[/dim]",
        border_style="bright_blue",
    ))
    console.print(
        f"\n  Status [cyan]{status}[/cyan]   "
        f"Headers passing [cyan]{passing}/{total}[/cyan]   "
        f"Grade [{color}][bold]{grade}[/bold][/{color}]\n"
    )

    # Main table
    t = Table(box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_blue")
    t.add_column("Header",   style="bold", width=33)
    t.add_column("Status",   justify="center", width=12)
    t.add_column("Detail",   width=46)
    t.add_column("Priority", justify="center", width=10)

    for name, r in results.items():
        if r["present"] and r["valid"]:
            badge  = Text("✔  Pass",    style="green")
            detail = Text(r["value"][:55] + ("…" if len(r["value"]) > 55 else ""), style="dim green")
        elif r["present"]:
            badge  = Text("⚠  Weak",    style="yellow")
            detail = Text(f"Misconfigured: {r['value'][:40]}", style="yellow")
        else:
            badge  = Text("✘  Missing", style="red")
            detail = Text(f"Add: {r['fix'][:50]}", style="dim red")

        prio = Text("Critical", style="bold red") if r["critical"] else Text("Optional", style="dim")
        t.add_row(name, badge, detail, prio)

    console.print(t)

    # Information leakage
    if leaky:
        console.print("\n  [bold red]⚠  Information Leakage — remove these headers[/bold red]")
        lt = Table(box=box.SIMPLE, header_style="bold red")
        lt.add_column("Header",  style="bold", width=26)
        lt.add_column("Value",   width=30)
        lt.add_column("Risk",    width=52)
        for name, d in leaky.items():
            lt.add_row(name, d["value"], d["warning"])
        console.print(lt)

    # Remediation for missing critical headers
    missing = [n for n, r in results.items() if not r["present"] and r["critical"]]
    if missing:
        console.print("\n  [bold yellow]What to fix first:[/bold yellow]")
        for name in missing:
            r = results[name]
            console.print(f"  [red]→[/red] [bold]{name}[/bold]")
            console.print(f"    [dim]{r['description']}[/dim]")
            console.print(f"    [cyan]{r['fix']}[/cyan]\n")

    console.print()


# ─── Export ──────────────────────────────────────────────────────────────────

def to_json(url: str, results: dict, leaky: dict, grade: str, path: str) -> None:
    data = {
        "url":       url,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "grade":     grade,
        "headers":   results,
        "leaky":     leaky,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]✔ JSON report saved → {path}[/green]")


def to_html(url: str, results: dict, leaky: dict, grade: str, path: str) -> None:
    grade_col = {"A+": "#00e676", "A": "#69f0ae", "B": "#ffee58",
                 "C": "#ffa726", "D": "#ef5350", "F": "#b71c1c"}.get(grade, "#aaa")

    rows = ""
    for name, r in results.items():
        if r["present"] and r["valid"]:
            badge = "<span style='color:#69f0ae'>✔ Pass</span>"
            val   = r["value"][:80]
        elif r["present"]:
            badge = "<span style='color:#ffa726'>⚠ Weak</span>"
            val   = r["value"][:80]
        else:
            badge = "<span style='color:#ef5350'>✘ Missing</span>"
            val   = f"Add: {r['fix']}"
        prio  = "<b style='color:#ef5350'>Critical</b>" if r["critical"] else "<span style='color:#777'>Optional</span>"
        rows += (f"<tr><td><b>{name}</b><br>"
                 f"<small style='color:#888'>{r['description']}</small></td>"
                 f"<td>{badge}</td><td><code>{val}</code></td><td>{prio}</td></tr>")

    leaky_rows = "".join(
        f"<tr><td><b>{n}</b></td><td><code>{d['value']}</code></td><td>{d['warning']}</td></tr>"
        for n, d in leaky.items()
    )
    leaky_section = (
        f"<h2 style='color:#ef5350'>⚠ Information Leakage</h2>"
        f"<table><tr><th>Header</th><th>Value</th><th>Risk</th></tr>{leaky_rows}</table>"
        if leaky else ""
    )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Header Report – {url}</title>
<style>
  body  {{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem;max-width:1100px;margin:auto}}
  h1    {{color:#58a6ff}}  h2 {{color:#f0883e;margin-top:2rem}}
  table {{width:100%;border-collapse:collapse;margin-top:.8rem}}
  th    {{background:#161b22;color:#58a6ff;padding:.6rem .8rem;text-align:left}}
  td    {{padding:.5rem .8rem;border-bottom:1px solid #21262d;vertical-align:top}}
  code  {{background:#161b22;padding:2px 5px;border-radius:3px;font-size:.82em}}
  .grade{{font-size:3.5rem;font-weight:700;color:{grade_col}}}
  small {{font-size:.8em}}
</style></head><body>
<h1>HTTP Security Header Report</h1>
<p>URL: <code>{url}</code> &nbsp;·&nbsp;
   Scanned: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;·&nbsp;
   Grade: <span class="grade">{grade}</span></p>
<h2>Security Headers</h2>
<table>
  <tr><th>Header</th><th>Status</th><th>Value / Recommendation</th><th>Priority</th></tr>
  {rows}
</table>
{leaky_section}
</body></html>"""

    with open(path, "w") as f:
        f.write(html)
    console.print(f"[green]✔ HTML report saved → {path}[/green]")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HTTP Security Header Analyser",
        epilog="Example: python header_analyser.py example.com --export html",
    )
    parser.add_argument("url",            help="Target URL or domain  (e.g. example.com)")
    parser.add_argument("--export",       choices=["json", "html"], help="Export report format")
    parser.add_argument("--output", "-o", help="Output filename  (default: report.json/html)")
    args = parser.parse_args()

    console.print(f"\n[dim]Fetching {args.url} …[/dim]")

    try:
        raw, final_url, status = fetch(args.url)
    except requests.exceptions.SSLError:
        console.print("[red]SSL error — try prefixing with http://[/red]"); sys.exit(1)
    except requests.exceptions.ConnectionError:
        console.print("[red]Could not connect. Check the URL.[/red]");      sys.exit(1)
    except requests.exceptions.Timeout:
        console.print("[red]Request timed out.[/red]");                      sys.exit(1)

    results, leaky = analyse(raw)
    grade, _       = calculate_grade(results)

    display(args.url, final_url, status, results, leaky)

    if args.export:
        out = args.output or f"report.{args.export}"
        if args.export == "json":
            to_json(final_url, results, leaky, grade, out)
        else:
            to_html(final_url, results, leaky, grade, out)


if __name__ == "__main__":
    main()
