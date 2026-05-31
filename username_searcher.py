"""
username_searcher.py — Cross-Platform Username Checker
=======================================================
Checks if a username exists across 55+ platforms concurrently.
Useful for OSINT investigations and username availability checks.

SETUP:
    pip install requests rich

USAGE:
    python username_searcher.py johndoe
    python username_searcher.py johndoe --only-found
    python username_searcher.py johndoe --export json
    python username_searcher.py johndoe --export txt
"""

import sys
import json
import argparse
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box

console = Console()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )
}

# ─── Platform Registry ───────────────────────────────────────────────────────
# url:   {u} is replaced with the username
# code:  HTTP status that means "found"  (usually 200)
# error: a string in the response body that means "not found even if HTTP 200"

PLATFORMS: dict[str, dict] = {
    # ── Dev & Code ───────────────────────────────────────────────────────────
    "GitHub":       {"url": "https://github.com/{u}",                           "code": 200, "error": None},
    "GitLab":       {"url": "https://gitlab.com/{u}",                           "code": 200, "error": None},
    "Bitbucket":    {"url": "https://bitbucket.org/{u}/",                       "code": 200, "error": None},
    "Replit":       {"url": "https://replit.com/@{u}",                          "code": 200, "error": None},
    "CodePen":      {"url": "https://codepen.io/{u}",                           "code": 200, "error": None},
    "npm":          {"url": "https://www.npmjs.com/~{u}",                       "code": 200, "error": None},
    "PyPI":         {"url": "https://pypi.org/user/{u}/",                       "code": 200, "error": None},
    "DockerHub":    {"url": "https://hub.docker.com/u/{u}",                     "code": 200, "error": None},
    "Hacker News":  {"url": "https://news.ycombinator.com/user?id={u}",         "code": 200, "error": "No such user"},
    "LeetCode":     {"url": "https://leetcode.com/{u}",                         "code": 200, "error": None},
    "Codeforces":   {"url": "https://codeforces.com/profile/{u}",               "code": 200, "error": "handle: User with handle"},
    "HackerEarth":  {"url": "https://www.hackerearth.com/@{u}",                 "code": 200, "error": None},
    "Exercism":     {"url": "https://exercism.org/profiles/{u}",                "code": 200, "error": None},

    # ── Social ───────────────────────────────────────────────────────────────
    "Twitter / X":  {"url": "https://x.com/{u}",                                "code": 200, "error": "This account doesn't exist"},
    "Instagram":    {"url": "https://www.instagram.com/{u}/",                   "code": 200, "error": "Page Not Found"},
    "TikTok":       {"url": "https://www.tiktok.com/@{u}",                      "code": 200, "error": "Couldn't find this account"},
    "Reddit":       {"url": "https://www.reddit.com/user/{u}",                  "code": 200, "error": "nobody on Reddit goes by that name"},
    "Tumblr":       {"url": "https://{u}.tumblr.com",                           "code": 200, "error": "There's nothing here"},
    "Pinterest":    {"url": "https://www.pinterest.com/{u}/",                   "code": 200, "error": None},
    "Mastodon":     {"url": "https://mastodon.social/@{u}",                     "code": 200, "error": None},
    "Bluesky":      {"url": "https://bsky.app/profile/{u}",                     "code": 200, "error": None},
    "Threads":      {"url": "https://www.threads.net/@{u}",                     "code": 200, "error": None},
    "Linktree":     {"url": "https://linktr.ee/{u}",                            "code": 200, "error": None},
    "Keybase":      {"url": "https://keybase.io/{u}",                           "code": 200, "error": None},

    # ── Content & Blogging ───────────────────────────────────────────────────
    "YouTube":      {"url": "https://www.youtube.com/@{u}",                     "code": 200, "error": None},
    "Twitch":       {"url": "https://www.twitch.tv/{u}",                        "code": 200, "error": None},
    "Medium":       {"url": "https://medium.com/@{u}",                          "code": 200, "error": None},
    "Dev.to":       {"url": "https://dev.to/{u}",                               "code": 200, "error": None},
    "Hashnode":     {"url": "https://hashnode.com/@{u}",                        "code": 200, "error": None},
    "Substack":     {"url": "https://substack.com/@{u}",                        "code": 200, "error": None},
    "Vimeo":        {"url": "https://vimeo.com/{u}",                            "code": 200, "error": None},

    # ── Music & Audio ────────────────────────────────────────────────────────
    "Spotify":      {"url": "https://open.spotify.com/user/{u}",                "code": 200, "error": None},
    "SoundCloud":   {"url": "https://soundcloud.com/{u}",                       "code": 200, "error": None},
    "Last.fm":      {"url": "https://www.last.fm/user/{u}",                     "code": 200, "error": None},
    "Bandcamp":     {"url": "https://bandcamp.com/{u}",                         "code": 200, "error": None},

    # ── Design & Creative ────────────────────────────────────────────────────
    "Behance":      {"url": "https://www.behance.net/{u}",                      "code": 200, "error": None},
    "Dribbble":     {"url": "https://dribbble.com/{u}",                         "code": 200, "error": None},
    "Figma":        {"url": "https://www.figma.com/@{u}",                       "code": 200, "error": None},
    "Flickr":       {"url": "https://www.flickr.com/people/{u}",                "code": 200, "error": None},
    "ArtStation":   {"url": "https://www.artstation.com/{u}",                   "code": 200, "error": None},
    "DeviantArt":   {"url": "https://www.deviantart.com/{u}",                   "code": 200, "error": None},

    # ── Gaming ───────────────────────────────────────────────────────────────
    "Steam":        {"url": "https://steamcommunity.com/id/{u}",                "code": 200, "error": "The specified profile could not be found"},
    "Chess.com":    {"url": "https://www.chess.com/member/{u}",                 "code": 200, "error": None},
    "Lichess":      {"url": "https://lichess.org/@/{u}",                        "code": 200, "error": None},

    # ── Professional ─────────────────────────────────────────────────────────
    "Product Hunt": {"url": "https://www.producthunt.com/@{u}",                 "code": 200, "error": None},
    "AngelList":    {"url": "https://angel.co/u/{u}",                           "code": 200, "error": None},
    "About.me":     {"url": "https://about.me/{u}",                             "code": 200, "error": None},
    "Gravatar":     {"url": "https://en.gravatar.com/{u}",                      "code": 200, "error": None},

    # ── Payments ─────────────────────────────────────────────────────────────
    "Venmo":        {"url": "https://venmo.com/{u}",                            "code": 200, "error": None},
    "Cash App":     {"url": "https://cash.app/${u}",                            "code": 200, "error": None},

    # ── Misc ─────────────────────────────────────────────────────────────────
    "Duolingo":     {"url": "https://www.duolingo.com/profile/{u}",             "code": 200, "error": None},
    "Letterboxd":   {"url": "https://letterboxd.com/{u}/",                      "code": 200, "error": None},
    "Goodreads":    {"url": "https://www.goodreads.com/{u}",                    "code": 200, "error": None},
    "Pastebin":     {"url": "https://pastebin.com/u/{u}",                       "code": 200, "error": "Not Found"},
    "Strava":       {"url": "https://www.strava.com/athletes/{u}",              "code": 200, "error": None},
}


# ─── Check Logic ─────────────────────────────────────────────────────────────

def check(platform: str, cfg: dict, username: str) -> dict:
    url = cfg["url"].replace("{u}", username)
    base = {"platform": platform, "url": url}

    try:
        r = requests.get(url, headers=HEADERS, timeout=9, allow_redirects=True)

        if r.status_code == 404:
            return {**base, "found": False, "note": "404 Not Found"}

        if r.status_code == 200:
            if cfg["error"] and cfg["error"].lower() in r.text.lower():
                return {**base, "found": False, "note": "Not found (content)"}
            return {**base, "found": True, "note": ""}

        if r.status_code == 403:
            return {**base, "found": None, "note": "403 Blocked"}

        return {**base, "found": False, "note": f"HTTP {r.status_code}"}

    except requests.exceptions.Timeout:
        return {**base, "found": None, "note": "Timeout"}
    except requests.exceptions.SSLError:
        return {**base, "found": None, "note": "SSL Error"}
    except requests.exceptions.ConnectionError:
        return {**base, "found": None, "note": "Connection Error"}
    except Exception as e:
        return {**base, "found": None, "note": str(e)[:40]}


def search(username: str) -> list[dict]:
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(
            f"[cyan]Checking [bold]{username}[/bold] across "
            f"{len(PLATFORMS)} platforms...",
            total=None,
        )

        with ThreadPoolExecutor(max_workers=25) as ex:
            futures = {ex.submit(check, p, c, username): p for p, c in PLATFORMS.items()}
            for future in as_completed(futures):
                results.append(future.result())

    return sorted(results, key=lambda r: (r["found"] is not True, r["platform"].lower()))


# ─── Display ─────────────────────────────────────────────────────────────────

def display(username: str, results: list[dict], only_found: bool) -> None:
    found     = [r for r in results if r["found"] is True]
    uncertain = [r for r in results if r["found"] is None]
    not_found = [r for r in results if r["found"] is False]

    console.print()
    console.print(Panel.fit(
        f"[bold]Username Searcher[/bold]  ·  [cyan]{username}[/cyan]\n"
        f"[dim]"
        f"[bright_green]{len(found)}[/bright_green] found  ·  "
        f"[yellow]{len(uncertain)}[/yellow] uncertain  ·  "
        f"[red]{len(not_found)}[/red] not found"
        f"[/dim]",
        border_style="bright_blue",
    ))

    to_show = found if only_found else results

    t = Table(box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_blue")
    t.add_column("Platform", style="bold", width=18)
    t.add_column("Status",   justify="center", width=16)
    t.add_column("URL",      width=56)

    for r in to_show:
        if r["found"] is True:
            badge = Text("✔  Found",     style="bright_green")
            url   = Text(r["url"],       style="bright_green")
        elif r["found"] is None:
            badge = Text("?  Uncertain", style="yellow")
            url   = Text(r["url"],       style="dim")
        else:
            if only_found:
                continue
            badge = Text("✘  Not found", style="dim red")
            url   = Text(r["url"],       style="dim")

        t.add_row(r["platform"], badge, url)

    console.print()
    console.print(t)
    console.print()


# ─── Export ──────────────────────────────────────────────────────────────────

def export_json(username: str, results: list[dict], path: str) -> None:
    found = [r for r in results if r["found"] is True]
    data  = {
        "username":   username,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "found_count": len(found),
        "found":      found,
        "all_results": results,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]✔ JSON saved → {path}[/green]")


def export_txt(username: str, results: list[dict], path: str) -> None:
    found = [r for r in results if r["found"] is True]
    with open(path, "w") as f:
        f.write(f"Username: {username}\n")
        f.write(f"Scanned:  {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n")
        f.write(f"Found on {len(found)} platform(s):\n\n")
        for r in found:
            f.write(f"  [{r['platform']}]  {r['url']}\n")
    console.print(f"[green]✔ TXT saved → {path}[/green]")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform username checker",
        epilog="Example: python username_searcher.py johndoe --only-found --export txt",
    )
    parser.add_argument("username",             help="Username to search")
    parser.add_argument("--only-found",         action="store_true", help="Only show matches")
    parser.add_argument("--export", "-e",       choices=["json", "txt"])
    parser.add_argument("--output", "-o",       help="Output filename")
    args = parser.parse_args()

    username = args.username.strip()
    if not username:
        console.print("[red]Username cannot be empty.[/red]")
        sys.exit(1)

    results = search(username)
    display(username, results, args.only_found)

    if args.export:
        out = args.output or f"{username}_results.{args.export}"
        if args.export == "json":
            export_json(username, results, out)
        else:
            export_txt(username, results, out)


if __name__ == "__main__":
    main()
