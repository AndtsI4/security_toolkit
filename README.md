# 🛡️ Security Toolkit

A collection of Python CLI tools for security analysis, OSINT, and privacy auditing.
Built for pentesters, developers, and anyone who wants to understand what their files and websites are exposing.

---

## Tools

| Tool | Description |
|---|---|
| `header_analyser.py` | Grade a website's HTTP security headers (A+ to F) |
| `metadata_viewer.py` | Extract hidden metadata from images, PDFs, Word docs, audio |
| `username_searcher.py` | Check if a username exists across 55+ platforms |

---

## Setup

```bash
git clone https://github.com/yourusername/security-toolkit
cd security-toolkit
pip install -r requirements.txt
```

---

## header_analyser.py

Fetches a URL and checks its HTTP security headers — grading the site from **A+** to **F**.
Shows what's missing, why it matters, and the exact header to add.

**Checks for:**
- `Strict-Transport-Security` — SSL stripping prevention
- `Content-Security-Policy` — XSS protection
- `X-Frame-Options` — clickjacking prevention
- `X-Content-Type-Options` — MIME sniffing prevention
- `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection` and more
- Information leakage via `Server`, `X-Powered-By` etc.

```bash
python header_analyser.py example.com
python header_analyser.py example.com --export html
python header_analyser.py example.com --export json --output report.json
```

**Example output:**
```
HTTP Security Header Analyser
https://example.com

Status 200   Headers passing 3/10   Grade D

  Header                         Status       Detail
  ─────────────────────────────────────────────────────
  Strict-Transport-Security      ✔ Pass       max-age=31536000; includeSubDomains
  Content-Security-Policy        ✘ Missing    Add: Content-Security-Policy: default-src 'self'
  X-Frame-Options                ✘ Missing    Add: X-Frame-Options: DENY
  ...
```

---

## metadata_viewer.py

Extracts hidden metadata from files — useful for OSINT, privacy auditing, and digital forensics.
Highlights GPS coordinates, author names, device serials and other data people don't realise they're sharing.

**Supported file types:**
- **Images** — JPEG, PNG, TIFF, GIF, WebP (EXIF, GPS, camera make/model, serial numbers)
- **PDFs** — Author, creator app, timestamps
- **Word docs** — Author, last modified by, revision count, company
- **Audio** — ID3/FLAC tags, bitrate, duration

```bash
python metadata_viewer.py photo.jpg
python metadata_viewer.py document.pdf
python metadata_viewer.py song.mp3
python metadata_viewer.py photo.jpg --strip        # saves a clean copy without metadata
python metadata_viewer.py photo.jpg --export json
```

**Example output:**
```
Metadata Viewer
photo.jpg  ·  Image  ·  3.2 MB

  Camera & Settings
  ──────────────────────────────────────
  Make              Canon
  Model             EOS R5
  DateTimeOriginal  2024:03:15 14:22:01
  BodySerialNumber  083021234567

  GPS Location
  ──────────────────────────────────────
  ⚠ Decimal Coords  51.509865, -0.118092
  ⚠ Google Maps     https://maps.google.com/?q=51.509865,-0.118092

⚠ Privacy Warnings
  → 📍 GPS data found — reveals exact location where photo was taken
  → 📷 Device serial number found — links this file to a physical device
```

---

## username_searcher.py

Checks if a username exists across **55+ platforms** concurrently.
Shows found profiles, uncertain results, and not-found — with export to JSON or TXT.

**Platforms include:** GitHub, GitLab, Reddit, Twitter/X, Instagram, TikTok, Twitch, YouTube,
Steam, Chess.com, Lichess, Spotify, SoundCloud, Medium, Dev.to, Behance, Dribbble, LeetCode,
Codeforces, npm, PyPI, DockerHub, Duolingo, Letterboxd, and more.

```bash
python username_searcher.py johndoe
python username_searcher.py johndoe --only-found
python username_searcher.py johndoe --export json
python username_searcher.py johndoe --export txt --output results.txt
```

**Example output:**
```
Username Searcher  ·  johndoe
14 found  ·  3 uncertain  ·  38 not found

  Platform       Status        URL
  ──────────────────────────────────────────────────────────────
  GitHub         ✔ Found       https://github.com/johndoe
  Reddit         ✔ Found       https://www.reddit.com/user/johndoe
  Dev.to         ✔ Found       https://dev.to/johndoe
  Hacker News    ✔ Found       https://news.ycombinator.com/user?id=johndoe
  Instagram      ✘ Not found   https://www.instagram.com/johndoe/
  ...
```

---

## Flags Reference

### header_analyser.py
| Flag | Description |
|---|---|
| `url` | Target domain or URL |
| `--export json\|html` | Save report to file |
| `--output filename` | Custom output filename |

### metadata_viewer.py
| Flag | Description |
|---|---|
| `file` | Path to the file |
| `--strip` | Save a metadata-free copy (images only) |
| `--export json` | Save report to JSON |
| `--output filename` | Custom output filename |

### username_searcher.py
| Flag | Description |
|---|---|
| `username` | Username to search |
| `--only-found` | Only display platforms where found |
| `--export json\|txt` | Save results |
| `--output filename` | Custom output filename |

---

## Disclaimer

These tools are for **educational purposes, ethical security testing, and personal privacy auditing only**.
Only test websites and files you own or have permission to test.
The author is not responsible for misuse.

---

## Contributing

Pull requests welcome. To add platforms to `username_searcher.py`, add an entry to the `PLATFORMS` dict:

```python
"PlatformName": {
    "url":   "https://example.com/users/{u}",
    "code":  200,
    "error": "User not found",   # or None if 404 is reliable
},
```

---

## License

MIT
