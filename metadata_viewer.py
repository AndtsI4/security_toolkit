"""
metadata_viewer.py — File Metadata Extractor
==============================================
Extracts hidden metadata from images, PDFs, Word documents, and audio files.
Highlights privacy risks like GPS coordinates, author names, and device serials.

Supported:
  Images  — JPEG, PNG, TIFF, GIF, WebP  (EXIF, GPS, camera info)
  PDFs    — Author, creator, software, dates
  Word    — Author, revision history, company, dates
  Audio   — ID3/FLAC tags, bitrate, duration

SETUP:
    pip install Pillow pypdf python-docx mutagen rich

USAGE:
    python metadata_viewer.py photo.jpg
    python metadata_viewer.py document.pdf
    python metadata_viewer.py song.mp3 --export json
    python metadata_viewer.py photo.jpg --strip
"""

import sys
import json
import argparse
import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".gif", ".bmp", ".webp"}
PDF_EXTS   = {".pdf"}
DOCX_EXTS  = {".docx", ".doc"}
AUDIO_EXTS = {".mp3", ".flac", ".ogg", ".m4a", ".aac", ".wav", ".wma"}


# ─── Image ───────────────────────────────────────────────────────────────────

def _dms_to_decimal(dms_str: str, ref: str) -> float | None:
    """Convert a DMS tuple string like '(53.0, 22.0, 11.5)' to decimal degrees."""
    try:
        nums   = [float(x.strip()) for x in dms_str.strip("()").split(",")]
        result = nums[0] + nums[1] / 60 + nums[2] / 3600
        if ref.strip("'\" ").upper() in ("S", "W"):
            result = -result
        return result
    except Exception:
        return None


def read_image(path: Path) -> dict:
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        console.print("[red]Pillow not installed → pip install Pillow[/red]")
        return {}

    try:
        img = Image.open(path)
    except Exception as e:
        console.print(f"[red]Cannot open image: {e}[/red]")
        return {}

    metadata: dict = {
        "File Info": {
            "Format":     img.format or path.suffix.upper().lstrip("."),
            "Mode":       img.mode,
            "Dimensions": f"{img.width} × {img.height} px",
        }
    }

    try:
        raw_exif = img._getexif()
    except AttributeError:
        raw_exif = None

    if not raw_exif:
        return metadata

    PRIORITY = {
        "Make", "Model", "Software", "DateTime", "DateTimeOriginal",
        "DateTimeDigitized", "Artist", "Copyright", "ImageDescription",
        "BodySerialNumber", "CameraOwnerName", "LensMake", "LensModel",
        "ExposureTime", "FNumber", "ISOSpeedRatings", "Flash",
        "FocalLength", "WhiteBalance",
    }

    camera, extra, gps_raw = {}, {}, {}

    for tag_id, value in raw_exif.items():
        tag = TAGS.get(tag_id, str(tag_id))

        if tag == "GPSInfo":
            for gps_id, gps_val in value.items():
                gps_raw[GPSTAGS.get(gps_id, str(gps_id))] = str(gps_val)
            continue

        if isinstance(value, bytes):
            try:    val = value.decode("utf-8", errors="replace").strip()
            except: val = repr(value)
        else:
            val = str(value).strip()

        if not val or val in ("b''", ""):
            continue

        if tag in PRIORITY:
            camera[tag] = val
        else:
            extra[tag] = val

    if camera:
        metadata["Camera & Settings"] = camera

    if gps_raw:
        lat = _dms_to_decimal(
            gps_raw.get("GPSLatitude",  ""),
            gps_raw.get("GPSLatitudeRef", "N"),
        )
        lon = _dms_to_decimal(
            gps_raw.get("GPSLongitude",  ""),
            gps_raw.get("GPSLongitudeRef", "E"),
        )
        if lat is not None and lon is not None:
            gps_raw["⚠ Decimal Coords"] = f"{lat:.6f}, {lon:.6f}"
            gps_raw["⚠ Google Maps"]    = f"https://maps.google.com/?q={lat:.6f},{lon:.6f}"
        metadata["GPS Location"] = gps_raw

    if extra:
        metadata["Other EXIF"] = extra

    return metadata


def strip_image(path: Path) -> None:
    """Re-save the image without any metadata."""
    try:
        from PIL import Image
    except ImportError:
        console.print("[red]Pillow not installed → pip install Pillow[/red]")
        return

    try:
        img  = Image.open(path)
        data = list(img.getdata())
        clean = Image.new(img.mode, img.size)
        clean.putdata(data)
        out  = path.parent / f"{path.stem}_stripped{path.suffix}"
        clean.save(out)
        console.print(f"[green]✔ Stripped image saved → {out}[/green]")
    except Exception as e:
        console.print(f"[red]Strip failed: {e}[/red]")


# ─── PDF ─────────────────────────────────────────────────────────────────────

def read_pdf(path: Path) -> dict:
    try:
        from pypdf import PdfReader
    except ImportError:
        console.print("[red]pypdf not installed → pip install pypdf[/red]")
        return {}

    try:
        reader = PdfReader(path)
        info   = reader.metadata
    except Exception as e:
        console.print(f"[red]Cannot read PDF: {e}[/red]")
        return {}

    doc = {"Pages": str(len(reader.pages))}
    if info:
        for key, val in info.items():
            doc[key.lstrip("/")] = str(val)

    return {"Document Info": doc} if doc else {}


# ─── Word Document ────────────────────────────────────────────────────────────

def read_docx(path: Path) -> dict:
    try:
        from docx import Document
    except ImportError:
        console.print("[red]python-docx not installed → pip install python-docx[/red]")
        return {}

    try:
        doc  = Document(path)
        core = doc.core_properties
    except Exception as e:
        console.print(f"[red]Cannot read .docx: {e}[/red]")
        return {}

    props = {
        "Author":           core.author,
        "Last Modified By": core.last_modified_by,
        "Created":          str(core.created)  if core.created  else None,
        "Modified":         str(core.modified) if core.modified else None,
        "Title":            core.title,
        "Subject":          core.subject,
        "Description":      core.description,
        "Keywords":         core.keywords,
        "Category":         core.category,
        "Revision":         str(core.revision) if core.revision else None,
        "Language":         core.language,
        "Content Status":   core.content_status,
    }
    props = {k: v for k, v in props.items() if v and str(v).strip()}
    return {"Document Properties": props} if props else {}


# ─── Audio ────────────────────────────────────────────────────────────────────

def read_audio(path: Path) -> dict:
    try:
        import mutagen
    except ImportError:
        console.print("[red]mutagen not installed → pip install mutagen[/red]")
        return {}

    try:
        audio = mutagen.File(path, easy=True)
    except Exception as e:
        console.print(f"[red]Cannot read audio: {e}[/red]")
        return {}

    if audio is None:
        return {}

    TAG_MAP = {
        "title":       "Title",
        "artist":      "Artist",
        "album":       "Album",
        "albumartist": "Album Artist",
        "date":        "Year",
        "genre":       "Genre",
        "tracknumber": "Track",
        "discnumber":  "Disc",
        "composer":    "Composer",
        "comment":     "Comment",
        "encoder":     "Encoder",
    }

    tags = {}
    for key, label in TAG_MAP.items():
        val = audio.get(key)
        if val:
            tags[label] = val[0] if isinstance(val, list) else str(val)

    tech = {}
    info = getattr(audio, "info", None)
    if info:
        if hasattr(info, "length"):
            s = int(info.length)
            tech["Duration"] = f"{s // 60}:{s % 60:02d}"
        if hasattr(info, "bitrate"):
            tech["Bitrate"] = f"{info.bitrate // 1000} kbps"
        if hasattr(info, "sample_rate"):
            tech["Sample Rate"] = f"{info.sample_rate} Hz"
        if hasattr(info, "channels"):
            tech["Channels"] = str(info.channels)

    result = {}
    if tags:
        result["Tags"] = tags
    if tech:
        result["Technical"] = tech
    return result


# ─── Dispatcher ──────────────────────────────────────────────────────────────

def read_metadata(path: Path) -> tuple[str, dict]:
    ext = path.suffix.lower()
    if ext in IMAGE_EXTS: return "Image",         read_image(path)
    if ext in PDF_EXTS:   return "PDF",           read_pdf(path)
    if ext in DOCX_EXTS:  return "Word Document", read_docx(path)
    if ext in AUDIO_EXTS: return "Audio",         read_audio(path)
    return "Unknown", {}


# ─── Privacy Warnings ────────────────────────────────────────────────────────

GPS_FIELDS    = {"gps", "coordinates", "maps", "latitude", "longitude"}
AUTHOR_FIELDS = {"author", "artist", "creator", "made by", "last modified by"}
SERIAL_FIELDS = {"serial", "serialnumber"}
LEAKY_FIELDS  = {"company", "username", "useraccount"}

def get_warnings(metadata: dict) -> list[str]:
    warnings = []
    for section, fields in metadata.items():
        for field, value in fields.items():
            fl = field.lower()
            if any(g in fl for g in GPS_FIELDS):
                warnings.append(f"📍 GPS data found — reveals exact location where photo was taken")
            if any(a in fl for a in AUTHOR_FIELDS) and value:
                warnings.append(f"👤 Identity exposed: {field} = \"{value}\"")
            if any(s in fl for s in SERIAL_FIELDS) and value:
                warnings.append(f"📷 Device serial number found — links this file to a physical device")
            if any(l in fl for l in LEAKY_FIELDS) and value:
                warnings.append(f"🏢 Org/user info found: {field} = \"{value}\"")
    return list(dict.fromkeys(warnings))  # deduplicate, preserve order


# ─── Display ─────────────────────────────────────────────────────────────────

def display(path: Path, file_type: str, metadata: dict) -> None:
    size     = path.stat().st_size
    size_str = f"{size / 1024:.1f} KB" if size < 1_000_000 else f"{size / 1_000_000:.2f} MB"

    console.print()
    console.print(Panel.fit(
        f"[bold]Metadata Viewer[/bold]\n"
        f"[dim]{path.name}[/dim]  ·  {file_type}  ·  {size_str}",
        border_style="bright_blue",
    ))

    if not metadata:
        console.print("[yellow]  No metadata found in this file.[/yellow]\n")
        return

    for section, fields in metadata.items():
        t = Table(
            title=section,
            box=box.ROUNDED,
            border_style="bright_blue",
            header_style="bold bright_blue",
            min_width=60,
        )
        t.add_column("Field", style="bold", width=26)
        t.add_column("Value", width=58)

        for field, value in fields.items():
            fl  = field.lower()
            val = str(value)[:90] + ("…" if len(str(value)) > 90 else "")

            if any(g in fl for g in GPS_FIELDS):
                row = Text(val, style="bold bright_red")
            elif any(a in fl for a in AUTHOR_FIELDS):
                row = Text(val, style="cyan")
            elif "date" in fl or "time" in fl or "created" in fl or "modified" in fl:
                row = Text(val, style="yellow")
            elif any(s in fl for s in SERIAL_FIELDS):
                row = Text(val, style="bold red")
            else:
                row = Text(val)

            t.add_row(field, row)

        console.print()
        console.print(t)

    warnings = get_warnings(metadata)
    if warnings:
        console.print("\n  [bold yellow]⚠  Privacy Warnings[/bold yellow]")
        for w in warnings:
            console.print(f"  [yellow]→[/yellow] {w}")

    console.print()


# ─── Export ──────────────────────────────────────────────────────────────────

def export_json(path: Path, file_type: str, metadata: dict, out: str) -> None:
    data = {
        "file":       str(path),
        "type":       file_type,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "metadata":   metadata,
        "warnings":   get_warnings(metadata),
    }
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]✔ JSON report saved → {out}[/green]")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="File Metadata Extractor — images, PDFs, Word docs, audio",
        epilog="Example: python metadata_viewer.py photo.jpg --strip",
    )
    parser.add_argument("file",           help="Path to the file")
    parser.add_argument("--export", "-e", choices=["json"], help="Export results to JSON")
    parser.add_argument("--output", "-o", help="Output filename")
    parser.add_argument("--strip",        action="store_true",
                        help="Strip metadata from image and save a clean copy (images only)")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)

    file_type, metadata = read_metadata(path)

    if file_type == "Unknown":
        console.print(f"[yellow]Unsupported file type: {path.suffix}[/yellow]")
        console.print(f"Supported: {', '.join(IMAGE_EXTS | PDF_EXTS | DOCX_EXTS | AUDIO_EXTS)}")
        sys.exit(1)

    display(path, file_type, metadata)

    if args.strip:
        if path.suffix.lower() in IMAGE_EXTS:
            strip_image(path)
        else:
            console.print("[yellow]--strip only works with image files.[/yellow]")

    if args.export:
        out = args.output or f"{path.stem}_metadata.json"
        export_json(path, file_type, metadata, out)


if __name__ == "__main__":
    main()
