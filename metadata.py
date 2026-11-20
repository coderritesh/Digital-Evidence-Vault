"""Stage 3 - Metadata Extractor.

Reads EXIF data from a stored evidence file WITHOUT modifying it.
Findings are observations to support an investigator, not proof of tampering.
"""
from datetime import datetime
from pathlib import Path

from PIL import ExifTags, Image

EXIF_IFD = 0x8769
GPS_IFD = 0x8825
SKIP_TAGS = {EXIF_IFD, GPS_IFD}
EDITOR_WORDS = [
    "photoshop", "lightroom", "gimp", "snapseed", "canva", "picsart",
    "pixlr", "paint.net", "affinity", "facetune", "photoscape", "fotor",
]


def _to_text(value):
    """Turn any EXIF value into a short, readable string."""
    if isinstance(value, bytes):
        if len(value) > 64:
            return f"<{len(value)} bytes of binary data>"
        return value.decode(errors="replace").replace("\x00", "").strip()
    if isinstance(value, tuple):
        return ", ".join(_to_text(v) for v in value)
    try:
        if hasattr(value, "numerator"):  # Pillow's rational numbers
            return str(float(value))
    except (ZeroDivisionError, TypeError):
        return str(value)
    return str(value)


def _dms_to_decimal(dms, ref):
    try:
        d, m, s = (float(x) for x in dms)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    dec = d + m / 60 + s / 3600
    if str(ref).upper() in ("S", "W"):
        dec = -dec
    return round(dec, 6)


def _parse_date(text):
    try:
        return datetime.strptime(str(text).strip(), "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None


def extract(path):
    """Return {'basic', 'exif', 'gps', 'observations'} for the image at path."""
    path = Path(path)
    with Image.open(path) as img:  # read-only open; we never save
        basic = {
            "Format": img.format,
            "Width x Height": f"{img.width} x {img.height}",
            "Colour mode": img.mode,
            "File size (bytes)": path.stat().st_size,
        }
        exif = img.getexif()
        base = {k: v for k, v in exif.items() if k not in SKIP_TAGS}
        try:
            sub = dict(exif.get_ifd(EXIF_IFD))
        except Exception:
            sub = {}
        try:
            gps_raw = dict(exif.get_ifd(GPS_IFD))
        except Exception:
            gps_raw = {}

    merged = {}
    for tags in (base, sub):
        for k, v in tags.items():
            merged[ExifTags.TAGS.get(k, f"Tag {k}")] = _to_text(v)

    gps = None
    if gps_raw.get(2) and gps_raw.get(4):
        lat = _dms_to_decimal(gps_raw.get(2), gps_raw.get(1, "N"))
        lon = _dms_to_decimal(gps_raw.get(4), gps_raw.get(3, "E"))
        if lat is not None and lon is not None:
            gps = {
                "latitude": lat,
                "longitude": lon,
                "map_url": f"https://www.google.com/maps?q={lat},{lon}",
            }

    return {
        "basic": basic,
        "exif": merged,
        "gps": gps,
        "observations": _observations(merged, gps),
    }


def _observations(exif, gps):
    notes = []
    if not exif:
        notes.append(
            "No EXIF metadata found. Messaging apps, social media, screenshots and "
            "editing tools often remove it, and it can also be removed deliberately. "
            "On its own this does not prove tampering."
        )
        return notes

    software = exif.get("Software", "")
    if software:
        hit = [w for w in EDITOR_WORDS if w in software.lower()]
        if hit:
            notes.append(
                f"Software tag reads '{software}', which matches a known image editor. "
                "The file may have been saved by editing software."
            )
        else:
            notes.append(
                f"Software tag reads '{software}'. Phone and camera firmware also "
                "write this tag, so it is not suspicious by itself."
            )

    taken = _parse_date(exif.get("DateTimeOriginal"))
    changed = _parse_date(exif.get("DateTime"))
    if taken and changed and taken != changed:
        notes.append(
            f"Capture time ({taken}) differs from last-modified time ({changed}). "
            "The file was re-saved after it was taken. This can be normal "
            "(rotation, auto-processing) or a sign of editing."
        )
    if not exif.get("Make") and not exif.get("Model"):
        notes.append(
            "Camera make and model are missing even though other metadata exists."
        )
    if gps:
        notes.append(
            "GPS coordinates are present. Handle this report carefully because "
            "it reveals where the photo was taken."
        )
    if not notes:
        notes.append("No obvious inconsistencies found in the metadata fields checked.")
    return notes
