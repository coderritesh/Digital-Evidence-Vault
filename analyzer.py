"""Stage 5A - Image Analyzer: Error Level Analysis (ELA) + advisory risk score.

IMPORTANT: ELA and the score are advisory indicators. They can be wrong in both
directions and must never be presented as final legal proof.
The stored original is only read; all processing happens on in-memory copies.
"""
import io

import numpy as np
from PIL import Image, ImageChops

import metadata

RESAVE_QUALITY = 90
BLOCK = 16


def _clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def run_ela(path):
    """Re-save the image as JPEG and measure how much each pixel changes."""
    with Image.open(path) as img:
        fmt = img.format
        original = img.convert("RGB")

    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=RESAVE_QUALITY)
    buf.seek(0)
    resaved = Image.open(buf).convert("RGB")

    diff = ImageChops.difference(original, resaved)
    d = np.asarray(diff).max(axis=2)  # biggest change across colour channels

    peak = int(d.max())
    scale = 255.0 / peak if peak > 0 else 1.0
    ela_img = Image.fromarray((d.astype(np.float32) * scale).clip(0, 255).astype(np.uint8))

    h, w = d.shape
    hb, wb = h // BLOCK, w // BLOCK
    if hb < 4 or wb < 4:
        return {"format": fmt, "ela_image": ela_img, "mean": float(d.mean()),
                "cv": None, "hotspot_ratio": None}

    blocks = d[: hb * BLOCK, : wb * BLOCK].astype(np.float32)
    blocks = blocks.reshape(hb, BLOCK, wb, BLOCK).mean(axis=(1, 3))
    m, s = float(blocks.mean()), float(blocks.std())
    cv = s / (m + 1e-6)
    hotspot = float((blocks > m + 3 * s).mean()) if s > 0 else 0.0
    return {"format": fmt, "ela_image": ela_img, "mean": float(d.mean()),
            "cv": cv, "hotspot_ratio": hotspot}


def analyze(path, exif):
    """Return ELA image plus an advisory risk score with every contributing factor."""
    ela = run_ela(path)
    factors = []  # (description, points)
    limits = []

    is_jpeg = ela["format"] == "JPEG"
    if not is_jpeg:
        limits.append(
            f"File format is {ela['format']}. ELA is designed for JPEG files, so ELA "
            "results are shown for viewing only and are NOT used in the score."
        )
    elif ela["cv"] is None:
        limits.append("Image is too small for block analysis, so ELA is not scored.")
    else:
        p1 = _clamp((ela["cv"] - 0.6) / 0.9) * 30
        factors.append((f"Unevenness of error levels across the image (value {ela['cv']:.2f})", round(p1)))
        p2 = _clamp((ela["hotspot_ratio"] - 0.005) / 0.035) * 30
        factors.append((f"Share of unusually bright blocks ({ela['hotspot_ratio']*100:.1f}% of image)", round(p2)))

    software = exif.get("Software", "")
    if software and any(w in software.lower() for w in metadata.EDITOR_WORDS):
        factors.append((f"Software tag matches a known image editor ('{software}')", 25))
    taken = metadata._parse_date(exif.get("DateTimeOriginal"))
    changed = metadata._parse_date(exif.get("DateTime"))
    if taken and changed and taken != changed:
        factors.append(("Capture time differs from last-modified time", 10))
    if not exif:
        factors.append(("No EXIF metadata present (often removed by apps, so weak evidence)", 5))

    score = int(min(100, sum(p for _, p in factors)))
    level = "Low" if score < 30 else "Medium" if score < 60 else "High"

    limits += [
        "Heavily compressed or re-shared images (for example via WhatsApp) can look "
        "'edited' to ELA even when they are not.",
        "Skilled edits, or edits followed by re-saving, can hide from ELA entirely.",
        "Sharp edges and high-contrast areas are naturally bright in ELA.",
        "Score weights are heuristic and not statistically validated.",
    ]
    return {"ela_image": ela["ela_image"], "ela": ela, "factors": factors,
            "score": score, "level": level, "limits": limits}
