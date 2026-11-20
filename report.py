"""Stage 5B - PDF Report Generator (ReportLab).

Builds a structured, read-only summary of one piece of evidence. The original
file is only read; images in the report are in-memory resized copies.
"""
import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (Image, KeepTogether, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

KEY_EXIF = ["Make", "Model", "LensModel", "DateTimeOriginal", "DateTime", "Software",
            "ExposureTime", "FNumber", "ISOSpeedRatings", "FocalLength", "Orientation"]
NAVY = colors.HexColor("#1b2a41")
LIGHT = colors.HexColor("#eef1f6")
LEVEL_COLOR = {"Low": "#1f7a5a", "Medium": "#b7791f", "High": "#b23a2e"}

_base = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=_base["Normal"], fontSize=9.5, leading=13)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, leading=10.5, textColor=colors.HexColor("#444444"))
MONO = ParagraphStyle("mono", parent=BODY, fontName="Courier", fontSize=7.6, leading=10)
H1 = ParagraphStyle("h1", parent=_base["Title"], fontSize=20, textColor=NAVY, alignment=0, spaceAfter=4)
H2 = ParagraphStyle("h2", parent=_base["Heading2"], fontSize=12.5, textColor=NAVY, spaceBefore=12, spaceAfter=5)
NOTICE = ParagraphStyle("notice", parent=BODY, backColor=colors.HexColor("#fff4e0"),
                        borderColor=colors.HexColor("#e8a33d"), borderWidth=0.8,
                        borderPadding=6, leading=12.5)


def _t(value):
    """Make text safe for ReportLab's built-in fonts and XML markup."""
    s = "" if value is None else str(value)
    return escape(s.encode("latin-1", "replace").decode("latin-1"))


def P(text, style=BODY):
    return Paragraph(_t(text), style)


def _cell(text, style=BODY, bold=False):
    t = _t(text)
    return Paragraph(f"<b>{t}</b>" if bold else t, style)


def kv_table(rows):
    data = [[_cell(k, BODY, True), _cell(v, BODY)] for k, v in rows]
    t = Table(data, colWidths=[4.2 * cm, 12.8 * cm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d0da")),
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def grid_table(header, rows, widths):
    data = [[_cell(h, SMALL, True) for h in header]]
    data += [[_cell(c, SMALL) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d0da")),
        ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    return t


def _picture(pil_img, max_w, max_h):
    img = pil_img.convert("RGB")
    img.thumbnail((1000, 1000))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=85)
    buf.seek(0)
    w, h = img.size
    ratio = min(max_w / w, max_h / h)
    return Image(buf, width=w * ratio, height=h * ratio)


def _footer(evidence_id, sha):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(2 * cm, 1.1 * cm,
                          f"Evidence #{evidence_id} | SHA-256 {sha[:16]}... | Advisory report, not final legal proof")
        canvas.drawRightString(A4[0] - 2 * cm, 1.1 * cm, f"Page {doc.page}")
        canvas.restoreState()
    return draw


def build_report(out_path, *, evidence, actor, integrity_ok, meta, analysis,
                 custody_entries, chain_ok, chain_message, chain_head):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story = [P("Digital Evidence Analysis Report", H1),
             P(f"Generated {now} by {actor}", SMALL), Spacer(1, 6),
             Paragraph(_t("ADVISORY REPORT. Error Level Analysis and the risk score are "
                          "indicators to guide a human investigator. They are not proof that "
                          "an image is genuine or manipulated and are not final legal proof."), NOTICE)]

    # 1. Evidence summary
    story += [P("1. Evidence summary", H2), kv_table([
        ("Evidence ID", evidence["id"]),
        ("Original file name", evidence["original_name"]),
        ("File size", f"{evidence['size_bytes']:,} bytes"),
        ("Stored in vault (UTC)", evidence["ingested_at"]),
        ("Integrity check now", "INTACT: file matches its recorded hash" if integrity_ok
         else "FAILED: file does NOT match its recorded hash"),
    ]), Spacer(1, 4), P("SHA-256", SMALL), Paragraph(_t(evidence["sha256"]), MONO)]
    try:
        with PILImage.open(evidence["stored_path"]) as im:
            story += [Spacer(1, 6), _picture(im, 9 * cm, 7 * cm),
                      P("Original image (resized copy for display; the stored file is unchanged)", SMALL)]
    except Exception:
        story.append(P("Preview could not be generated for this file.", SMALL))

    # 2. Metadata
    exif = meta["exif"]
    rows = [(k, v) for k in KEY_EXIF if (v := exif.get(k))]
    story += [P("2. Metadata (EXIF)", H2),
              kv_table(list(meta["basic"].items())), Spacer(1, 5)]
    if rows:
        story += [P(f"Key EXIF fields ({len(exif)} fields found in total):", SMALL), kv_table(rows)]
    else:
        story.append(P("No EXIF metadata was found in this file.", BODY))
    if meta["gps"]:
        g = meta["gps"]
        story += [Spacer(1, 5), kv_table([("GPS location", f"{g['latitude']}, {g['longitude']}"),
                  ("Privacy note", "Location data is sensitive. Share this report with care.")])]
    story += [Spacer(1, 5), P("Observations (advisory):", SMALL)]
    story += [P("- " + n, BODY) for n in meta["observations"]]

    # 3. Analysis
    level = analysis["level"]
    story += [P("3. Forensic analysis (advisory)", H2),
              Paragraph(f"Advisory risk score: <b>{analysis['score']} / 100</b> "
                        f"(<font color='{LEVEL_COLOR[level]}'><b>{level}</b></font> indicator)", BODY),
              Spacer(1, 5)]
    if analysis["factors"]:
        story.append(grid_table(["Factor", "Points"],
                                [(f, p) for f, p in analysis["factors"]], [14 * cm, 3 * cm]))
    else:
        story.append(P("No factors added points.", BODY))
    story += [Spacer(1, 6), KeepTogether([
        _picture(analysis["ela_image"], 9 * cm, 7 * cm),
        P("Error Level Analysis map (derived copy). Even brightness suggests a similar "
          "compression history; a bright patch unlike its surroundings merits a closer look.", SMALL)]),
        Spacer(1, 5), P("Limitations", SMALL)]
    story += [P("- " + item, SMALL) for item in analysis["limits"]]

    # 4. Chain of custody
    story += [P("4. Chain of custody", H2),
              Paragraph(_t(("LEDGER INTACT. " if chain_ok else "LEDGER TAMPERING DETECTED. ") + chain_message
                           + " Verification covers the whole ledger; entries below are for this evidence."),
                        BODY), Spacer(1, 3), P("Latest chain hash at time of report", SMALL),
              Paragraph(_t(chain_head), MONO), Spacer(1, 5)]
    rows = [(e["id"], e["timestamp"], e["actor"], e["action"], e["details"]) for e in custody_entries]
    story.append(grid_table(["#", "When (UTC)", "Who", "Action", "Details"], rows,
                            [1 * cm, 3.4 * cm, 2.6 * cm, 3.4 * cm, 6.6 * cm]))

    doc = SimpleDocTemplate(out_path, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=1.8 * cm, bottomMargin=2 * cm,
                            title=f"Evidence report #{evidence['id']}", author=actor)
    footer = _footer(evidence["id"], evidence["sha256"])
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
