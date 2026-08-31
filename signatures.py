"""PDF signature stamping helpers — DocuSign-style.

Given the original PDF + a list of filled fields (with normalized coordinates),
this module:

1. Renders each field on the correct page at the correct position
   - signature / initial / mention → PNG image overlay (trimmed)
   - date / text                   → text in Helvetica
   - checkbox                      → a small frame + check mark
2. Appends an audit-trail page summarising who signed what, when, and from
   where (IP / user-agent).
"""
from __future__ import annotations

import base64
import io
import logging
from datetime import datetime, timezone
from typing import List, Optional

from PIL import Image
from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

logger = logging.getLogger(__name__)


def decode_signature_b64(b64: str) -> bytes:
    """Decode a base64 / data-URL PNG and return raw bytes."""
    if "," in b64:
        b64 = b64.split(",", 1)[1]
    return base64.b64decode(b64)


def _trim_image(img: Image.Image) -> Image.Image:
    """Crop transparent borders so the signature is tightly framed."""
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    bbox = img.getbbox()
    return img.crop(bbox) if bbox else img


def _norm_to_pdf(field: dict, page_w: float, page_h: float) -> tuple:
    """Convert normalized (top-left origin) coordinates to PDF points
    (bottom-left origin). Returns (x, y_bottom, w, h)."""
    x = field["x"] * page_w
    w = field["w"] * page_w
    h = field["h"] * page_h
    # PDF y is measured from the bottom; field y is measured from top of page.
    y_top_of_field_in_top_origin = field["y"] * page_h
    y_bottom = page_h - y_top_of_field_in_top_origin - h
    return x, y_bottom, w, h


def _draw_image_field(c: canvas.Canvas, png_bytes: bytes, x: float, y: float, w: float, h: float):
    try:
        img = _trim_image(Image.open(io.BytesIO(png_bytes)))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        iw, ih = img.size
        ratio = min(w / iw, h / ih) if iw and ih else 1.0
        sw, sh = iw * ratio, ih * ratio
        c.drawImage(
            ImageReader(buf),
            x + (w - sw) / 2,
            y + (h - sh) / 2,
            width=sw,
            height=sh,
            mask="auto",
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("Failed to draw image field: %s", e)


def _draw_text_field(c: canvas.Canvas, text: str, x: float, y: float, w: float, h: float, *, italic=False):
    text = (text or "").strip()
    if not text:
        return
    font_size = max(7, min(h * 0.55, 14))
    c.setFillColor(HexColor("#09090b"))
    c.setFont("Helvetica-Oblique" if italic else "Helvetica", font_size)
    # vertical centring of single-line text
    c.drawString(x + 2, y + (h - font_size) / 2 + 1, text[:200])


def _draw_checkbox(c: canvas.Canvas, checked: bool, x: float, y: float, w: float, h: float):
    side = min(w, h) * 0.7
    cx = x + (w - side) / 2
    cy = y + (h - side) / 2
    c.setStrokeColor(HexColor("#09090b"))
    c.setLineWidth(0.8)
    c.rect(cx, cy, side, side, stroke=1, fill=0)
    if checked:
        c.setLineWidth(1.4)
        # X mark
        c.line(cx + side * 0.15, cy + side * 0.15, cx + side * 0.85, cy + side * 0.85)
        c.line(cx + side * 0.15, cy + side * 0.85, cx + side * 0.85, cy + side * 0.15)


def _build_audit_page(audit_rows: List[dict], doc_title: str) -> bytes:
    """Build a single-page PDF summarising the signing events."""
    buf = io.BytesIO()
    page_w, page_h = A4
    c = canvas.Canvas(buf, pagesize=A4)

    # Header
    c.setFillColor(HexColor("#09090b"))
    c.setFont("Helvetica-Bold", 14)
    c.drawString(0.6 * inch, page_h - 0.7 * inch, "Signature audit trail")
    c.setFont("Helvetica", 9)
    c.setFillColor(HexColor("#52525b"))
    c.drawString(0.6 * inch, page_h - 0.92 * inch, f"Document: {doc_title}")
    c.drawString(0.6 * inch, page_h - 1.08 * inch, f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")

    # Divider
    c.setStrokeColor(HexColor("#d4d4d8"))
    c.setLineWidth(0.5)
    c.line(0.6 * inch, page_h - 1.25 * inch, page_w - 0.6 * inch, page_h - 1.25 * inch)

    # Rows
    y = page_h - 1.55 * inch
    row_h = 0.42 * inch
    for ev in audit_rows:
        if y < 1.0 * inch:
            break
        c.setFillColor(HexColor("#09090b"))
        c.setFont("Helvetica-Bold", 10)
        signer = ev.get("name") or ev.get("email") or "—"
        c.drawString(0.6 * inch, y, signer[:60])

        c.setFont("Helvetica", 9)
        c.setFillColor(HexColor("#52525b"))
        c.drawString(0.6 * inch, y - 0.16 * inch, (ev.get("email") or "")[:80])

        c.setFont("Helvetica", 8.5)
        c.setFillColor(HexColor("#27272a"))
        right_x = page_w - 0.6 * inch
        c.drawRightString(right_x, y, ev.get("signed_at", "")[:25])
        c.drawRightString(right_x, y - 0.16 * inch, f"IP {ev.get('ip','—')}")

        y -= row_h
        c.setStrokeColor(HexColor("#e4e4e7"))
        c.setLineWidth(0.3)
        c.line(0.6 * inch, y + 0.08 * inch, page_w - 0.6 * inch, y + 0.08 * inch)

    # Footer
    c.setFont("Helvetica-Oblique", 7.5)
    c.setFillColor(HexColor("#a1a1aa"))
    c.drawString(0.6 * inch, 0.55 * inch,
                 "Electronic signatures applied via Skadden Exchange. Each signer authenticated and confirmed acceptance of the document.")
    c.save()
    return buf.getvalue()


def build_signed_pdf(
    original_pdf_bytes: bytes,
    fields: List[dict],
    field_images: dict,
    audit_rows: List[dict],
    doc_title: str = "",
) -> bytes:
    """Stamp every filled field on the appropriate page, then append an audit page.

    - `fields` is the full list of FieldOut dicts (only `filled=True` ones get stamped).
    - `field_images` maps field_id -> raw PNG bytes (for signature/initial/mention).
    - `audit_rows` is a list of `{name, email, signed_at, ip}` dicts (one per signer).
    """
    reader = PdfReader(io.BytesIO(original_pdf_bytes))
    if not reader.pages:
        raise ValueError("Empty PDF — cannot stamp signatures.")

    # Group fields by page index
    by_page: dict = {}
    for f in fields:
        if not f.get("filled"):
            continue
        by_page.setdefault(int(f["page"]), []).append(f)

    writer = PdfWriter()
    for i, page in enumerate(reader.pages):
        mb = page.mediabox
        page_w = float(mb.width)
        page_h = float(mb.height)

        page_fields = by_page.get(i, [])
        if page_fields:
            overlay_buf = io.BytesIO()
            c = canvas.Canvas(overlay_buf, pagesize=(page_w, page_h))
            for f in page_fields:
                x, y, w, h = _norm_to_pdf(f, page_w, page_h)
                ftype = f.get("type")
                if ftype in ("signature", "initial", "mention"):
                    img = field_images.get(f["id"])
                    if img:
                        _draw_image_field(c, img, x, y, w, h)
                elif ftype in ("date", "text"):
                    val = f.get("value_text") or ""
                    _draw_text_field(c, val, x, y, w, h)
                elif ftype == "checkbox":
                    _draw_checkbox(c, bool(f.get("value_bool")), x, y, w, h)
            c.save()
            overlay_buf.seek(0)
            overlay_page = PdfReader(overlay_buf).pages[0]
            page.merge_page(overlay_page)
        writer.add_page(page)

    # Append audit page
    audit_pdf = _build_audit_page(audit_rows, doc_title)
    for p in PdfReader(io.BytesIO(audit_pdf)).pages:
        writer.add_page(p)

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()
