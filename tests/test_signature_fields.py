"""Backend tests for the new DocuSign-style field-based signature flow.

Covers requirements (a)-(m) of the iteration 2 review request:
- POST /api/files/upload, /api/signature-docs with fields array
- Signer colours assignment, unknown signer rejection
- Submit with mixed field types and various rejection cases
- N+1 page output + audit page after all signers complete
- Extended /api/files/{id} access control for signers
- DELETE /api/signature-docs/{id} pending vs completed
"""
from __future__ import annotations

import base64
import io
import os
import uuid
from typing import List

import pytest
import requests
from pypdf import PdfReader, PdfWriter
from PIL import Image

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
assert BASE_URL, "REACT_APP_BACKEND_URL must be set"

ADMIN_EMAIL = "admin@intracom.app"
ADMIN_PASS = "Admin123!"
USER_EMAIL = "user@intracom.app"
USER_PASS = "User123!"


# ----------------------- Helpers / fixtures -----------------------
def _login(email: str, password: str) -> requests.Session:
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": password}, timeout=30)
    assert r.status_code == 200, f"login failed for {email}: {r.status_code} {r.text}"
    return s


@pytest.fixture(scope="module")
def admin_session() -> requests.Session:
    return _login(ADMIN_EMAIL, ADMIN_PASS)


@pytest.fixture(scope="module")
def user_session() -> requests.Session:
    return _login(USER_EMAIL, USER_PASS)


def _make_pdf_bytes(num_pages: int = 2) -> bytes:
    """Build a minimal valid PDF with N blank pages (A4)."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    for i in range(num_pages):
        c.setFont("Helvetica", 14)
        c.drawString(72, 750, f"TEST_PDF page {i + 1}")
        c.showPage()
    c.save()
    return buf.getvalue()


def _png_data_url() -> str:
    img = Image.new("RGBA", (160, 80), (0, 0, 0, 0))
    # draw a black line
    for x in range(20, 140):
        img.putpixel((x, 40), (0, 0, 0, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _upload_pdf(session: requests.Session, num_pages: int = 2) -> str:
    pdf_bytes = _make_pdf_bytes(num_pages)
    files = {"file": ("TEST_doc.pdf", pdf_bytes, "application/pdf")}
    r = session.post(f"{BASE_URL}/api/files/upload", files=files, timeout=30)
    assert r.status_code == 200, f"upload failed: {r.status_code} {r.text}"
    j = r.json()
    assert "id" in j
    return j["id"]


def _basic_fields(signer_email: str, page: int = 0) -> List[dict]:
    return [
        {"type": "signature", "page": page, "x": 0.1, "y": 0.7, "w": 0.3, "h": 0.08, "signer_email": signer_email, "required": True},
        {"type": "initial", "page": page, "x": 0.5, "y": 0.7, "w": 0.1, "h": 0.05, "signer_email": signer_email, "required": True},
        {"type": "date", "page": page, "x": 0.1, "y": 0.85, "w": 0.2, "h": 0.04, "signer_email": signer_email, "required": True},
        {"type": "text", "page": page, "x": 0.5, "y": 0.85, "w": 0.2, "h": 0.04, "signer_email": signer_email, "required": True},
        {"type": "checkbox", "page": page, "x": 0.8, "y": 0.85, "w": 0.04, "h": 0.04, "signer_email": signer_email, "required": True},
        {"type": "mention", "page": page, "x": 0.1, "y": 0.55, "w": 0.4, "h": 0.06, "signer_email": signer_email, "required": True},
    ]


def _values_for(doc: dict, signer_email: str) -> List[dict]:
    out: List[dict] = []
    for f in doc["fields"]:
        if f["signer_email"] != signer_email:
            continue
        t = f["type"]
        if t in ("signature", "initial", "mention"):
            out.append({"id": f["id"], "value_image_b64": _png_data_url()})
        elif t == "checkbox":
            out.append({"id": f["id"], "value_bool": True})
        else:  # date / text
            out.append({"id": f["id"], "value_text": "2026-01-15" if t == "date" else "Acknowledged"})
    return out


# ----------------------- a/b/d: create doc -----------------------
class TestCreateDoc:
    def test_upload_pdf_returns_id(self, user_session):
        fid = _upload_pdf(user_session)
        assert isinstance(fid, str) and len(fid) > 8

    def test_create_with_all_field_types_and_auto_ids_and_colors(self, user_session):
        fid = _upload_pdf(user_session)
        payload = {
            "title": "TEST_FieldsAllTypes",
            "file_id": fid,
            "signers": [
                {"email": USER_EMAIL, "name": "User"},
                {"email": ADMIN_EMAIL, "name": "Admin"},
            ],
            "fields": _basic_fields(USER_EMAIL) + _basic_fields(ADMIN_EMAIL),
            "message": "please sign",
        }
        r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
        assert r.status_code == 200, r.text
        doc = r.json()
        # auto-generated ids
        for f in doc["fields"]:
            assert f["id"] and isinstance(f["id"], str)
        # unique colors per signer (d)
        colors = [s.get("color") for s in doc["signers"]]
        assert all(colors), f"signers missing color: {doc['signers']}"
        assert len(set(colors)) == len(colors), f"colors not unique: {colors}"
        # cleanup
        user_session.delete(f"{BASE_URL}/api/signature-docs/{doc['id']}")

    # c
    def test_create_rejects_unknown_signer_email_field(self, user_session):
        fid = _upload_pdf(user_session)
        payload = {
            "title": "TEST_UnknownSigner",
            "file_id": fid,
            "signers": [{"email": USER_EMAIL}],
            "fields": [
                {"type": "signature", "page": 0, "x": 0.1, "y": 0.1, "w": 0.2, "h": 0.05,
                 "signer_email": "ghost@nowhere.app", "required": True},
            ],
        }
        r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
        assert r.status_code == 400, r.text


# ----------------------- e..i: submit endpoint -----------------------
@pytest.fixture()
def two_signer_doc(user_session):
    """Create a fresh 2-signer doc (user + admin) with full set of field types each."""
    fid = _upload_pdf(user_session, num_pages=2)
    payload = {
        "title": f"TEST_TwoSigner_{uuid.uuid4().hex[:6]}",
        "file_id": fid,
        "signers": [
            {"email": USER_EMAIL, "name": "User"},
            {"email": ADMIN_EMAIL, "name": "Admin"},
        ],
        "fields": _basic_fields(USER_EMAIL, page=0) + _basic_fields(ADMIN_EMAIL, page=1),
        "message": "two-signer test",
    }
    r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
    assert r.status_code == 200, r.text
    doc = r.json()
    yield doc
    # cleanup if still pending
    try:
        user_session.delete(f"{BASE_URL}/api/signature-docs/{doc['id']}")
    except Exception:
        pass


class TestSubmit:
    # e: full mixed submission
    def test_submit_all_field_types(self, user_session, two_signer_doc):
        doc = two_signer_doc
        values = _values_for(doc, USER_EMAIL)
        r = user_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit", json={"values": values}, timeout=60)
        assert r.status_code == 200, r.text
        updated = r.json()
        me = next(s for s in updated["signers"] if s["email"] == USER_EMAIL)
        assert me["status"] == "signed"
        assert me.get("signed_at")
        # status still pending because admin hasn't signed
        assert updated["status"] == "pending"
        # all my fields marked filled
        my_fields = [f for f in updated["fields"] if f["signer_email"] == USER_EMAIL]
        assert all(f["filled"] for f in my_fields)

    # f: rejects when required fields would remain empty
    def test_submit_rejects_missing_required_fields(self, user_session, two_signer_doc):
        doc = two_signer_doc
        # only provide ONE field value (signature) while 5 others required
        sig_field = next(f for f in doc["fields"] if f["signer_email"] == USER_EMAIL and f["type"] == "signature")
        payload = {"values": [{"id": sig_field["id"], "value_image_b64": _png_data_url()}]}
        r = user_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit", json=payload, timeout=30)
        assert r.status_code == 400, r.text
        assert "Required fields" in r.text or "required" in r.text.lower()

    # g: rejects non-signer (a third party)
    def test_submit_rejects_non_signer(self, user_session, admin_session):
        # doc with only USER as signer; admin tries to submit
        fid = _upload_pdf(user_session)
        payload = {
            "title": "TEST_NonSigner",
            "file_id": fid,
            "signers": [{"email": USER_EMAIL}],
            "fields": _basic_fields(USER_EMAIL),
        }
        r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
        assert r.status_code == 200, r.text
        doc = r.json()
        try:
            r = admin_session.post(
                f"{BASE_URL}/api/signature-docs/{doc['id']}/submit",
                json={"values": [{"id": doc["fields"][0]["id"], "value_image_b64": _png_data_url()}]},
                timeout=30,
            )
            assert r.status_code == 403, r.text
        finally:
            user_session.delete(f"{BASE_URL}/api/signature-docs/{doc['id']}")

    # i: rejects already-signed signer
    def test_submit_rejects_already_signed(self, user_session, two_signer_doc):
        doc = two_signer_doc
        values = _values_for(doc, USER_EMAIL)
        r = user_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit", json={"values": values}, timeout=60)
        assert r.status_code == 200
        # second time
        r2 = user_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit", json={"values": values}, timeout=30)
        assert r2.status_code == 400, r2.text

    # h: rejects when doc completed
    def test_submit_rejects_completed_doc(self, user_session, admin_session, two_signer_doc):
        doc = two_signer_doc
        # user signs
        r = user_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit",
                              json={"values": _values_for(doc, USER_EMAIL)}, timeout=60)
        assert r.status_code == 200
        # admin signs -> completed
        r = admin_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit",
                               json={"values": _values_for(doc, ADMIN_EMAIL)}, timeout=60)
        assert r.status_code == 200, r.text
        completed = r.json()
        assert completed["status"] == "completed"
        # third attempt: any signer trying to re-submit on a completed doc => 400
        r2 = user_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit",
                               json={"values": _values_for(doc, USER_EMAIL)}, timeout=30)
        assert r2.status_code == 400, r2.text


# ----------------------- j: full flow + N+1 audit page -----------------------
class TestSignedPdfAndAudit:
    def test_full_flow_produces_n_plus_1_page_pdf_with_audit(self, user_session, admin_session):
        fid = _upload_pdf(user_session, num_pages=2)
        payload = {
            "title": "TEST_AuditTrail",
            "file_id": fid,
            "signers": [
                {"email": USER_EMAIL, "name": "Test User"},
                {"email": ADMIN_EMAIL, "name": "Test Admin"},
            ],
            "fields": _basic_fields(USER_EMAIL, page=0) + _basic_fields(ADMIN_EMAIL, page=1),
        }
        r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
        assert r.status_code == 200, r.text
        doc = r.json()
        try:
            # both sign
            r1 = user_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit",
                                   json={"values": _values_for(doc, USER_EMAIL)}, timeout=60)
            assert r1.status_code == 200
            r2 = admin_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit",
                                    json={"values": _values_for(doc, ADMIN_EMAIL)}, timeout=60)
            assert r2.status_code == 200
            doc2 = r2.json()
            assert doc2["status"] == "completed"
            assert doc2.get("signed_file_id")

            # Download signed PDF
            rf = user_session.get(f"{BASE_URL}/api/files/{doc2['signed_file_id']}", timeout=30)
            assert rf.status_code == 200, rf.text
            content = rf.content
            reader = PdfReader(io.BytesIO(content))
            # Original 2 pages + 1 audit page = 3
            assert len(reader.pages) == 3, f"expected 3 pages, got {len(reader.pages)}"

            # Extract text from last page (audit) and look for name+email+IP
            last_text = reader.pages[2].extract_text() or ""
            assert "Test User" in last_text, f"audit page missing user name: {last_text!r}"
            assert USER_EMAIL in last_text
            assert ADMIN_EMAIL in last_text
            assert "Signature audit trail" in last_text
            assert "IP" in last_text
        finally:
            # completed -> won't delete
            pass


# ----------------------- k: extended file access control -----------------------
class TestFileAccess:
    def test_signer_can_download_original_and_signed_pdf(self, user_session, admin_session):
        """User uploads PDF (admin is non-uploader signer); admin must be able to GET the original file_id."""
        fid = _upload_pdf(user_session)
        payload = {
            "title": "TEST_FileAccess",
            "file_id": fid,
            "signers": [
                {"email": USER_EMAIL},
                {"email": ADMIN_EMAIL},
            ],
            "fields": _basic_fields(USER_EMAIL) + _basic_fields(ADMIN_EMAIL, page=0),
        }
        r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
        assert r.status_code == 200, r.text
        doc = r.json()

        # As admin (signer, not uploader, no conversation): must succeed
        rf = admin_session.get(f"{BASE_URL}/api/files/{fid}", timeout=30)
        assert rf.status_code == 200, f"signer should be allowed to download original: {rf.status_code} {rf.text[:200]}"
        # Cleanup
        user_session.delete(f"{BASE_URL}/api/signature-docs/{doc['id']}")

    def test_non_signer_cannot_download(self, user_session, admin_session):
        """A random third party with no relationship to the file should get 403."""
        # Create a temporary 3rd user via admin
        unique = uuid.uuid4().hex[:6]
        new_email = f"test_outsider_{unique}@intracom.app"
        ru = admin_session.post(f"{BASE_URL}/api/users",
                                json={"email": new_email, "name": "Outsider", "password": "Outsider123!", "role": "user"},
                                timeout=30)
        if ru.status_code not in (200, 201):
            pytest.skip(f"cannot provision outsider user: {ru.status_code} {ru.text}")
        try:
            outsider = _login(new_email, "Outsider123!")
            fid = _upload_pdf(user_session)
            # user creates doc with USER only as signer
            payload = {
                "title": "TEST_NoAccess",
                "file_id": fid,
                "signers": [{"email": USER_EMAIL}],
                "fields": _basic_fields(USER_EMAIL),
            }
            r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
            assert r.status_code == 200
            doc = r.json()
            try:
                rf = outsider.get(f"{BASE_URL}/api/files/{fid}", timeout=30)
                assert rf.status_code in (403, 404), f"outsider unexpectedly got {rf.status_code}"
            finally:
                user_session.delete(f"{BASE_URL}/api/signature-docs/{doc['id']}")
        finally:
            # delete outsider user
            uid_resp = admin_session.get(f"{BASE_URL}/api/users", timeout=30)
            if uid_resp.status_code == 200:
                for u in uid_resp.json():
                    if u.get("email") == new_email:
                        admin_session.delete(f"{BASE_URL}/api/users/{u['id']}")
                        break


# ----------------------- l: field-type value validation -----------------------
class TestValueTypeValidation:
    def test_image_field_without_image_does_not_mark_filled(self, user_session):
        """If user submits an image field with only value_text, it must NOT count as filled
        and the submission must be rejected for missing required field (or yield a 400)."""
        fid = _upload_pdf(user_session)
        payload = {
            "title": "TEST_TypeValid",
            "file_id": fid,
            "signers": [{"email": USER_EMAIL}],
            "fields": [
                {"type": "signature", "page": 0, "x": 0.1, "y": 0.1, "w": 0.2, "h": 0.05,
                 "signer_email": USER_EMAIL, "required": True},
            ],
        }
        r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
        assert r.status_code == 200, r.text
        doc = r.json()
        try:
            r2 = user_session.post(
                f"{BASE_URL}/api/signature-docs/{doc['id']}/submit",
                json={"values": [{"id": doc["fields"][0]["id"], "value_text": "fake signature"}]},
                timeout=30,
            )
            # Either "No matching fields" (400) or "Required fields" (400)
            assert r2.status_code == 400, r2.text
        finally:
            user_session.delete(f"{BASE_URL}/api/signature-docs/{doc['id']}")


# ----------------------- m: delete endpoint -----------------------
class TestDelete:
    def test_delete_pending_as_creator_returns_200(self, user_session):
        fid = _upload_pdf(user_session)
        payload = {
            "title": "TEST_DeletePending",
            "file_id": fid,
            "signers": [{"email": USER_EMAIL}],
            "fields": _basic_fields(USER_EMAIL),
        }
        r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
        assert r.status_code == 200
        doc = r.json()
        r = user_session.delete(f"{BASE_URL}/api/signature-docs/{doc['id']}", timeout=30)
        assert r.status_code == 200, r.text

    def test_delete_completed_returns_400(self, user_session):
        # Create a single-signer doc and fully sign it -> completed
        fid = _upload_pdf(user_session)
        payload = {
            "title": "TEST_DeleteCompleted",
            "file_id": fid,
            "signers": [{"email": USER_EMAIL}],
            "fields": _basic_fields(USER_EMAIL),
        }
        r = user_session.post(f"{BASE_URL}/api/signature-docs", json=payload, timeout=30)
        assert r.status_code == 200
        doc = r.json()
        r = user_session.post(f"{BASE_URL}/api/signature-docs/{doc['id']}/submit",
                              json={"values": _values_for(doc, USER_EMAIL)}, timeout=60)
        assert r.status_code == 200
        assert r.json()["status"] == "completed"
        # Now try to delete
        r = user_session.delete(f"{BASE_URL}/api/signature-docs/{doc['id']}", timeout=30)
        assert r.status_code == 400, r.text
