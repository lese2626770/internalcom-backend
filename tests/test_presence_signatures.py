"""
Tests for presence (heartbeat / list) and signature documents (create / list /
sign / final PDF / delete / access control).
"""
from __future__ import annotations

import base64
import io
import os
import time
import uuid

import pytest
import requests
from PIL import Image
from reportlab.pdfgen import canvas as rl_canvas
from pypdf import PdfReader

BASE_URL = os.environ.get(
    "REACT_APP_BACKEND_URL", "https://internal-comms-12.preview.emergentagent.com"
).rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@intracom.app"
ADMIN_PASSWORD = "Admin123!"
USER_EMAIL = "user@intracom.app"
USER_PASSWORD = "User123!"


# ---------------- Fixtures ----------------
def _login(email: str, password: str) -> requests.Session:
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"Login failed for {email}: {r.status_code} {r.text}"
    return s


@pytest.fixture(scope="module")
def admin_session():
    return _login(ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.fixture(scope="module")
def user_session():
    return _login(USER_EMAIL, USER_PASSWORD)


@pytest.fixture(scope="module")
def admin_me(admin_session):
    return admin_session.get(f"{API}/auth/me").json()


@pytest.fixture(scope="module")
def user_me(user_session):
    return user_session.get(f"{API}/auth/me").json()


@pytest.fixture(scope="module")
def third_user(admin_session):
    """A throwaway user used as a NON-participant for access-control tests."""
    email = f"test_thirdparty_{uuid.uuid4().hex[:6]}@intracom.app"
    r = admin_session.post(
        f"{API}/users",
        json={"email": email, "name": "Third Party", "password": "Passw0rd!", "role": "user"},
    )
    assert r.status_code == 200, r.text
    uid = r.json()["id"]
    third_sess = _login(email, "Passw0rd!")
    yield {"id": uid, "email": email, "session": third_sess}
    admin_session.delete(f"{API}/users/{uid}")


def _make_pdf_bytes(text: str = "Hello signature test") -> bytes:
    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf)
    c.drawString(100, 750, text)
    c.showPage()
    c.save()
    return buf.getvalue()


def _make_signature_png_b64() -> str:
    """Return a small non-empty PNG (a few drawn pixels) encoded as data URL."""
    img = Image.new("RGBA", (200, 80), (0, 0, 0, 0))
    pixels = img.load()
    for x in range(20, 180):
        pixels[x, 40] = (0, 0, 0, 255)
        pixels[x, 41] = (0, 0, 0, 255)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _upload_pdf(sess: requests.Session, text: str = "PDF content") -> str:
    pdf = _make_pdf_bytes(text)
    r = sess.post(
        f"{API}/files/upload",
        files={"file": ("doc.pdf", io.BytesIO(pdf), "application/pdf")},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ---------------- PRESENCE ----------------
class TestPresence:
    def test_heartbeat_returns_iso(self, admin_session):
        r = admin_session.post(f"{API}/presence/heartbeat")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True
        assert isinstance(data["last_seen_at"], str)
        assert "T" in data["last_seen_at"]  # ISO format

    def test_heartbeat_unauthenticated(self):
        r = requests.post(f"{API}/presence/heartbeat")
        assert r.status_code == 401

    def test_presence_list_reflects_heartbeat(self, admin_session, admin_me):
        admin_session.post(f"{API}/presence/heartbeat")
        r = admin_session.get(f"{API}/presence")
        assert r.status_code == 200
        items = r.json()
        assert isinstance(items, list) and len(items) > 0
        me = next((x for x in items if x["id"] == admin_me["id"]), None)
        assert me is not None
        assert me["online"] is True
        assert me["last_seen_at"] is not None
        # every entry must have the required shape
        for entry in items:
            assert set(entry.keys()) >= {"id", "online", "last_seen_at"}
            assert isinstance(entry["online"], bool)

    def test_users_endpoint_exposes_last_seen_at(self, admin_session, admin_me):
        admin_session.post(f"{API}/presence/heartbeat")
        r = admin_session.get(f"{API}/users")
        assert r.status_code == 200
        users = r.json()
        me = next((u for u in users if u["id"] == admin_me["id"]), None)
        assert me is not None
        assert "last_seen_at" in me
        assert me["last_seen_at"] is not None


# ---------------- SIGNATURE DOCUMENTS ----------------
class TestSignatureDocsHappyPath:
    @pytest.fixture(scope="class")
    def doc(self, admin_session, user_me):
        file_id = _upload_pdf(admin_session, "Original PDF body")
        r = admin_session.post(
            f"{API}/signature-docs",
            json={
                "title": "TEST_SignDoc",
                "file_id": file_id,
                "signers": [{"email": USER_EMAIL}],
                "message": "Please sign",
            },
        )
        assert r.status_code == 200, r.text
        d = r.json()
        return d

    def test_create_resolves_signer_user_id(self, doc, user_me):
        assert doc["status"] == "pending"
        assert doc["signed_file_id"] is None
        assert len(doc["signers"]) == 1
        signer = doc["signers"][0]
        assert signer["email"] == USER_EMAIL
        assert signer["user_id"] == user_me["id"]
        assert signer["status"] == "pending"

    def test_listing_to_sign_for_signer(self, user_session, doc):
        r = user_session.get(f"{API}/signature-docs", params={"filter": "to_sign"})
        assert r.status_code == 200
        ids = [d["id"] for d in r.json()]
        assert doc["id"] in ids

    def test_listing_sent_for_creator(self, admin_session, doc):
        r = admin_session.get(f"{API}/signature-docs", params={"filter": "sent"})
        assert r.status_code == 200
        ids = [d["id"] for d in r.json()]
        assert doc["id"] in ids

    def test_signer_signs_and_doc_completes(self, user_session, admin_session, doc):
        r = user_session.post(
            f"{API}/signature-docs/{doc['id']}/sign",
            json={"signature_image_b64": _make_signature_png_b64()},
        )
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["status"] == "completed"
        assert out["signed_file_id"] is not None
        assert out["signers"][0]["status"] == "signed"
        assert out["signers"][0]["signed_at"] is not None

        # signed PDF retrievable + parseable
        signed_id = out["signed_file_id"]
        r2 = admin_session.get(f"{API}/files/{signed_id}")
        assert r2.status_code == 200
        assert r2.headers["content-type"].startswith("application/pdf")
        reader = PdfReader(io.BytesIO(r2.content))
        assert len(reader.pages) >= 1
        # Original text preserved on a page
        all_text = "".join(p.extract_text() or "" for p in reader.pages)
        assert "Original PDF body" in all_text

    def test_completed_doc_in_completed_filter(self, admin_session, user_session, doc):
        for sess in (admin_session, user_session):
            r = sess.get(f"{API}/signature-docs", params={"filter": "completed"})
            assert r.status_code == 200
            ids = [d["id"] for d in r.json()]
            assert doc["id"] in ids


class TestSignatureDocsEdgeCases:
    def test_sign_twice_rejected(self, admin_session, user_session):
        file_id = _upload_pdf(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={
                "title": "TEST_SignTwice",
                "file_id": file_id,
                "signers": [
                    {"email": USER_EMAIL},
                    {"email": f"ghost_{uuid.uuid4().hex[:6]}@external-signer.com"},
                ],
            },
        )
        assert r.status_code == 200, r.text
        doc_id = r.json()["id"]
        # First sign should succeed (only one signer of two — still pending overall)
        r1 = user_session.post(
            f"{API}/signature-docs/{doc_id}/sign",
            json={"signature_image_b64": _make_signature_png_b64()},
        )
        assert r1.status_code == 200, r1.text
        assert r1.json()["status"] == "pending"  # ghost has not signed
        # Second sign attempt by same user should be rejected
        r2 = user_session.post(
            f"{API}/signature-docs/{doc_id}/sign",
            json={"signature_image_b64": _make_signature_png_b64()},
        )
        assert r2.status_code == 400
        # cleanup: cancel still-pending doc
        admin_session.delete(f"{API}/signature-docs/{doc_id}")

    def test_email_only_signer_created_with_null_user_id(self, admin_session):
        ghost_email = f"ghost_{uuid.uuid4().hex[:6]}@external-signer.com"
        file_id = _upload_pdf(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={
                "title": "TEST_EmailOnlySigner",
                "file_id": file_id,
                "signers": [{"email": ghost_email}],
            },
        )
        assert r.status_code == 200, r.text
        d = r.json()
        signer = d["signers"][0]
        assert signer["email"] == ghost_email
        assert signer["user_id"] is None
        assert signer["status"] == "pending"
        admin_session.delete(f"{API}/signature-docs/{d['id']}")

    def test_delete_pending_as_creator(self, admin_session):
        file_id = _upload_pdf(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={"title": "TEST_Delete", "file_id": file_id, "signers": [{"email": USER_EMAIL}]},
        )
        doc_id = r.json()["id"]
        rd = admin_session.delete(f"{API}/signature-docs/{doc_id}")
        assert rd.status_code == 200

    def test_delete_as_signer_forbidden(self, admin_session, user_session):
        file_id = _upload_pdf(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={"title": "TEST_DeleteSigner", "file_id": file_id, "signers": [{"email": USER_EMAIL}]},
        )
        doc_id = r.json()["id"]
        rd = user_session.delete(f"{API}/signature-docs/{doc_id}")
        assert rd.status_code == 403
        admin_session.delete(f"{API}/signature-docs/{doc_id}")

    def test_delete_completed_doc_rejected(self, admin_session, user_session):
        file_id = _upload_pdf(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={"title": "TEST_DeleteCompleted", "file_id": file_id, "signers": [{"email": USER_EMAIL}]},
        )
        doc_id = r.json()["id"]
        # fully sign
        r_sign = user_session.post(
            f"{API}/signature-docs/{doc_id}/sign",
            json={"signature_image_b64": _make_signature_png_b64()},
        )
        assert r_sign.status_code == 200
        assert r_sign.json()["status"] == "completed"
        rd = admin_session.delete(f"{API}/signature-docs/{doc_id}")
        assert rd.status_code == 400

    def test_access_control_non_participant(self, admin_session, third_user):
        file_id = _upload_pdf(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={"title": "TEST_AccessCtl", "file_id": file_id, "signers": [{"email": USER_EMAIL}]},
        )
        doc_id = r.json()["id"]
        # third user is neither creator nor signer
        r_get = third_user["session"].get(f"{API}/signature-docs/{doc_id}")
        assert r_get.status_code == 403
        admin_session.delete(f"{API}/signature-docs/{doc_id}")

    def test_non_signer_cannot_sign(self, admin_session, third_user):
        file_id = _upload_pdf(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={"title": "TEST_NoSign", "file_id": file_id, "signers": [{"email": USER_EMAIL}]},
        )
        doc_id = r.json()["id"]
        r_sign = third_user["session"].post(
            f"{API}/signature-docs/{doc_id}/sign",
            json={"signature_image_b64": _make_signature_png_b64()},
        )
        assert r_sign.status_code == 403
        admin_session.delete(f"{API}/signature-docs/{doc_id}")

    def test_create_with_non_pdf_rejected(self, admin_session):
        r_up = admin_session.post(
            f"{API}/files/upload",
            files={"file": ("note.txt", io.BytesIO(b"hi"), "text/plain")},
        )
        assert r_up.status_code == 200
        fid = r_up.json()["id"]
        r = admin_session.post(
            f"{API}/signature-docs",
            json={"title": "TEST_NonPDF", "file_id": fid, "signers": [{"email": USER_EMAIL}]},
        )
        assert r.status_code == 400

    def test_create_with_empty_signers_rejected(self, admin_session):
        file_id = _upload_pdf(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={"title": "TEST_NoSigners", "file_id": file_id, "signers": []},
        )
        # Pydantic 422 or business 400 both acceptable
        assert r.status_code in (400, 422)
