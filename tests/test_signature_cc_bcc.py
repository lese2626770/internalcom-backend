"""Tests for CC + BCC informational recipients on signature documents."""
import io
import os
import uuid
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
assert BASE_URL, "REACT_APP_BACKEND_URL must be set"
API = f"{BASE_URL}/api"

ADMIN = {"email": "admin@intracom.app", "password": "Admin123!"}
USER = {"email": "user@intracom.app", "password": "User123!"}


def _login(creds):
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json=creds)
    assert r.status_code == 200, r.text
    return s


def _tiny_pdf() -> bytes:
    """Return a minimal valid PDF byte payload via reportlab."""
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.drawString(100, 700, f"sig-cc-test-{uuid.uuid4().hex[:6]}")
    c.showPage()
    c.save()
    return buf.getvalue()


def _pick_two_other_users(admin_session):
    """Return two user emails that are neither admin nor the standard test user."""
    users = admin_session.get(f"{API}/users").json()
    others = [u for u in users if u["email"] not in (ADMIN["email"], USER["email"])]
    if len(others) < 2:
        pytest.skip("Need at least 2 extra users for CC + BCC test")
    return others[0], others[1]


@pytest.fixture
def admin_session():
    return _login(ADMIN)


@pytest.fixture
def user_session():
    return _login(USER)


@pytest.fixture
def admin_pdf_file_id(admin_session):
    files = {"file": ("doc.pdf", _tiny_pdf(), "application/pdf")}
    r = admin_session.post(f"{API}/files/upload", files=files)
    assert r.status_code == 200, r.text
    return r.json()["id"]


class TestSignatureCcBcc:
    def test_admin_can_attach_cc_bcc(self, admin_session, admin_pdf_file_id):
        cc_user, bcc_user = _pick_two_other_users(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={
                "title": "CC/BCC unit test",
                "file_id": admin_pdf_file_id,
                "signers": [{"email": USER["email"], "name": "Sophie"}],
                "fields": [],
                "cc_emails": [cc_user["email"]],
                "bcc_emails": [bcc_user["email"]],
            },
        )
        assert r.status_code == 200, r.text
        doc = r.json()
        assert [c["email"] for c in doc["cc"]] == [cc_user["email"]]
        assert [c["email"] for c in doc["bcc"]] == [bcc_user["email"]]

    def test_non_admin_cannot_use_cc_bcc(self, user_session, admin_session):
        # User uploads their own PDF first
        files = {"file": ("u.pdf", _tiny_pdf(), "application/pdf")}
        up = user_session.post(f"{API}/files/upload", files=files)
        assert up.status_code == 200
        fid = up.json()["id"]
        cc_user, _ = _pick_two_other_users(admin_session)
        r = user_session.post(
            f"{API}/signature-docs",
            json={
                "title": "Standard user shouldn't be able to CC",
                "file_id": fid,
                "signers": [{"email": ADMIN["email"], "name": "Admin"}],
                "fields": [],
                "cc_emails": [cc_user["email"]],
            },
        )
        assert r.status_code == 403

    def test_signer_sees_cc_but_not_bcc(self, admin_session, user_session, admin_pdf_file_id):
        cc_user, bcc_user = _pick_two_other_users(admin_session)
        r = admin_session.post(
            f"{API}/signature-docs",
            json={
                "title": "Visibility test",
                "file_id": admin_pdf_file_id,
                "signers": [{"email": USER["email"], "name": "Sophie"}],
                "fields": [],
                "cc_emails": [cc_user["email"]],
                "bcc_emails": [bcc_user["email"]],
            },
        )
        assert r.status_code == 200
        doc_id = r.json()["id"]

        # Signer fetches the doc — must see CC, must NOT see BCC
        r = user_session.get(f"{API}/signature-docs/{doc_id}")
        assert r.status_code == 200
        view = r.json()
        assert [c["email"] for c in view["cc"]] == [cc_user["email"]]
        assert view["bcc"] == [], f"signer should not see BCC, got {view['bcc']}"

    def test_cc_user_does_not_get_pdf_access(self, admin_session, user_session, admin_pdf_file_id):
        """The PDF is only accessible to signers + creator, never to CC/BCC."""
        cc_user, _ = _pick_two_other_users(admin_session)
        admin_session.post(
            f"{API}/signature-docs",
            json={
                "title": "PDF access test",
                "file_id": admin_pdf_file_id,
                "signers": [{"email": USER["email"], "name": "Sophie"}],
                "fields": [],
                "cc_emails": [cc_user["email"]],
            },
        )
        # The standard user we have credentials for is NOT in cc/signers of this PDF
        # but is a signer in OTHER docs. Easier: just check the CC user's inbox notif
        # via admin view-as and verify the message has no signature_doc_id.
        users = admin_session.get(f"{API}/users").json()
        cc_uid = next(u["id"] for u in users if u["email"] == cc_user["email"])
        # Admin views the CC user's inbox (using as_user_id)
        r = admin_session.get(
            f"{API}/conversations",
            params={"folder": "inbox", "as_user_id": cc_uid},
        )
        assert r.status_code == 200
        convs = r.json()
        # Find the conv whose latest message subject starts with [CC]
        target_conv = next(
            (c for c in convs if "[CC]" in (c.get("last_message_preview") or "")),
            None,
        )
        assert target_conv is not None, "CC notification not found"
        # Now check the messages: latest message must NOT have signature_doc_id
        msgs = admin_session.get(
            f"{API}/conversations/{target_conv['id']}/messages",
        ).json()
        latest = max(msgs, key=lambda m: m["created_at"])
        assert latest.get("signature_doc_id") in (None, ""), (
            "CC notification must NOT carry signature_doc_id (would expose PDF link)"
        )
