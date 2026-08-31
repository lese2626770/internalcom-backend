"""Tests for OTP register flow + N+1 folder endpoints regression."""
import os
import time
import uuid

import pytest
import requests
from pymongo import MongoClient

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://internal-comms-12.preview.emergentagent.com").rstrip("/")
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.environ.get("DB_NAME", "test_database")

ADMIN_EMAIL = os.environ.get("TEST_ADMIN_EMAIL", "admin@intracom.app")
ADMIN_PASSWORD = os.environ.get("TEST_ADMIN_PASSWORD", "Admin123!")

mongo = MongoClient(MONGO_URL)
db = mongo[DB_NAME]


# ---------- Helpers / fixtures ----------
@pytest.fixture(scope="session")
def admin_session():
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text}"
    return s


def _fresh_invite_code(admin: requests.Session) -> str:
    r = admin.post(f"{BASE_URL}/api/invite-codes")
    assert r.status_code == 200, r.text
    return r.json()["code"]


def _otp_from_db(pending_id: str) -> str:
    doc = db.pending_registrations.find_one({"id": pending_id})
    assert doc, f"pending_id {pending_id} not found in mongo"
    return doc["otp_code"]


def _unique_email():
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


# ---------- N+1 / folders regression (admin) ----------
class TestFolders:
    @pytest.mark.parametrize("folder", ["inbox", "sent", "drafts", "starred", "archive", "trash"])
    def test_folder_endpoint(self, admin_session, folder):
        if folder == "drafts":
            r = admin_session.get(f"{BASE_URL}/api/drafts")
        else:
            r = admin_session.get(f"{BASE_URL}/api/conversations", params={"folder": folder})
        assert r.status_code == 200, f"{folder} -> {r.status_code} {r.text}"
        data = r.json()
        assert isinstance(data, list)
        if folder not in ("drafts",) and data:
            sample = data[0]
            for key in ("id", "participants", "to", "cc", "bcc", "created_by", "unread_count"):
                assert key in sample, f"missing key {key} in conv: {sample.keys()}"

    def test_unread_count(self, admin_session):
        r = admin_session.get(f"{BASE_URL}/api/inbox/unread-count")
        assert r.status_code == 200, r.text
        data = r.json()
        assert "unread" in data and isinstance(data["unread"], int)


# ---------- OTP register flow ----------
class TestOtpRegister:
    def test_invalid_invite_code(self):
        r = requests.post(f"{BASE_URL}/api/auth/register/start", json={
            "email": _unique_email(),
            "name": "Bob",
            "password": "Secret123!",
            "invite_code": "FAKE-CODE",
        })
        assert r.status_code == 400
        assert "invitation" in r.json().get("detail", "").lower() or "invalid" in r.json().get("detail", "").lower()

    def test_existing_email(self, admin_session):
        code = _fresh_invite_code(admin_session)
        r = requests.post(f"{BASE_URL}/api/auth/register/start", json={
            "email": ADMIN_EMAIL,
            "name": "Bob",
            "password": "Secret123!",
            "invite_code": code,
        })
        assert r.status_code == 400
        assert "already" in r.json().get("detail", "").lower() or "exist" in r.json().get("detail", "").lower()

    def test_start_returns_pending(self, admin_session):
        code = _fresh_invite_code(admin_session)
        email = _unique_email()
        r = requests.post(f"{BASE_URL}/api/auth/register/start", json={
            "email": email,
            "name": "Alice",
            "password": "Secret123!",
            "invite_code": code,
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert "pending_id" in data
        assert data["email"] == email.lower()
        assert data["expires_in"] == 600
        assert "email_sent" in data
        # invite code must NOT be marked used yet
        inv = db.invite_codes.find_one({"code": code})
        assert inv["used"] == False  # noqa: E712
        # cleanup
        db.pending_registrations.delete_one({"id": data["pending_id"]})

    def test_wrong_otp_then_success(self, admin_session):
        code = _fresh_invite_code(admin_session)
        email = _unique_email()
        r = requests.post(f"{BASE_URL}/api/auth/register/start", json={
            "email": email, "name": "Carol", "password": "Secret123!", "invite_code": code,
        })
        assert r.status_code == 200, r.text
        pending_id = r.json()["pending_id"]

        # wrong code
        wr = requests.post(f"{BASE_URL}/api/auth/register/verify", json={
            "pending_id": pending_id, "code": "000000",
        })
        # avoid colliding with true code by chance (unlikely)
        true_code = _otp_from_db(pending_id)
        if true_code != "000000":
            assert wr.status_code == 400, wr.text
            assert "incorrect" in wr.json().get("detail", "").lower()
            doc = db.pending_registrations.find_one({"id": pending_id})
            assert doc["attempts"] >= 1

        # correct code -> user created, cookies set
        s = requests.Session()
        ok = s.post(f"{BASE_URL}/api/auth/register/verify", json={
            "pending_id": pending_id, "code": true_code,
        })
        assert ok.status_code == 200, ok.text
        user = ok.json()
        assert user["email"] == email.lower()
        assert user["role"] == "user"
        # cookies set
        assert s.cookies.get("access_token") or s.cookies.get("refresh_token")
        # /me works
        me = s.get(f"{BASE_URL}/api/auth/me")
        assert me.status_code == 200
        assert me.json()["email"] == email.lower()
        # invite is now used
        inv = db.invite_codes.find_one({"code": code})
        assert inv["used"] == True  # noqa: E712
        # pending deleted
        assert db.pending_registrations.find_one({"id": pending_id}) is None
        # cleanup test user
        db.users.delete_one({"email": email.lower()})

    def test_too_many_attempts_429(self, admin_session):
        code = _fresh_invite_code(admin_session)
        email = _unique_email()
        r = requests.post(f"{BASE_URL}/api/auth/register/start", json={
            "email": email, "name": "Dan", "password": "Secret123!", "invite_code": code,
        })
        pending_id = r.json()["pending_id"]
        true_code = _otp_from_db(pending_id)
        wrong = "999999" if true_code != "999999" else "111111"

        last_status = None
        for _ in range(5):
            wr = requests.post(f"{BASE_URL}/api/auth/register/verify", json={
                "pending_id": pending_id, "code": wrong,
            })
            last_status = wr.status_code
        # 5th call: pending had attempts=4 before, code wrong => 400, then deleted on next attempt with 429
        # Try once more to confirm pending was wiped
        extra = requests.post(f"{BASE_URL}/api/auth/register/verify", json={
            "pending_id": pending_id, "code": wrong,
        })
        # Either 429 "too many attempts" or 404 "request not found" (already deleted)
        assert extra.status_code in (404, 429), f"got {extra.status_code} {extra.text}"
        # pending should be gone
        assert db.pending_registrations.find_one({"id": pending_id}) is None

    def test_resend_cooldown(self, admin_session):
        code = _fresh_invite_code(admin_session)
        email = _unique_email()
        r = requests.post(f"{BASE_URL}/api/auth/register/start", json={
            "email": email, "name": "Eve", "password": "Secret123!", "invite_code": code,
        })
        pending_id = r.json()["pending_id"]
        # immediate resend → 429 cooldown
        rr = requests.post(f"{BASE_URL}/api/auth/register/resend-otp", json={"pending_id": pending_id})
        assert rr.status_code == 429
        assert "wait" in rr.json().get("detail", "").lower() or "patient" in rr.json().get("detail", "").lower()
        # cleanup
        db.pending_registrations.delete_one({"id": pending_id})

    def test_resend_invalidates_old_code(self, admin_session):
        code = _fresh_invite_code(admin_session)
        email = _unique_email()
        r = requests.post(f"{BASE_URL}/api/auth/register/start", json={
            "email": email, "name": "Frank", "password": "Secret123!", "invite_code": code,
        })
        pending_id = r.json()["pending_id"]
        old_code = _otp_from_db(pending_id)
        # bypass cooldown
        db.pending_registrations.update_one(
            {"id": pending_id},
            {"$set": {"last_sent_at": "2020-01-01T00:00:00+00:00"}},
        )
        rr = requests.post(f"{BASE_URL}/api/auth/register/resend-otp", json={"pending_id": pending_id})
        assert rr.status_code == 200, rr.text
        new_code = _otp_from_db(pending_id)
        assert new_code != old_code
        # old code must fail
        wr = requests.post(f"{BASE_URL}/api/auth/register/verify", json={
            "pending_id": pending_id, "code": old_code,
        })
        assert wr.status_code == 400
        # cleanup
        db.pending_registrations.delete_one({"id": pending_id})

    def test_legacy_register_endpoint_410(self, admin_session):
        code = _fresh_invite_code(admin_session)
        r = requests.post(f"{BASE_URL}/api/auth/register", json={
            "email": _unique_email(), "name": "Greg",
            "password": "Secret123!", "invite_code": code,
        })
        assert r.status_code == 410
        # cleanup invite (still unused)
        db.invite_codes.delete_one({"code": code})

    def test_expired_otp(self, admin_session):
        code = _fresh_invite_code(admin_session)
        email = _unique_email()
        r = requests.post(f"{BASE_URL}/api/auth/register/start", json={
            "email": email, "name": "Hank", "password": "Secret123!", "invite_code": code,
        })
        pending_id = r.json()["pending_id"]
        true_code = _otp_from_db(pending_id)
        # force expiry in past
        db.pending_registrations.update_one(
            {"id": pending_id}, {"$set": {"expires_at": "2020-01-01T00:00:00+00:00"}}
        )
        wr = requests.post(f"{BASE_URL}/api/auth/register/verify", json={
            "pending_id": pending_id, "code": true_code,
        })
        assert wr.status_code == 400
        assert "expir" in wr.json().get("detail", "").lower()
        assert db.pending_registrations.find_one({"id": pending_id}) is None
