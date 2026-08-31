"""
Tests for the live screen capture endpoint `/api/presence/screen`, with focus
on the hash-based de-duplication path (a.k.a. the "touch" mode).

Goal of the optimization: when the user is staring at the exact same screen,
the client computes a fast hash of the JPEG dataUrl and ships only `{ hash,
path, touch: true }` instead of 30-150 KB of base64. The server then only
refreshes `captured_at` + `expires_at` and leaves the heavy image bytes
untouched.

If the server's stored hash does not match (TTL expired, doc lost), the
server replies 409 `{ resend: true }` so the client falls back to a full
upload on the next tick.
"""
from __future__ import annotations

import base64
import os

import pytest
import requests

BASE_URL = os.environ.get(
    "REACT_APP_BACKEND_URL", "https://internal-comms-12.preview.emergentagent.com"
).rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@intracom.app"
ADMIN_PASSWORD = "Admin123!"
USER_EMAIL = "user@intracom.app"
USER_PASSWORD = "User123!"


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


def _fake_image(payload: bytes = b"X" * 1024) -> str:
    return "data:image/jpeg;base64," + base64.b64encode(payload).decode()


def test_full_upload_stores_image_and_hash(user_session):
    r = user_session.post(
        f"{API}/presence/screen",
        json={"image": _fake_image(b"a" * 512), "hash": "abc123", "path": "/app/inbox"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["touched"] is False
    assert body.get("captured_at")


def test_touch_with_matching_hash_renews_ttl(user_session):
    # 1) Seed with a known frame
    img = _fake_image(b"b" * 600)
    r1 = user_session.post(
        f"{API}/presence/screen",
        json={"image": img, "hash": "match-hash", "path": "/app/inbox"},
    )
    assert r1.status_code == 200
    first_at = r1.json()["captured_at"]

    # 2) Touch with the matching hash → no image needed
    r2 = user_session.post(
        f"{API}/presence/screen",
        json={"hash": "match-hash", "touch": True, "path": "/app/inbox"},
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["touched"] is True
    # captured_at must move forward (TTL renewed)
    assert body["captured_at"] >= first_at


def test_touch_with_mismatching_hash_returns_409_resend(user_session):
    # Seed with a frame whose hash is "seed-hash"
    user_session.post(
        f"{API}/presence/screen",
        json={"image": _fake_image(b"c" * 700), "hash": "seed-hash", "path": "/app/inbox"},
    )
    # Touch with a different hash → server tells client to resend full
    r = user_session.post(
        f"{API}/presence/screen",
        json={"hash": "different-hash", "touch": True, "path": "/app/inbox"},
    )
    assert r.status_code == 409, r.text
    assert r.json() == {"resend": True}


def test_touch_without_hash_is_rejected(user_session):
    r = user_session.post(
        f"{API}/presence/screen",
        json={"touch": True, "path": "/app/inbox"},
    )
    assert r.status_code == 400, r.text


def test_full_upload_without_hash_still_works(user_session):
    """Hash is optional on full uploads — the server stores `null` and later
    touches will hit the mismatch path until a new full upload provides one."""
    r = user_session.post(
        f"{API}/presence/screen",
        json={"image": _fake_image(b"d" * 400), "path": "/app/inbox"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["touched"] is False


def test_admin_reads_freshest_capture(admin_session, user_session):
    """End-to-end: admin sees user's latest capture after a touch sequence."""
    me = user_session.get(f"{API}/auth/me").json()
    uid = me["id"]
    # Full upload
    user_session.post(
        f"{API}/presence/screen",
        json={"image": _fake_image(b"hello-admin"), "hash": "hash-A", "path": "/app/inbox"},
    )
    # Several touches with same hash — server should keep returning OK
    for _ in range(3):
        r = user_session.post(
            f"{API}/presence/screen",
            json={"hash": "hash-A", "touch": True, "path": "/app/inbox"},
        )
        assert r.status_code == 200
        assert r.json()["touched"] is True
    # Admin pulls the screen
    r = admin_session.get(f"{API}/admin/users/{uid}/screen")
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["user_id"] == uid
    assert doc["image_b64"].startswith("data:image/jpeg;base64,")
    assert doc["path"] == "/app/inbox"


def test_image_payload_size_guard(user_session):
    """Payloads over the 600 KB limit must be rejected with 413."""
    huge = "data:image/jpeg;base64," + ("A" * 700_000)
    r = user_session.post(
        f"{API}/presence/screen",
        json={"image": huge, "hash": "x", "path": "/app/inbox"},
    )
    assert r.status_code == 413
