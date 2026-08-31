"""Tests for new 'subject' field on messages + conversation preview behaviour."""
import os
import io
import uuid

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = os.environ.get("TEST_ADMIN_EMAIL", "admin@intracom.app")
ADMIN_PASSWORD = os.environ.get("TEST_ADMIN_PASSWORD", "Admin123!")
USER_EMAIL = os.environ.get("TEST_USER_EMAIL", "user@intracom.app")
USER_PASSWORD = os.environ.get("TEST_USER_PASSWORD", "User123!")


@pytest.fixture(scope="module")
def admin_session():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return s


@pytest.fixture(scope="module")
def user_me(admin_session):
    users = admin_session.get(f"{API}/users").json()
    return next(u for u in users if u["email"] == USER_EMAIL)


@pytest.fixture(scope="module")
def conv(admin_session, user_me):
    r = admin_session.post(f"{API}/conversations", json={
        "type": "direct", "participant_ids": [user_me["id"]]
    })
    assert r.status_code == 200, r.text
    return r.json()


class TestMessageSubject:
    def test_send_with_subject(self, admin_session, conv):
        r = admin_session.post(
            f"{API}/conversations/{conv['id']}/messages",
            json={"content": "Hello", "subject": "Test subject"},
        )
        assert r.status_code == 200, r.text
        msg = r.json()
        assert msg["subject"] == "Test subject"
        assert msg["content"] == "Hello"
        assert msg["sender_email"] == ADMIN_EMAIL
        # Verify persistence via GET
        msgs = admin_session.get(f"{API}/conversations/{conv['id']}/messages").json()
        match = next(m for m in msgs if m["id"] == msg["id"])
        assert match["subject"] == "Test subject"
        assert match["sender_email"] == ADMIN_EMAIL

    def test_send_without_subject(self, admin_session, conv):
        r = admin_session.post(
            f"{API}/conversations/{conv['id']}/messages",
            json={"content": "no subject here"},
        )
        assert r.status_code == 200
        msg = r.json()
        assert msg.get("subject", "") == ""
        assert msg["content"] == "no subject here"

    def test_subject_max_length_trimmed(self, admin_session, conv):
        long = "S" * 300
        r = admin_session.post(
            f"{API}/conversations/{conv['id']}/messages",
            json={"content": "hi", "subject": long},
        )
        assert r.status_code == 200
        assert len(r.json()["subject"]) == 200

    def test_conversation_preview_uses_subject(self, admin_session, conv):
        # Send a message with distinctive subject
        unique = f"PREVIEW_{uuid.uuid4().hex[:6]}"
        r = admin_session.post(
            f"{API}/conversations/{conv['id']}/messages",
            json={"content": "body content here", "subject": unique},
        )
        assert r.status_code == 200
        # list conversations
        convs = admin_session.get(f"{API}/conversations").json()
        c = next(x for x in convs if x["id"] == conv["id"])
        assert c["last_message_preview"] == unique

    def test_conversation_preview_falls_back_to_content(self, admin_session, user_me):
        # New conv to avoid prior subject contamination
        # create a brand-new group conv just for fallback testing
        # Actually we need the latest message to have no subject.
        # Send a message with no subject and verify preview equals content
        r = admin_session.post(f"{API}/conversations", json={
            "type": "group", "name": f"TEST_fallback_{uuid.uuid4().hex[:4]}",
            "participant_ids": [user_me["id"]],
        })
        assert r.status_code == 200
        cid = r.json()["id"]
        admin_session.post(f"{API}/conversations/{cid}/messages",
                           json={"content": "fallback body text"})
        convs = admin_session.get(f"{API}/conversations").json()
        c = next(x for x in convs if x["id"] == cid)
        assert c["last_message_preview"] == "fallback body text"

    def test_conversation_preview_falls_back_to_attachment_label(self, admin_session, user_me):
        # upload a file
        png = bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c63000100000005000100"
            "0d0a2db40000000049454e44ae426082"
        )
        up = admin_session.post(
            f"{API}/files/upload",
            files={"file": ("p.png", io.BytesIO(png), "image/png")},
        )
        assert up.status_code == 200
        fid = up.json()["id"]
        # new conv to isolate
        r = admin_session.post(f"{API}/conversations", json={
            "type": "group", "name": f"TEST_att_{uuid.uuid4().hex[:4]}",
            "participant_ids": [user_me["id"]],
        })
        cid = r.json()["id"]
        admin_session.post(
            f"{API}/conversations/{cid}/messages",
            json={"content": "", "subject": "", "attachment_ids": [fid]},
        )
        convs = admin_session.get(f"{API}/conversations").json()
        c = next(x for x in convs if x["id"] == cid)
        assert "📎" in (c["last_message_preview"] or "")
        assert "1" in c["last_message_preview"]
