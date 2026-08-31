"""End-to-end tests for the per-message read-receipt tracker."""
import os
import uuid
import time
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


@pytest.fixture
def admin_session():
    return _login(ADMIN)


@pytest.fixture
def user_session():
    return _login(USER)


class TestReadReceipts:
    def test_message_initially_has_empty_read_by(self, admin_session):
        """A freshly-sent message has read_by == [] for the sender."""
        r = admin_session.post(f"{API}/conversations", json={"to_emails": [USER["email"]]})
        assert r.status_code == 200, r.text
        conv_id = r.json()["id"]

        r = admin_session.post(
            f"{API}/conversations/{conv_id}/messages",
            json={"content": f"rr-test-{uuid.uuid4().hex[:6]}"},
        )
        assert r.status_code == 200, r.text
        msg = r.json()
        assert "read_by" in msg
        assert msg["read_by"] == []

    def test_recipient_marking_read_creates_receipt(self, admin_session, user_session):
        """When the recipient marks the conversation read, the sender sees
        a populated read_by array with name/email/timestamp."""
        # Admin creates conv + sends message to user
        r = admin_session.post(f"{API}/conversations", json={"to_emails": [USER["email"]]})
        conv_id = r.json()["id"]
        marker = f"rr-receipt-{uuid.uuid4().hex[:6]}"
        r = admin_session.post(
            f"{API}/conversations/{conv_id}/messages",
            json={"content": marker},
        )
        msg_id = r.json()["id"]
        assert r.json()["read_by"] == []

        # User opens conversation -> marks read
        r = user_session.post(f"{API}/conversations/{conv_id}/read")
        assert r.status_code == 200, r.text

        # Admin re-fetches the messages
        r = admin_session.get(f"{API}/conversations/{conv_id}/messages")
        assert r.status_code == 200
        msgs = r.json()
        target = next((m for m in msgs if m["id"] == msg_id), None)
        assert target is not None, "message disappeared"
        assert len(target["read_by"]) == 1, target["read_by"]
        receipt = target["read_by"][0]
        assert receipt["email"] == USER["email"]
        assert receipt["name"]  # name was hydrated
        assert receipt["at"]
        assert receipt["user_id"]

    def test_sender_is_excluded_from_read_by(self, admin_session, user_session):
        """Even though the backend marks the sender as read on send, the
        serialized read_by list must NOT include the sender themselves."""
        r = admin_session.post(f"{API}/conversations", json={"to_emails": [USER["email"]]})
        conv_id = r.json()["id"]
        r = admin_session.post(
            f"{API}/conversations/{conv_id}/messages",
            json={"content": "sender-exclusion-test"},
        )
        msg_id = r.json()["id"]
        user_session.post(f"{API}/conversations/{conv_id}/read")

        msgs = admin_session.get(f"{API}/conversations/{conv_id}/messages").json()
        target = next(m for m in msgs if m["id"] == msg_id)
        sender_ids = [r["user_id"] for r in target["read_by"]]
        assert target["sender_id"] not in sender_ids

    def test_read_receipt_is_idempotent(self, admin_session, user_session):
        """Marking read multiple times must not duplicate the receipt."""
        r = admin_session.post(f"{API}/conversations", json={"to_emails": [USER["email"]]})
        conv_id = r.json()["id"]
        r = admin_session.post(
            f"{API}/conversations/{conv_id}/messages",
            json={"content": "idempotency-test"},
        )
        msg_id = r.json()["id"]

        for _ in range(3):
            user_session.post(f"{API}/conversations/{conv_id}/read")
            time.sleep(0.05)

        msgs = admin_session.get(f"{API}/conversations/{conv_id}/messages").json()
        target = next(m for m in msgs if m["id"] == msg_id)
        assert len(target["read_by"]) == 1

    def test_non_admin_never_sees_read_by(self, admin_session, user_session):
        """Standard (non-admin) users must never see read_by data — it must
        always be an empty list when they query their own messages."""
        # Admin sets up a conv + sends a message to user
        r = admin_session.post(f"{API}/conversations", json={"to_emails": [USER["email"]]})
        conv_id = r.json()["id"]
        admin_session.post(
            f"{API}/conversations/{conv_id}/messages",
            json={"content": "admin-only-receipts"},
        )
        # Have user open the conv to register a receipt
        user_session.post(f"{API}/conversations/{conv_id}/read")

        # Now user sends their own reply and queries the thread
        r = user_session.post(
            f"{API}/conversations/{conv_id}/messages",
            json={"content": "user-reply"},
        )
        assert r.status_code == 200
        # Admin opens the conv to register a receipt on user's reply
        admin_session.post(f"{API}/conversations/{conv_id}/read")

        # User fetches the messages: every message must have read_by == []
        msgs = user_session.get(f"{API}/conversations/{conv_id}/messages").json()
        assert msgs, "expected at least one message"
        for m in msgs:
            assert m["read_by"] == [], f"non-admin leaked read_by on msg {m['id']}: {m['read_by']}"

        # Sanity: admin still sees the receipts on the user's reply
        admin_msgs = admin_session.get(f"{API}/conversations/{conv_id}/messages").json()
        replies = [m for m in admin_msgs if m["content"] == "user-reply"]
        assert replies and len(replies[0]["read_by"]) == 1
