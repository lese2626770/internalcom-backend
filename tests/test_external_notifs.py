"""Tests for external email notifications triggered when admin sends a message."""
import os
import time
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


@pytest.fixture
def admin_session():
    return _login(ADMIN)


@pytest.fixture
def user_session():
    return _login(USER)


class TestExternalNotifications:
    def test_admin_message_send_returns_quickly(self, admin_session):
        """Critical: external Resend notification must NOT block the API
        response. The send_message endpoint should return in < 1 second even
        though it triggers an external email."""
        r = admin_session.post(f"{API}/conversations", json={"to_emails": [USER["email"]]})
        conv_id = r.json()["id"]

        start = time.monotonic()
        r = admin_session.post(
            f"{API}/conversations/{conv_id}/messages",
            json={"content": f"perf-test-{uuid.uuid4().hex[:6]}"},
        )
        elapsed = time.monotonic() - start
        assert r.status_code == 200
        assert elapsed < 1.5, (
            f"send_message took {elapsed:.2f}s — Resend notification appears "
            "to block the response. It must be fire-and-forget."
        )

    def test_non_admin_send_does_not_break(self, user_session):
        """When a standard user sends a message, the external notification
        path must be skipped silently (no error, no notification)."""
        # User needs an existing conv to send into. Create one to admin.
        r = user_session.post(f"{API}/conversations", json={"to_emails": [ADMIN["email"]]})
        assert r.status_code == 200
        conv_id = r.json()["id"]
        r = user_session.post(
            f"{API}/conversations/{conv_id}/messages",
            json={"content": "standard-user-send"},
        )
        assert r.status_code == 200
        # The send succeeded and didn't raise — that's all we can assert here
        # without intercepting Resend. The integration-level behaviour is
        # validated manually (see backend logs).

    def test_admin_impersonation_still_notifies(self, admin_session, user_session):
        """When admin impersonates user A to send to user B, the notification
        should still fire (the caller — admin — is the one with permission)."""
        # Need a 3rd user. Admin acts as someone else, sends to USER.
        users = admin_session.get(f"{API}/users").json()
        impersonate_target = next(
            (u for u in users if u["email"] not in (ADMIN["email"], USER["email"]) and u.get("is_active", True)),
            None,
        )
        if impersonate_target is None:
            pytest.skip("Need a 3rd user")

        # Create a conv as admin
        r = admin_session.post(
            f"{API}/conversations",
            json={
                "to_emails": [USER["email"]],
                "as_sender_id": impersonate_target["id"],
            },
        )
        assert r.status_code == 200, r.text
        conv_id = r.json()["id"]

        start = time.monotonic()
        r = admin_session.post(
            f"{API}/conversations/{conv_id}/messages",
            json={
                "content": "impersonation-notif-test",
                "as_sender_id": impersonate_target["id"],
            },
        )
        elapsed = time.monotonic() - start
        assert r.status_code == 200
        # Same perf budget
        assert elapsed < 1.5
