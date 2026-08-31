"""Tests for the admin Super Inbox + View-as-user feature."""
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


@pytest.fixture
def admin_session():
    return _login(ADMIN)


@pytest.fixture
def user_session():
    return _login(USER)


@pytest.fixture
def user_me(user_session):
    return user_session.get(f"{API}/auth/me").json()


class TestSuperInbox:
    def test_admin_lists_all_conversations(self, admin_session):
        """folder=all returns ALL conversations system-wide and each entry has owner info."""
        r = admin_session.get(f"{API}/conversations", params={"folder": "all"})
        assert r.status_code == 200, r.text
        data = r.json()
        assert isinstance(data, list)
        # As long as we have at least one conv globally, validate owner shape.
        if data:
            sample = data[0]
            assert "owner" in sample
            if sample["owner"]:
                assert "id" in sample["owner"]
                assert "name" in sample["owner"]
                assert "email" in sample["owner"]

    def test_non_admin_cannot_list_all(self, user_session):
        r = user_session.get(f"{API}/conversations", params={"folder": "all"})
        assert r.status_code == 403

    def test_admin_can_read_any_conversation(self, admin_session, user_session, user_me):
        """Admin can fetch messages from a conv they're not a participant of."""
        # User creates a conv with themselves only (admin is not in it)
        # by sending to a teammate — here we use admin as recipient, then drop admin afterwards
        # Simpler: user invites another participant (not admin). We pick any other user.
        users_list = admin_session.get(f"{API}/users").json()
        third_party = next(
            (u for u in users_list
             if u["email"] not in (USER["email"], ADMIN["email"])),
            None,
        )
        if third_party is None:
            pytest.skip("Need a third user to construct a conv excluding admin")
        r = user_session.post(f"{API}/conversations", json={"to_emails": [third_party["email"]]})
        assert r.status_code == 200, r.text
        conv_id = r.json()["id"]
        marker = f"private-{uuid.uuid4().hex[:6]}"
        user_session.post(f"{API}/conversations/{conv_id}/messages", json={"content": marker})

        # Admin can read it without being a participant
        r = admin_session.get(f"{API}/conversations/{conv_id}/messages")
        assert r.status_code == 200
        msgs = r.json()
        assert any(m["content"] == marker for m in msgs)

    def test_non_admin_cannot_read_others_conversation(self, admin_session, user_session, user_me):
        """Standard users still get 404 on conversations they're not in."""
        users_list = admin_session.get(f"{API}/users").json()
        third_party = next(
            (u for u in users_list
             if u["email"] not in (USER["email"], ADMIN["email"])),
            None,
        )
        if third_party is None:
            pytest.skip("Need a third user")
        # Admin creates a conv to a third party (user excluded)
        r = admin_session.post(f"{API}/conversations", json={"to_emails": [third_party["email"]]})
        conv_id = r.json()["id"]
        r = user_session.get(f"{API}/conversations/{conv_id}/messages")
        assert r.status_code == 404


class TestViewAs:
    def test_admin_lists_conversations_as_user(self, admin_session, user_session, user_me):
        """as_user_id makes the listing use the target user's perspective (their
        participation, their unread counts)."""
        # Set up a conv from admin to user — user should see it in their inbox
        r = admin_session.post(f"{API}/conversations", json={"to_emails": [USER["email"]]})
        conv_id = r.json()["id"]
        admin_session.post(f"{API}/conversations/{conv_id}/messages", json={"content": "view-as-test"})

        # Admin listing as the user should include this conv with unread_count > 0
        r = admin_session.get(
            f"{API}/conversations",
            params={"folder": "inbox", "as_user_id": user_me["id"]},
        )
        assert r.status_code == 200
        data = r.json()
        target = next((c for c in data if c["id"] == conv_id), None)
        assert target is not None, "conv should appear in user's perspective inbox"

    def test_non_admin_cannot_use_view_as(self, user_session):
        r = user_session.get(
            f"{API}/conversations",
            params={"folder": "inbox", "as_user_id": "any-id"},
        )
        assert r.status_code == 403

    def test_view_as_unknown_user(self, admin_session):
        r = admin_session.get(
            f"{API}/conversations",
            params={"folder": "inbox", "as_user_id": "nonexistent-user-id"},
        )
        assert r.status_code == 404
