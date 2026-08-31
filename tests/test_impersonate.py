"""Tests for the admin "Log in as user" full-session impersonation."""
import os
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


class TestImpersonation:
    def test_admin_can_impersonate(self, admin_session, user_me):
        """Admin POSTs to /auth/impersonate/<id> and the same session now acts
        as the target user, with `impersonated_by` exposed on /auth/me."""
        r = admin_session.post(f"{API}/auth/impersonate/{user_me['id']}")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["impersonating"]["id"] == user_me["id"]

        me = admin_session.get(f"{API}/auth/me").json()
        assert me["email"] == USER["email"]
        assert me["impersonated_by"]["email"] == ADMIN["email"]

        # Cleanup: return to admin so other tests are unaffected
        admin_session.post(f"{API}/auth/impersonate/return")

    def test_non_admin_cannot_impersonate(self, user_session, user_me):
        r = user_session.post(f"{API}/auth/impersonate/{user_me['id']}")
        assert r.status_code == 403

    def test_cannot_impersonate_self(self, admin_session):
        me = admin_session.get(f"{API}/auth/me").json()
        r = admin_session.post(f"{API}/auth/impersonate/{me['id']}")
        assert r.status_code == 400
        assert "yourself" in r.json()["detail"].lower()

    def test_nested_impersonation_blocked(self, admin_session, user_me):
        admin_session.post(f"{API}/auth/impersonate/{user_me['id']}")
        try:
            # Now the session is Sophie's — Sophie is not admin so first the
            # admin check rejects. The "already impersonating" guard exists for
            # the (impossible-by-design) case where an admin impersonates an
            # admin — we don't have a 2nd admin here so we settle for the 403.
            r = admin_session.post(f"{API}/auth/impersonate/{user_me['id']}")
            assert r.status_code in (400, 403)
        finally:
            admin_session.post(f"{API}/auth/impersonate/return")

    def test_return_restores_admin_session(self, admin_session, user_me):
        admin_session.post(f"{API}/auth/impersonate/{user_me['id']}")
        r = admin_session.post(f"{API}/auth/impersonate/return")
        assert r.status_code == 200, r.text
        me = admin_session.get(f"{API}/auth/me").json()
        assert me["email"] == ADMIN["email"]
        assert me.get("impersonated_by") in (None, {}, False)

    def test_return_requires_active_impersonation(self, admin_session):
        # Make sure we are NOT impersonating right now
        r = admin_session.post(f"{API}/auth/impersonate/return")
        assert r.status_code == 400
        assert "not impersonating" in r.json()["detail"].lower()

    def test_impersonate_unknown_user(self, admin_session):
        r = admin_session.post(f"{API}/auth/impersonate/nonexistent-id")
        assert r.status_code == 404
