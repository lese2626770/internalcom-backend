"""
IntraCom backend API tests.

Covers: auth (register/login/me/logout/lockout), users (RBAC), roles (system+custom),
conversations (direct dedupe, group), messages (text+attachments+since), files (upload/download/limits).
"""
import io
import os
import time
import uuid

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://internal-comms-12.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = os.environ.get("TEST_ADMIN_EMAIL", "admin@intracom.app")
ADMIN_PASSWORD = os.environ.get("TEST_ADMIN_PASSWORD", "Admin123!")
USER_EMAIL = os.environ.get("TEST_USER_EMAIL", "user@intracom.app")
USER_PASSWORD = os.environ.get("TEST_USER_PASSWORD", "User123!")


# ---------------- Fixtures ----------------
@pytest.fixture(scope="session")
def admin_session():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"Admin login failed: {r.status_code} {r.text}"
    return s


@pytest.fixture(scope="session")
def user_session():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD})
    assert r.status_code == 200, f"User login failed: {r.status_code} {r.text}"
    return s


@pytest.fixture(scope="session")
def admin_me(admin_session):
    return admin_session.get(f"{API}/auth/me").json()


@pytest.fixture(scope="session")
def user_me(user_session):
    return user_session.get(f"{API}/auth/me").json()


# ---------------- Auth ----------------
class TestAuth:
    def test_health(self):
        r = requests.get(f"{API}/")
        assert r.status_code == 200
        assert r.json().get("status") == "ok"

    def test_admin_login(self):
        s = requests.Session()
        r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == "admin"
        assert "users.manage" in data["permissions"]
        assert "roles.manage" in data["permissions"]
        assert "access_token" in s.cookies

    def test_login_invalid_password(self):
        r = requests.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-pw"})
        assert r.status_code == 401

    def test_me_unauthenticated(self):
        r = requests.get(f"{API}/auth/me")
        assert r.status_code == 401

    def test_me_authenticated(self, admin_session):
        r = admin_session.get(f"{API}/auth/me")
        assert r.status_code == 200
        assert r.json()["email"] == ADMIN_EMAIL

    def test_register_new_user(self):
        s = requests.Session()
        email = f"test_reg_{uuid.uuid4().hex[:8]}@intracom.app"
        r = s.post(f"{API}/auth/register", json={
            "email": email, "name": "Reg Test", "password": "Passw0rd!"
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["email"] == email
        assert data["role"] == "user"
        assert "messages.send" in data["permissions"]
        assert "access_token" in s.cookies
        # cleanup
        admin = requests.Session()
        admin.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        admin.delete(f"{API}/users/{data['id']}")

    def test_logout_clears_cookies(self, admin_session):
        s = requests.Session()
        s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert "access_token" in s.cookies
        r = s.post(f"{API}/auth/logout")
        assert r.status_code == 200
        # After logout the cookie should be cleared
        r2 = s.get(f"{API}/auth/me")
        assert r2.status_code == 401


# ---------------- Users (RBAC) ----------------
class TestUsers:
    def test_list_users_admin(self, admin_session):
        r = admin_session.get(f"{API}/users")
        assert r.status_code == 200
        users = r.json()
        assert isinstance(users, list)
        assert any(u["email"] == ADMIN_EMAIL for u in users)
        assert any(u["email"] == USER_EMAIL for u in users)

    def test_list_users_regular(self, user_session):
        r = user_session.get(f"{API}/users")
        assert r.status_code == 200

    def test_admin_create_update_delete_user(self, admin_session, admin_me):
        email = f"test_crud_{uuid.uuid4().hex[:8]}@intracom.app"
        # create
        r = admin_session.post(f"{API}/users", json={
            "email": email, "name": "CRUD Test", "password": "Passw0rd!", "role": "user"
        })
        assert r.status_code == 200, r.text
        uid = r.json()["id"]

        # GET verify
        users = admin_session.get(f"{API}/users").json()
        assert any(u["id"] == uid and u["email"] == email for u in users)

        # update name + deactivate
        r2 = admin_session.patch(f"{API}/users/{uid}", json={"name": "Renamed", "is_active": False})
        assert r2.status_code == 200
        assert r2.json()["name"] == "Renamed"
        assert r2.json()["is_active"] == False  # noqa: E712

        # admin cannot disable self
        r3 = admin_session.patch(f"{API}/users/{admin_me['id']}", json={"is_active": False})
        assert r3.status_code == 400

        # admin cannot delete self
        r4 = admin_session.delete(f"{API}/users/{admin_me['id']}")
        assert r4.status_code == 400

        # delete
        r5 = admin_session.delete(f"{API}/users/{uid}")
        assert r5.status_code == 200

        # gone -> deleting again 404
        r6 = admin_session.delete(f"{API}/users/{uid}")
        assert r6.status_code == 404

    def test_non_admin_cannot_manage(self, user_session):
        r = user_session.post(f"{API}/users", json={
            "email": "TEST_x@intracom.app", "name": "X", "password": "Passw0rd!", "role": "user"
        })
        assert r.status_code == 403
        r2 = user_session.patch(f"{API}/users/some-id", json={"name": "Y"})
        assert r2.status_code == 403
        r3 = user_session.delete(f"{API}/users/some-id")
        assert r3.status_code == 403


# ---------------- Roles ----------------
class TestRoles:
    def test_permissions_catalog(self, admin_session):
        r = admin_session.get(f"{API}/permissions/catalog")
        assert r.status_code == 200
        perms = r.json()["permissions"]
        assert len(perms) == 6
        for p in ["messages.send", "messages.send_attachments", "conversations.create_direct",
                  "conversations.create_group", "users.manage", "roles.manage"]:
            assert p in perms

    def test_list_roles_contains_system(self, admin_session):
        r = admin_session.get(f"{API}/roles")
        assert r.status_code == 200
        roles = r.json()
        ids = [x["id"] for x in roles]
        assert "admin" in ids and "user" in ids

    def test_create_update_delete_custom_role(self, admin_session):
        name = f"TEST_role_{uuid.uuid4().hex[:6]}"
        r = admin_session.post(f"{API}/roles", json={
            "name": name, "description": "x", "permissions": ["messages.send"]
        })
        assert r.status_code == 200, r.text
        rid = r.json()["id"]

        # cannot update system role
        r2 = admin_session.patch(f"{API}/roles/admin", json={
            "name": "admin", "description": "", "permissions": []
        })
        assert r2.status_code == 400

        # update custom role
        r3 = admin_session.patch(f"{API}/roles/{rid}", json={
            "name": name, "description": "updated", "permissions": ["messages.send", "messages.send_attachments"]
        })
        assert r3.status_code == 200
        assert "messages.send_attachments" in r3.json()["permissions"]

        # cannot delete system role
        r4 = admin_session.delete(f"{API}/roles/admin")
        assert r4.status_code == 400

        # delete custom role
        r5 = admin_session.delete(f"{API}/roles/{rid}")
        assert r5.status_code == 200

    def test_non_admin_cannot_create_role(self, user_session):
        r = user_session.post(f"{API}/roles", json={
            "name": "TEST_no", "description": "", "permissions": []
        })
        assert r.status_code == 403


# ---------------- Conversations + Messages ----------------
class TestConversationsMessages:
    @pytest.fixture(scope="class")
    def direct_conv(self, admin_session, admin_me, user_me):
        r = admin_session.post(f"{API}/conversations", json={
            "type": "direct", "participant_ids": [user_me["id"]]
        })
        assert r.status_code == 200, r.text
        return r.json()

    def test_direct_dedupe(self, admin_session, user_me, direct_conv):
        r2 = admin_session.post(f"{API}/conversations", json={
            "type": "direct", "participant_ids": [user_me["id"]]
        })
        assert r2.status_code == 200
        assert r2.json()["id"] == direct_conv["id"]

    def test_group_requires_name(self, admin_session, user_me):
        r = admin_session.post(f"{API}/conversations", json={
            "type": "group", "participant_ids": [user_me["id"]]
        })
        assert r.status_code == 400

    def test_list_conversations(self, admin_session, direct_conv):
        r = admin_session.get(f"{API}/conversations")
        assert r.status_code == 200
        ids = [c["id"] for c in r.json()]
        assert direct_conv["id"] in ids

    def test_send_message_and_since(self, admin_session, direct_conv):
        cid = direct_conv["id"]
        r = admin_session.post(f"{API}/conversations/{cid}/messages", json={"content": "Hello from test"})
        assert r.status_code == 200
        msg = r.json()
        assert msg["content"] == "Hello from test"
        ts = msg["created_at"]
        # since=ts should return no messages (strict gt)
        r2 = admin_session.get(f"{API}/conversations/{cid}/messages", params={"since": ts})
        assert r2.status_code == 200
        assert all(m["created_at"] > ts for m in r2.json())

        # send another message; verify since fetches only newer one
        time.sleep(0.05)
        r3 = admin_session.post(f"{API}/conversations/{cid}/messages", json={"content": "second"})
        assert r3.status_code == 200
        r4 = admin_session.get(f"{API}/conversations/{cid}/messages", params={"since": ts})
        assert any(m["content"] == "second" for m in r4.json())

    def test_mark_read(self, admin_session, direct_conv):
        cid = direct_conv["id"]
        r = admin_session.post(f"{API}/conversations/{cid}/read")
        assert r.status_code == 200

    def test_non_participant_cannot_send(self, admin_session, user_session, admin_me):
        # create a direct conv only with admin (admin+admin not possible). Use a 3rd seeded? skip
        # Build group with admin+test user excluding regular user
        new_email = f"TEST_np_{uuid.uuid4().hex[:6]}@intracom.app"
        c = admin_session.post(f"{API}/users", json={
            "email": new_email, "name": "NP", "password": "Passw0rd!", "role": "user"
        })
        nid = c.json()["id"]
        g = admin_session.post(f"{API}/conversations", json={
            "type": "group", "name": "TEST_grp", "participant_ids": [nid]
        })
        assert g.status_code == 200
        gid = g.json()["id"]
        # user_session is not in this group
        r = user_session.post(f"{API}/conversations/{gid}/messages", json={"content": "x"})
        assert r.status_code == 404
        admin_session.delete(f"{API}/users/{nid}")


# ---------------- Files ----------------
class TestFiles:
    def test_upload_image_and_download(self, admin_session):
        # 1x1 PNG
        png = bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c63000100000005000100"
            "0d0a2db40000000049454e44ae426082"
        )
        r = admin_session.post(
            f"{API}/files/upload",
            files={"file": ("pixel.png", io.BytesIO(png), "image/png")},
        )
        assert r.status_code == 200, r.text
        fid = r.json()["id"]
        assert r.json()["content_type"].startswith("image/")

        # download
        r2 = admin_session.get(f"{API}/files/{fid}")
        assert r2.status_code == 200
        assert r2.headers["content-type"].startswith("image/")
        assert len(r2.content) > 0

    def test_upload_too_large(self, admin_session):
        big = b"x" * (16 * 1024 * 1024)
        r = admin_session.post(
            f"{API}/files/upload",
            files={"file": ("big.txt", io.BytesIO(big), "text/plain")},
        )
        assert r.status_code == 400

    def test_upload_disallowed_mime(self, admin_session):
        r = admin_session.post(
            f"{API}/files/upload",
            files={"file": ("evil.bin", io.BytesIO(b"abc"), "application/x-executable")},
        )
        assert r.status_code == 400

    def test_download_unauthenticated(self, admin_session):
        # upload a file first
        r = admin_session.post(
            f"{API}/files/upload",
            files={"file": ("t.txt", io.BytesIO(b"hello"), "text/plain")},
        )
        assert r.status_code == 200
        fid = r.json()["id"]
        # anonymous
        r2 = requests.get(f"{API}/files/{fid}")
        assert r2.status_code == 401

    def test_download_forbidden_for_non_participant(self, admin_session, user_session):
        r = admin_session.post(
            f"{API}/files/upload",
            files={"file": ("priv.txt", io.BytesIO(b"secret"), "text/plain")},
        )
        fid = r.json()["id"]
        # user_session has no relation to this file
        r2 = user_session.get(f"{API}/files/{fid}")
        assert r2.status_code == 403
