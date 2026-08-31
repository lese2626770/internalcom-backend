"""Authentication helpers: passwords, JWT tokens, current user dependency."""
from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Request

JWT_ALGORITHM = "HS256"
ACCESS_TTL_MIN = 60 * 12  # 12 hours
REFRESH_TTL_DAYS = 7


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def _fernet() -> Fernet:
    """Reversible symmetric cipher used ONLY to let admins re-display the
    initial password they themselves typed when creating a user. Never used
    for hash storage. Key is derived from JWT_SECRET so it survives
    deployments without needing a second env var. If the secret is rotated,
    previously-stored encrypted blobs become unreadable — admins will simply
    see "not available" and can re-set a new password.
    """
    secret = (os.environ.get("JWT_SECRET") or "change-me-in-prod").encode("utf-8")
    digest = hashlib.sha256(secret + b"::password_visible_enc::v1").digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_password(plain: str) -> str:
    return _fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_password(token: str) -> Optional[str]:
    """Returns None if the blob can't be decrypted (key rotation, corrupted,
    or empty input) — callers should treat that as "password not available
    for display"."""
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def _secret() -> str:
    return os.environ.get("JWT_SECRET") or "change-me-in-prod"


def create_access_token(user_id: str, email: str, impersonated_by: Optional[str] = None) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TTL_MIN),
    }
    if impersonated_by:
        payload["imp_by"] = impersonated_by
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str, impersonated_by: Optional[str] = None) -> str:
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TTL_DAYS),
    }
    if impersonated_by:
        payload["imp_by"] = impersonated_by
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, _secret(), algorithms=[JWT_ALGORITHM])


def set_auth_cookies(response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=ACCESS_TTL_MIN * 60,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=REFRESH_TTL_DAYS * 24 * 3600,
        path="/",
    )


def clear_auth_cookies(response) -> None:
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")


def extract_token(request: Request) -> Optional[str]:
    # Bearer token takes priority over the cookie so an impersonation tab can
    # send `Authorization: Bearer <imp_token>` without losing the admin's
    # cookie session in the other tab on the same domain.
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    token = request.cookies.get("access_token")
    if token:
        return token
    return None
