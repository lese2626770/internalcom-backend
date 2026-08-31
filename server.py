"""IntraCom — Internal communication platform (FastAPI backend)."""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

from fastapi import (
    APIRouter,
    Body,
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from starlette.middleware.cors import CORSMiddleware

from auth import (
    clear_auth_cookies,
    create_access_token,
    create_refresh_token,
    decode_token,
    decrypt_password,
    encrypt_password,
    extract_token,
    hash_password,
    set_auth_cookies,
    verify_password,
)
import bleach
from bleach.css_sanitizer import CSSSanitizer
from models import (
    ALL_PERMISSIONS,
    SYSTEM_ROLES,
    AdminCreateUserIn,
    AdminUpdateUserIn,
    AttachmentOut,
    ConversationCreateIn,
    ConversationOut,
    DraftIn,
    FieldValueIn,
    InviteEmailIn,
    LoginIn,
    MessageCreateIn,
    MessageOut,
    MessageTemplateCreateIn,
    MessageTemplateUpdateIn,
    RegisterIn,
    RegisterResendOtpIn,
    RegisterStartIn,
    RegisterVerifyIn,
    RoleIn,
    RoleOut,
    SignDocIn,
    SignatureDocCreateIn,
    SubmitFieldsIn,
    UserPublic,
)
from email_otp import (
    generate_otp_code,
    send_invitation_email,
    send_new_message_notification,
    send_otp_email,
    send_password_reset_email,
)
from signatures import build_signed_pdf, decode_signature_b64
from storage import get_object, init_storage, put_object

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# ---------- DB ----------
# Read MongoDB connection details with a graceful fallback. The deployed
# container relies on the platform to inject MONGO_URL and DB_NAME via env
# vars; if the injection happens slightly after module import (race), or if
# a var is briefly missing, we log a clear error instead of crashing the
# whole process in a Kubernetes boot loop. Health endpoints will still
# respond, surfacing the real problem in a debuggable way.
MONGO_URL = os.environ.get("MONGO_URL") or "mongodb://localhost:27017"
DB_NAME = os.environ.get("DB_NAME") or "intracom"
if not os.environ.get("MONGO_URL"):
    logger.error("MONGO_URL env var missing — falling back to %s", MONGO_URL)
if not os.environ.get("DB_NAME"):
    logger.error("DB_NAME env var missing — falling back to %s", DB_NAME)
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# ---------- Constants ----------
APP_NAME = os.environ.get("APP_NAME", "intercom")
MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MB
ALLOWED_MIME_PREFIXES = ("image/", "application/pdf", "application/msword",
                        "application/vnd.openxmlformats-officedocument",
                        "text/plain", "application/zip")

LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_MIN = 15

# ---------- HTML sanitization (rich text composer) ----------
ALLOWED_HTML_TAGS = [
    "p", "br", "div", "span", "b", "strong", "i", "em", "u", "s", "strike",
    "ul", "ol", "li", "h1", "h2", "h3", "h4", "blockquote", "code", "pre",
    "a", "font", "hr",
]
ALLOWED_HTML_ATTRS = {
    "*": ["style", "class"],
    "a": ["href", "target", "rel"],
    "font": ["face", "size", "color"],
    "span": ["style"],
}
ALLOWED_CSS_PROPS = [
    "font-family", "font-size", "font-weight", "font-style",
    "text-decoration", "text-align", "color", "background-color",
    "line-height",
]


def sanitize_html(html: str) -> str:
    if not html:
        return ""
    cleaner = bleach.Cleaner(
        tags=ALLOWED_HTML_TAGS,
        attributes=ALLOWED_HTML_ATTRS,
        css_sanitizer=CSSSanitizer(allowed_css_properties=ALLOWED_CSS_PROPS),
        strip=True,
        strip_comments=True,
    )
    return cleaner.clean(html)


def html_to_text(html: str) -> str:
    """Strip tags to derive plain-text preview/fallback."""
    if not html:
        return ""
    txt = bleach.clean(html, tags=[], attributes={}, strip=True)
    # collapse whitespace
    return " ".join(txt.split())

# ---------- App ----------
app = FastAPI(title="IntraCom API")
api = APIRouter(prefix="/api")

allowed_origins_env = os.environ.get("CORS_ORIGINS", "*")
frontend_url = os.environ.get("FRONTEND_URL", "")

if allowed_origins_env.strip() == "*":
    # Browsers reject wildcard with allow_credentials=True, so build an explicit
    # allowlist that contains the configured FRONTEND_URL and any additional
    # origins listed in CORS_EXTRA_ORIGINS (comma-separated). Configure
    # production domains via env vars instead of hardcoding them in code.
    origins = [frontend_url] if frontend_url else []
    extra_env = os.environ.get("CORS_EXTRA_ORIGINS", "")
    for extra in extra_env.split(","):
        clean = extra.strip()
        if clean and clean not in origins:
            origins.append(clean)
else:
    origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
    if frontend_url and frontend_url not in origins:
        origins.append(frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Helpers ----------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def get_role_permissions(role: str, roles_cache: dict | None = None) -> List[str]:
    if role in SYSTEM_ROLES:
        return list(SYSTEM_ROLES[role])
    if roles_cache is not None and role in roles_cache:
        return list(roles_cache[role].get("permissions", []))
    role_doc = await db.roles.find_one({"id": role}, {"_id": 0})
    if role_doc:
        return list(role_doc.get("permissions", []))
    return []


async def serialize_user(user_doc: dict, roles_cache: dict | None = None) -> dict:
    role = user_doc.get("role", "user")
    perms = await get_role_permissions(role, roles_cache)
    role_name = role
    if role not in SYSTEM_ROLES:
        if roles_cache is not None and role in roles_cache:
            role_name = roles_cache[role].get("name", role)
        else:
            rd = await db.roles.find_one({"id": role}, {"_id": 0, "name": 1})
            role_name = rd["name"] if rd else role
    return {
        "id": user_doc["id"],
        "email": user_doc["email"],
        "name": user_doc["name"],
        "role": role,
        "role_name": role_name,
        "permissions": perms,
        "is_active": user_doc.get("is_active", True),
        "email_notifications_enabled": bool(user_doc.get("email_notifications_enabled", False)),
        "created_at": user_doc.get("created_at", now_iso()),
        "last_seen_at": user_doc.get("last_seen_at"),
    }


async def _load_roles_cache() -> dict:
    docs = await db.roles.find({}, {"_id": 0}).to_list(500)
    return {r["id"]: r for r in docs}


async def get_current_user(request: Request) -> dict:
    token = extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")
    # Propagate "impersonated by" — set when an admin assumed this user's
    # session via /api/auth/impersonate/{id}. Used in audit logs and UI banner.
    if payload.get("imp_by"):
        user["impersonated_by"] = payload["imp_by"]
    return user


def require_permission(perm: str):
    async def dep(request: Request) -> dict:
        user = await get_current_user(request)
        perms = await get_role_permissions(user.get("role", "user"))
        if perm not in perms:
            raise HTTPException(status_code=403, detail=f"Missing permission: {perm}")
        return user
    return dep


def require_admin():
    return require_permission("users.manage")


# ---------- Auth endpoints ----------
INVITE_CODE_TTL_DAYS = 30
OTP_TTL_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 30


def generate_invite_code() -> str:
    import secrets as _secrets
    import string as _string
    alphabet = _string.ascii_uppercase + _string.digits
    raw = "".join(_secrets.choice(alphabet) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


async def _validate_invite_code(code: str) -> dict:
    """Look up an invite code and verify it is still usable. Raises HTTPException on failure."""
    invite = await db.invite_codes.find_one({"code": code})
    if not invite:
        raise HTTPException(status_code=400, detail="Invalid invitation code")
    if invite.get("used"):
        raise HTTPException(status_code=400, detail="This invitation code has already been used")
    expires_at = invite.get("expires_at")
    if expires_at and datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="This invitation code has expired")
    return invite


# ---------- Activity log (admin tracking) ----------
async def log_activity(
    *,
    user_id: Optional[str],
    user_email: Optional[str],
    user_name: Optional[str] = None,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    details: Optional[dict] = None,
    request: Optional[Request] = None,
) -> None:
    """Insert an audit-trail entry. Best-effort — never raises."""
    try:
        ip = "—"
        ua = ""
        if request is not None:
            ip = (request.client.host if request.client else None) or request.headers.get("x-forwarded-for", "").split(",")[0].strip() or "—"
            ua = (request.headers.get("user-agent") or "")[:300]
        await db.activity_logs.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "user_email": user_email,
            "user_name": user_name,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details or {},
            "ip": ip,
            "user_agent": ua,
            "created_at": now_iso(),
        })
    except Exception as e:  # noqa: BLE001
        logger.warning("activity log failed: action=%s err=%s", action, e)


@api.post("/auth/register/start")
async def register_start(payload: RegisterStartIn):
    """Step 1: validate invite + email, generate OTP, send it by email."""
    email = payload.email.lower().strip()
    code = payload.invite_code.strip().upper()

    invite = await _validate_invite_code(code)

    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # invalidate any prior pending registration for the same email
    await db.pending_registrations.delete_many({"email": email})

    pending_id = str(uuid.uuid4())
    otp_code = generate_otp_code()
    now = datetime.now(timezone.utc)
    pending_doc = {
        "id": pending_id,
        "email": email,
        "name": payload.name.strip(),
        "password_hash": hash_password(payload.password),
        "invite_id": invite["id"],
        "invite_code": code,
        "otp_code": otp_code,
        "attempts": 0,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=OTP_TTL_MINUTES)).isoformat(),
        "last_sent_at": now.isoformat(),
    }
    await db.pending_registrations.insert_one(pending_doc)

    sent = await send_otp_email(email, payload.name.strip(), otp_code)
    return {
        "pending_id": pending_id,
        "email": email,
        "expires_in": OTP_TTL_MINUTES * 60,
        "email_sent": sent,
    }


@api.post("/auth/register/resend-otp")
async def register_resend_otp(payload: RegisterResendOtpIn):
    """Generate a new OTP for an existing pending registration and resend it."""
    pending = await db.pending_registrations.find_one({"id": payload.pending_id})
    if not pending:
        raise HTTPException(status_code=404, detail="Registration request not found or expired")

    last_sent = pending.get("last_sent_at")
    if last_sent:
        delta = (datetime.now(timezone.utc) - datetime.fromisoformat(last_sent)).total_seconds()
        if delta < OTP_RESEND_COOLDOWN_SECONDS:
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {int(OTP_RESEND_COOLDOWN_SECONDS - delta)}s before resending a code",
            )

    new_code = generate_otp_code()
    now = datetime.now(timezone.utc)
    await db.pending_registrations.update_one(
        {"id": pending["id"]},
        {"$set": {
            "otp_code": new_code,
            "attempts": 0,
            "expires_at": (now + timedelta(minutes=OTP_TTL_MINUTES)).isoformat(),
            "last_sent_at": now.isoformat(),
        }},
    )
    sent = await send_otp_email(pending["email"], pending.get("name", ""), new_code)
    return {"ok": True, "email_sent": sent, "expires_in": OTP_TTL_MINUTES * 60}


@api.post("/auth/register/verify")
async def register_verify(payload: RegisterVerifyIn):
    """Step 2: verify the OTP and finalize the account creation."""
    pending = await db.pending_registrations.find_one({"id": payload.pending_id})
    if not pending:
        raise HTTPException(status_code=404, detail="Registration request not found or expired")

    expires_at = pending.get("expires_at")
    if expires_at and datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
        await db.pending_registrations.delete_one({"id": pending["id"]})
        raise HTTPException(status_code=400, detail="The code has expired, please restart registration")

    if pending.get("attempts", 0) >= OTP_MAX_ATTEMPTS:
        await db.pending_registrations.delete_one({"id": pending["id"]})
        raise HTTPException(status_code=429, detail="Too many incorrect attempts, please start over")

    if payload.code.strip() != pending.get("otp_code"):
        await db.pending_registrations.update_one(
            {"id": pending["id"]}, {"$inc": {"attempts": 1}}
        )
        raise HTTPException(status_code=400, detail="Incorrect verification code")

    # re-validate the invite at the very last moment (it may have been used/expired in the meantime)
    invite = await _validate_invite_code(pending["invite_code"])

    if await db.users.find_one({"email": pending["email"]}):
        await db.pending_registrations.delete_one({"id": pending["id"]})
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "id": str(uuid.uuid4()),
        "email": pending["email"],
        "name": pending["name"],
        "password_hash": pending["password_hash"],
        "role": "user",
        "is_active": True,
        "created_at": now_iso(),
        "invited_via": invite["id"],
        "email_verified_at": now_iso(),
    }
    await db.users.insert_one(user_doc)

    await db.invite_codes.update_one(
        {"id": invite["id"]},
        {"$set": {"used": True, "used_by": user_doc["id"], "used_at": now_iso()}},
    )
    await db.pending_registrations.delete_one({"id": pending["id"]})

    pub = await serialize_user(user_doc)
    access = create_access_token(user_doc["id"], pending["email"])
    refresh = create_refresh_token(user_doc["id"])
    resp = JSONResponse(content={**pub, "access_token": access, "refresh_token": refresh})
    set_auth_cookies(resp, access, refresh)
    return resp


@api.post("/auth/register")
async def register(payload: RegisterIn):
    """Deprecated: legacy single-step register kept only to surface a clear error to old clients."""
    raise HTTPException(
        status_code=410,
        detail="Single-step registration has been removed. Use /auth/register/start then /auth/register/verify.",
    )


# ---------- Password reset ----------
PASSWORD_RESET_TTL_MIN = 60  # link valid for 60 minutes
PASSWORD_RESET_RATE_WINDOW_SEC = 60  # min seconds between successive reset requests for the same email


def _hash_reset_token(token: str) -> str:
    """SHA-256 hash of the reset token. We store the hash in the DB so a DB
    leak can not be replayed to take over accounts; the cleartext token is
    only ever transmitted in the email link."""
    import hashlib
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _origin_from_request(request: Request) -> str:
    """Frontend origin used to build email links (reset password, invitations).
    Priority order:
      1. FRONTEND_URL env var (so a fork/preview deployment can force prod
         links even when the admin clicks "Send" from the preview UI).
      2. The request's Origin / Referer header.
      3. The Host header.
    """
    env_url = (os.environ.get("FRONTEND_URL") or "").strip().rstrip("/")
    if env_url.startswith("https://") or env_url.startswith("http://"):
        return env_url
    origin = request.headers.get("origin") or request.headers.get("referer")
    if origin:
        from urllib.parse import urlparse
        p = urlparse(origin)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    host = request.headers.get("host", "")
    if host:
        return f"https://{host}"
    return ""


@api.post("/auth/forgot-password")
async def auth_forgot_password(payload: dict, request: Request):
    """Generate a single-use reset token and email it to the user.

    Per product decision, this endpoint tells the caller whether the email
    is registered (`sent: true/false`). This makes account enumeration
    possible — only flip back to the generic anti-enumeration response if
    that becomes a concern.
    """
    email = (payload or {}).get("email", "")
    if not isinstance(email, str):
        email = ""
    email = email.lower().strip()

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Please enter a valid email address")

    user = await db.users.find_one(
        {"email": email},
        {"_id": 0, "id": 1, "email": 1, "name": 1, "is_active": 1},
    )
    if not user:
        return {"ok": False, "sent": False, "reason": "not_registered"}
    if user.get("is_active") is False:
        return {"ok": False, "sent": False, "reason": "disabled"}

    now = datetime.now(timezone.utc)

    # Rate limit: 1 fresh token per email per PASSWORD_RESET_RATE_WINDOW_SEC.
    # If the user just requested a link, tell them to wait — explicit feedback
    # is more helpful than silently dropping the request.
    latest = await db.password_reset_tokens.find_one(
        {"user_id": user["id"]},
        sort=[("created_at", -1)],
    )
    if latest:
        try:
            last_at = datetime.fromisoformat(latest["created_at"])
            elapsed = (now - last_at).total_seconds()
            if elapsed < PASSWORD_RESET_RATE_WINDOW_SEC:
                wait = int(PASSWORD_RESET_RATE_WINDOW_SEC - elapsed) + 1
                raise HTTPException(
                    status_code=429,
                    detail=f"A reset link was just sent. Please wait {wait}s before requesting another.",
                )
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001
            pass

    # Invalidate any pending tokens for this user so only the latest one works.
    await db.password_reset_tokens.delete_many({"user_id": user["id"]})

    token = secrets.token_urlsafe(32)
    expires_at = now + timedelta(minutes=PASSWORD_RESET_TTL_MIN)
    await db.password_reset_tokens.insert_one({
        "user_id": user["id"],
        "email": user["email"],
        "token_hash": _hash_reset_token(token),
        "created_at": now.isoformat(),
        "expires_at": expires_at,  # Date type, TTL-indexed
        "used_at": None,
    })

    origin = _origin_from_request(request)
    reset_url = f"{origin}/reset-password?token={token}"

    # Fire and forget — never let email errors leak whether the user exists.
    asyncio.create_task(send_password_reset_email(
        user["email"], user.get("name", ""), reset_url, PASSWORD_RESET_TTL_MIN,
    ))

    return {"ok": True, "sent": True, "email": user["email"]}


@api.post("/auth/reset-password")
async def auth_reset_password(payload: dict):
    """Validate the reset token and overwrite the user's password. Token is
    single-use; immediately marked as used."""
    token = (payload or {}).get("token", "")
    new_password = (payload or {}).get("new_password", "")
    if not isinstance(token, str) or not isinstance(new_password, str):
        raise HTTPException(status_code=400, detail="Invalid request")
    if len(new_password) < 8 or len(new_password) > 200:
        raise HTTPException(status_code=400, detail="Password must be 8-200 characters")

    token_hash = _hash_reset_token(token)
    record = await db.password_reset_tokens.find_one({"token_hash": token_hash})
    if not record:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")
    if record.get("used_at"):
        raise HTTPException(status_code=400, detail="This reset link has already been used")
    expires_at = record.get("expires_at")
    if isinstance(expires_at, datetime):
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="Reset link has expired")

    user = await db.users.find_one({"id": record["user_id"]}, {"_id": 0, "id": 1, "email": 1})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")

    # Update password — bcrypt hash + clear the reversible cipher (admin no
    # longer needs to see this password since the user just set it themselves).
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {
            "password_hash": hash_password(new_password),
        }, "$unset": {"password_visible_enc": ""}},
    )

    # Mark the token as used (one-shot) and also wipe any sibling tokens for
    # the same user, so an attacker who intercepted an earlier link cannot
    # reuse it.
    await db.password_reset_tokens.update_one(
        {"token_hash": token_hash},
        {"$set": {"used_at": datetime.now(timezone.utc).isoformat()}},
    )
    await db.password_reset_tokens.delete_many({
        "user_id": user["id"],
        "token_hash": {"$ne": token_hash},
    })

    # Reset brute-force counters tied to this account so the user can log in
    # immediately after resetting.
    await db.login_attempts.delete_many({"identifier": {"$regex": f":{user['email']}$"}})

    return {"ok": True, "email": user["email"]}


@api.post("/auth/login")
async def login(payload: LoginIn, request: Request):
    email = payload.email.lower().strip()
    ip = request.client.host if request.client else "unknown"
    identifier = f"{ip}:{email}"

    attempts_doc = await db.login_attempts.find_one({"identifier": identifier})
    if attempts_doc:
        if attempts_doc.get("count", 0) >= LOCKOUT_THRESHOLD:
            locked_until = attempts_doc.get("locked_until")
            if locked_until and datetime.fromisoformat(locked_until) > datetime.now(timezone.utc):
                raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user["password_hash"]):
        # increment failed attempts
        new_count = (attempts_doc.get("count", 0) if attempts_doc else 0) + 1
        update = {"count": new_count, "last_attempt": now_iso()}
        if new_count >= LOCKOUT_THRESHOLD:
            update["locked_until"] = (
                datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_WINDOW_MIN)
            ).isoformat()
        await db.login_attempts.update_one(
            {"identifier": identifier}, {"$set": update}, upsert=True
        )
        await log_activity(
            user_id=None, user_email=email, user_name=None,
            action="auth.login.failed", request=request,
            details={"attempts": new_count, "locked": new_count >= LOCKOUT_THRESHOLD},
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")

    await db.login_attempts.delete_one({"identifier": identifier})

    pub = await serialize_user(user)
    access = create_access_token(user["id"], email)
    refresh = create_refresh_token(user["id"])
    # Return tokens in the body (in addition to cookies) so frontends deployed
    # cross-domain (e.g. static host + separate API host) can authenticate via
    # an Authorization: Bearer header instead of relying on cross-site cookies,
    # which many browsers now block by default.
    resp = JSONResponse(content={**pub, "access_token": access, "refresh_token": refresh})
    set_auth_cookies(resp, access, refresh)
    await log_activity(
        user_id=user["id"], user_email=user["email"], user_name=user.get("name"),
        action="auth.login", request=request,
    )
    return resp


@api.post("/auth/logout")
async def logout(request: Request):
    # Best-effort attribution: if there's a valid access cookie, log who logged out.
    uid, uemail, uname = None, None, None
    try:
        token = request.cookies.get("access_token")
        if token:
            payload = decode_token(token)
            uid = payload.get("sub")
            uemail = payload.get("email")
            u = await db.users.find_one({"id": uid}, {"_id": 0, "name": 1})
            uname = (u or {}).get("name")
    except Exception:
        pass
    resp = JSONResponse(content={"ok": True})
    clear_auth_cookies(resp)
    await log_activity(
        user_id=uid, user_email=uemail, user_name=uname,
        action="auth.logout", request=request,
    )
    return resp


@api.post("/auth/refresh")
async def refresh_token(request: Request, payload_in: Optional[dict] = Body(default=None)):
    token = request.cookies.get("refresh_token")
    if not token and payload_in:
        token = payload_in.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    access = create_access_token(user["id"], user["email"])
    new_refresh = create_refresh_token(user["id"])
    resp = JSONResponse(content={"ok": True, "access_token": access, "refresh_token": new_refresh})
    set_auth_cookies(resp, access, new_refresh)
    return resp


@api.get("/auth/me")
async def me(current=Depends(get_current_user)):
    payload = await serialize_user(current)
    # Surface the impersonator info so the UI can show a banner + a
    # "Return to admin" button without an extra round-trip.
    if current.get("impersonated_by"):
        impersonator = await db.users.find_one(
            {"id": current["impersonated_by"]},
            {"_id": 0, "id": 1, "name": 1, "email": 1},
        )
        if impersonator:
            payload["impersonated_by"] = impersonator
    return payload


@api.post("/auth/impersonate/return")
async def impersonate_return(
    response: Response,
    request: Request,
    current=Depends(get_current_user),
):
    """End an impersonation session and restore the admin's own session."""
    impersonator_id = current.get("impersonated_by")
    if not impersonator_id:
        raise HTTPException(status_code=400, detail="Not impersonating")
    admin = await db.users.find_one({"id": impersonator_id, "is_active": True}, {"_id": 0})
    if not admin:
        raise HTTPException(status_code=400, detail="Original admin account unavailable")

    access = create_access_token(admin["id"], admin["email"])
    refresh = create_refresh_token(admin["id"])
    set_auth_cookies(response, access, refresh)

    await log_activity(
        user_id=admin["id"], user_email=admin.get("email"), user_name=admin.get("name"),
        action="auth.impersonate.return",
        target_type="user", target_id=current["id"],
        details={"target_email": current.get("email"), "target_name": current.get("name")},
        request=request,
    )
    return {"ok": True}


@api.post("/auth/impersonate/{target_user_id}")
async def impersonate_user(
    target_user_id: str,
    response: Response,
    request: Request,
    mode: str = Query("cookie", pattern="^(cookie|token)$"),
    current=Depends(get_current_user),
):
    """Admin-only: assume a target user's session.
    - mode=cookie (default, legacy): replaces the admin's cookies (same tab).
    - mode=token: returns tokens in the JSON body WITHOUT touching cookies, so
      the caller can open a new browser tab with those tokens stored in
      sessionStorage. This lets the admin keep their own session intact while
      acting as the target user in a separate tab.
    """
    perms = await get_role_permissions(current.get("role", "user"))
    if "users.manage" not in perms:
        raise HTTPException(status_code=403, detail="Admins only")
    if current.get("impersonated_by"):
        raise HTTPException(status_code=400, detail="Already impersonating another user")
    target = await db.users.find_one({"id": target_user_id}, {"_id": 0})
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")
    if not target.get("is_active", True):
        raise HTTPException(status_code=400, detail="Target account is disabled")
    if target["id"] == current["id"]:
        raise HTTPException(status_code=400, detail="Cannot impersonate yourself")

    access = create_access_token(target["id"], target["email"], impersonated_by=current["id"])
    refresh = create_refresh_token(target["id"], impersonated_by=current["id"])

    if mode == "cookie":
        set_auth_cookies(response, access, refresh)

    await log_activity(
        user_id=current["id"], user_email=current.get("email"), user_name=current.get("name"),
        action="auth.impersonate.start",
        target_type="user", target_id=target["id"],
        details={"target_email": target.get("email"), "target_name": target.get("name"), "mode": mode},
        request=request,
    )
    out = {"ok": True, "impersonating": {
        "id": target["id"], "name": target.get("name"), "email": target.get("email"),
    }}
    if mode == "token":
        # Token-only mode: the caller stores these in sessionStorage of a new
        # browser tab. The frontend api client will then send them as Bearer.
        out["access_token"] = access
        out["refresh_token"] = refresh
    return out


# ---------- Users (admin) ----------
@api.get("/users")
async def list_users(current=Depends(get_current_user)):
    """Any authenticated user can list users (needed for starting conversations)."""
    docs = await db.users.find({}, {"_id": 0, "password_hash": 0, "password_visible_enc": 0}).sort("name", 1).to_list(1000)
    roles_cache = await _load_roles_cache()
    out = [await serialize_user(d, roles_cache) for d in docs]
    return out


@api.post("/users")
async def admin_create_user(payload: AdminCreateUserIn, _=Depends(require_permission("users.manage"))):
    email = payload.email.lower().strip()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    # validate role
    if payload.role not in SYSTEM_ROLES:
        if not await db.roles.find_one({"id": payload.role}):
            raise HTTPException(status_code=400, detail="Invalid role")

    user_doc = {
        "id": str(uuid.uuid4()),
        "email": email,
        "name": payload.name.strip(),
        "password_hash": hash_password(payload.password),
        # Reversible encryption of the password the admin just typed, so it
        # can be redisplayed later in the Users panel. Hashed with bcrypt for
        # actual authentication. Only ever set when the password originates
        # from an admin action — self-registered (OTP) accounts never expose
        # their password since the admin never knew it.
        "password_visible_enc": encrypt_password(payload.password),
        "role": payload.role,
        "is_active": True,
        # External email notifications are OFF by default. Admin must turn
        # them on explicitly from the Users page if the recipient should be
        # alerted on their external inbox when a new internal message
        # arrives. Can also be enabled at creation via the AdminCreateUserIn
        # payload.
        "email_notifications_enabled": bool(payload.email_notifications_enabled),
        "created_at": now_iso(),
    }
    await db.users.insert_one(user_doc)
    return await serialize_user(user_doc)


@api.patch("/users/{user_id}")
async def admin_update_user(
    user_id: str,
    payload: AdminUpdateUserIn,
    current=Depends(require_permission("users.manage")),
):
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update: dict = {}
    if payload.name is not None:
        update["name"] = payload.name.strip()
    if payload.role is not None:
        if payload.role not in SYSTEM_ROLES and not await db.roles.find_one({"id": payload.role}):
            raise HTTPException(status_code=400, detail="Invalid role")
        update["role"] = payload.role
    if payload.is_active is not None:
        # prevent admin from disabling themselves
        if user_id == current["id"] and payload.is_active == False:  # noqa: E712
            raise HTTPException(status_code=400, detail="You cannot disable yourself")
        update["is_active"] = payload.is_active
    if payload.email_notifications_enabled is not None:
        update["email_notifications_enabled"] = bool(payload.email_notifications_enabled)
    if payload.password is not None:
        update["password_hash"] = hash_password(payload.password)
        # Admin typed this password → keep a reversible copy so it can be
        # redisplayed in the Users panel.
        update["password_visible_enc"] = encrypt_password(payload.password)

    if update:
        await db.users.update_one({"id": user_id}, {"$set": update})

    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0, "password_visible_enc": 0})
    return await serialize_user(user)


# ---------- Admin: view / set a user's password ----------
@api.get("/admin/users/{user_id}/password")
async def admin_get_user_password(user_id: str, _=Depends(require_permission("users.manage"))):
    """Return the cleartext password ONLY if the admin originally typed it
    (via POST /users or PATCH /users/{id}). For self-registered users the
    server never had the cleartext to begin with — bcrypt is one-way — so we
    return `{password: null, reason: "self_registered"}`."""
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "id": 1, "email": 1, "name": 1, "password_visible_enc": 1})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    enc = user.get("password_visible_enc")
    if not enc:
        return {
            "password": None,
            "reason": "self_registered",
            "user_id": user["id"],
            "email": user["email"],
            "name": user["name"],
        }
    plain = decrypt_password(enc)
    if plain is None:
        # Key rotation or corruption — admin can set a new password manually.
        return {
            "password": None,
            "reason": "key_rotated",
            "user_id": user["id"],
            "email": user["email"],
            "name": user["name"],
        }
    return {
        "password": plain,
        "reason": "admin_set",
        "user_id": user["id"],
        "email": user["email"],
        "name": user["name"],
    }


@api.post("/admin/users/{user_id}/password")
async def admin_set_user_password(
    user_id: str,
    payload: dict,
    _=Depends(require_permission("users.manage")),
):
    """Admin overwrites the user's password. Stored both as a bcrypt hash
    (for auth) and as an encrypted blob (so it can be redisplayed)."""
    new_password = (payload or {}).get("password", "")
    if not isinstance(new_password, str) or len(new_password) < 4 or len(new_password) > 200:
        raise HTTPException(status_code=400, detail="Password must be 4-200 characters")
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "id": 1})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.users.update_one(
        {"id": user_id},
        {"$set": {
            "password_hash": hash_password(new_password),
            "password_visible_enc": encrypt_password(new_password),
        }},
    )
    return {"ok": True, "password": new_password}


@api.delete("/users/{user_id}")
async def admin_delete_user(user_id: str, current=Depends(require_permission("users.manage"))):
    if user_id == current["id"]:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")
    res = await db.users.delete_one({"id": user_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


# ---------- Roles ----------
@api.get("/permissions/catalog")
async def perms_catalog(_=Depends(get_current_user)):
    return {"permissions": ALL_PERMISSIONS}


@api.get("/roles")
async def list_roles(_=Depends(get_current_user)):
    out = []
    for k, perms in SYSTEM_ROLES.items():
        out.append({
            "id": k,
            "name": k.capitalize(),
            "description": "System" if k == "admin" else "Standard user",
            "permissions": perms,
            "is_system": True,
            "created_at": "",
        })
    custom = await db.roles.find({}, {"_id": 0}).sort("name", 1).to_list(500)
    for r in custom:
        r["is_system"] = False
        out.append(r)
    return out


@api.post("/roles")
async def create_role(payload: RoleIn, _=Depends(require_permission("roles.manage"))):
    # validate permissions
    invalid = [p for p in payload.permissions if p not in ALL_PERMISSIONS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown permissions: {invalid}")
    # name unique
    if await db.roles.find_one({"name": payload.name}):
        raise HTTPException(status_code=400, detail="A role with this name already exists")
    role_doc = {
        "id": str(uuid.uuid4()),
        "name": payload.name.strip(),
        "description": (payload.description or "").strip(),
        "permissions": payload.permissions,
        "is_system": False,
        "created_at": now_iso(),
    }
    await db.roles.insert_one(role_doc)
    role_doc.pop("_id", None)
    return role_doc


@api.patch("/roles/{role_id}")
async def update_role(role_id: str, payload: RoleIn, _=Depends(require_permission("roles.manage"))):
    if role_id in SYSTEM_ROLES:
        raise HTTPException(status_code=400, detail="System roles are read-only")
    invalid = [p for p in payload.permissions if p not in ALL_PERMISSIONS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown permissions: {invalid}")
    res = await db.roles.update_one(
        {"id": role_id},
        {"$set": {
            "name": payload.name.strip(),
            "description": (payload.description or "").strip(),
            "permissions": payload.permissions,
        }}
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Role not found")
    doc = await db.roles.find_one({"id": role_id}, {"_id": 0})
    return doc


@api.delete("/roles/{role_id}")
async def delete_role(role_id: str, _=Depends(require_permission("roles.manage"))):
    if role_id in SYSTEM_ROLES:
        raise HTTPException(status_code=400, detail="System roles cannot be deleted")
    # reassign users with this role to "user"
    await db.users.update_many({"role": role_id}, {"$set": {"role": "user"}})
    res = await db.roles.delete_one({"id": role_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Role not found")
    return {"ok": True}


# ---------- Conversations ----------
async def _serialize_conversation(
    conv: dict,
    current_user_id: str,
    *,
    users_cache: dict | None = None,
    roles_cache: dict | None = None,
    last_msg_map: dict | None = None,
    unread_map: dict | None = None,
    include_owner: bool = False,
) -> dict:
    to_ids = conv.get("to_ids", [])
    cc_ids = conv.get("cc_ids", [])
    bcc_ids = conv.get("bcc_ids", [])

    # bcc visibility: creator sees all bcc; bcc member sees only themselves; others see none
    is_creator = conv.get("created_by") == current_user_id
    if is_creator:
        visible_bcc_ids = bcc_ids
    elif current_user_id in bcc_ids:
        visible_bcc_ids = [current_user_id]
    else:
        visible_bcc_ids = []

    # legacy conversations without to_ids fall back to participants as "to"
    if not to_ids and not cc_ids and not bcc_ids:
        to_ids = conv.get("participants", [])

    async def hydrate(ids):
        out = []
        for uid in ids:
            u = None
            if users_cache is not None:
                u = users_cache.get(uid)
            if u is None:
                u = await db.users.find_one({"id": uid}, {"_id": 0, "password_hash": 0, "password_visible_enc": 0})
            if u:
                out.append(await serialize_user(u, roles_cache))
        return out

    to_users = await hydrate(to_ids)
    cc_users = await hydrate(cc_ids)
    bcc_users = await hydrate(visible_bcc_ids)

    seen = set()
    visible_participants = []
    for u in to_users + cc_users + bcc_users:
        if u["id"] not in seen:
            seen.add(u["id"])
            visible_participants.append(u)

    if last_msg_map is not None:
        last_msg = last_msg_map.get(conv["id"])
    else:
        last_msg = await db.messages.find_one(
            {"conversation_id": conv["id"]},
            {"_id": 0, "subject": 1, "content": 1, "attachments": 1, "created_at": 1, "sender_id": 1, "signature_doc_id": 1},
            sort=[("created_at", -1)],
        )

    last_preview = None
    last_at = None
    last_signature_doc_id = None
    if last_msg:
        subj = (last_msg.get("subject") or "").strip()
        body = (last_msg.get("content") or "").strip()
        if subj:
            last_preview = subj[:80]
        elif body:
            last_preview = body[:80]
        elif last_msg.get("attachments"):
            last_preview = f"📎 {len(last_msg.get('attachments', []))} attachment(s)"
        last_at = last_msg.get("created_at")
        last_signature_doc_id = last_msg.get("signature_doc_id")

    read_state = conv.get("read_state", {}) or {}
    last_read = read_state.get(current_user_id)

    unread = 0
    if unread_map is not None:
        unread = unread_map.get(conv["id"], 0)
    elif last_msg and (not last_read or last_read < last_msg["created_at"]):
        query = {"conversation_id": conv["id"], "sender_id": {"$ne": current_user_id}}
        if last_read:
            query["created_at"] = {"$gt": last_read}
        unread = await db.messages.count_documents(query)

    # Owner (creator) info — useful for the admin "Super Inbox" view to know whose conversation it is.
    owner_out = None
    if include_owner and conv.get("created_by"):
        owner_doc = None
        if users_cache is not None:
            owner_doc = users_cache.get(conv["created_by"])
        if owner_doc is None:
            owner_doc = await db.users.find_one(
                {"id": conv["created_by"]},
                {"_id": 0, "id": 1, "name": 1, "email": 1},
            )
        if owner_doc:
            owner_out = {
                "id": owner_doc.get("id"),
                "name": owner_doc.get("name"),
                "email": owner_doc.get("email"),
            }

    return {
        "id": conv["id"],
        "type": conv.get("type", "group"),
        "name": conv.get("name"),
        "participants": visible_participants,
        "to": to_users,
        "cc": cc_users,
        "bcc": bcc_users,
        "created_by": conv["created_by"],
        "owner": owner_out,
        "created_at": conv["created_at"],
        "last_message_at": last_at,
        "last_message_preview": last_preview,
        "unread_count": unread,
        "last_read_at": last_read,
        "is_starred": current_user_id in (conv.get("starred_by") or []),
        "is_archived": current_user_id in (conv.get("archived_by") or []),
        "is_trashed": current_user_id in (conv.get("trashed_by") or []),
        "has_sent": current_user_id in (conv.get("senders") or []),
        "last_signature_doc_id": last_signature_doc_id,
    }


@api.get("/conversations")
async def list_conversations(
    folder: str = Query("inbox", pattern="^(inbox|sent|drafts|starred|archive|trash|all)$"),
    as_user_id: Optional[str] = Query(None, description="Admin-only: view conversations from this user's perspective"),
    current=Depends(get_current_user),
):
    caller_perms = await get_role_permissions(current.get("role", "user"))
    is_caller_admin = "users.manage" in caller_perms

    # ---- Resolve "perspective" user (view-as) ----
    if as_user_id and as_user_id != current["id"]:
        if not is_caller_admin:
            raise HTTPException(status_code=403, detail="Admins only")
        target = await db.users.find_one({"id": as_user_id}, {"_id": 0})
        if not target:
            raise HTTPException(status_code=404, detail="Target user not found")
        uid = as_user_id
    else:
        uid = current["id"]

    # ---- 'all' folder = Super Inbox (admin only) ----
    if folder == "all":
        if not is_caller_admin:
            raise HTTPException(status_code=403, detail="Admins only")
        base: dict = {}
    else:
        base = {"participants": uid}
        if folder == "trash":
            base["trashed_by"] = uid
        elif folder == "archive":
            base["archived_by"] = uid
            base["trashed_by"] = {"$ne": uid}
        elif folder == "starred":
            base["starred_by"] = uid
            base["trashed_by"] = {"$ne": uid}
        elif folder == "sent":
            base["senders"] = uid
            base["trashed_by"] = {"$ne": uid}
            base["archived_by"] = {"$ne": uid}
        else:  # inbox
            base["trashed_by"] = {"$ne": uid}
            base["archived_by"] = {"$ne": uid}

    convs = await db.conversations.find(base, {"_id": 0}).to_list(1000 if folder == "all" else 500)
    if not convs:
        return []

    conv_ids = [c["id"] for c in convs]

    # Batch-prefetch: all participant user ids referenced across these conversations
    all_uids: set[str] = set()
    for c in convs:
        for k in ("to_ids", "cc_ids", "bcc_ids", "participants"):
            for x in (c.get(k) or []):
                all_uids.add(x)
        # Owner (creator) also needs to be hydrated for the super-inbox badge
        if c.get("created_by"):
            all_uids.add(c["created_by"])
    user_docs = await db.users.find(
        {"id": {"$in": list(all_uids)}}, {"_id": 0, "password_hash": 0, "password_visible_enc": 0}
    ).to_list(len(all_uids) or 1) if all_uids else []
    users_cache = {u["id"]: u for u in user_docs}

    roles_cache = await _load_roles_cache()

    # Batch-prefetch last message per conversation via aggregation
    last_msg_map: dict = {}
    if conv_ids:
        pipeline = [
            {"$match": {"conversation_id": {"$in": conv_ids}}},
            {"$sort": {"created_at": -1}},
            {"$group": {
                "_id": "$conversation_id",
                "subject": {"$first": "$subject"},
                "content": {"$first": "$content"},
                "attachments": {"$first": "$attachments"},
                "created_at": {"$first": "$created_at"},
                "sender_id": {"$first": "$sender_id"},
                "signature_doc_id": {"$first": "$signature_doc_id"},
            }},
        ]
        async for row in db.messages.aggregate(pipeline):
            last_msg_map[row["_id"]] = {
                "subject": row.get("subject"),
                "content": row.get("content"),
                "attachments": row.get("attachments"),
                "created_at": row.get("created_at"),
                "sender_id": row.get("sender_id"),
                "signature_doc_id": row.get("signature_doc_id"),
            }

    # Batch-prefetch unread counts per conversation in a single aggregation
    unread_map: dict = {}
    if conv_ids:
        read_by_conv = {c["id"]: (c.get("read_state") or {}).get(uid) for c in convs}
        match = {
            "conversation_id": {"$in": conv_ids},
            "sender_id": {"$ne": uid},
        }
        pipeline_u = [
            {"$match": match},
            {"$project": {"_id": 0, "conversation_id": 1, "created_at": 1}},
        ]
        async for row in db.messages.aggregate(pipeline_u):
            cid = row["conversation_id"]
            last_read = read_by_conv.get(cid)
            if last_read and row["created_at"] <= last_read:
                continue
            unread_map[cid] = unread_map.get(cid, 0) + 1

    include_owner = folder == "all"

    out = [
        await _serialize_conversation(
            c,
            uid,
            users_cache=users_cache,
            roles_cache=roles_cache,
            last_msg_map=last_msg_map,
            unread_map=unread_map,
            include_owner=include_owner,
        )
        for c in convs
    ]
    out.sort(key=lambda c: (c.get("last_message_at") or c["created_at"]), reverse=True)
    return out


@api.post("/conversations")
async def create_conversation(payload: ConversationCreateIn, current=Depends(get_current_user)):
    # Admin impersonation: if as_sender_id is set and the caller has users.manage,
    # treat the call as if the chosen user was the author. The caller is *not*
    # added as a participant; the chosen user is.
    actor = current
    if payload.as_sender_id and payload.as_sender_id != current["id"]:
        caller_perms = await get_role_permissions(current["role"])
        if "users.manage" not in caller_perms:
            raise HTTPException(status_code=403, detail="Only admins can send on behalf of other users")
        impersonated = await db.users.find_one({"id": payload.as_sender_id, "is_active": True}, {"_id": 0})
        if not impersonated:
            raise HTTPException(status_code=400, detail="Selected sender does not exist or is disabled")
        actor = impersonated

    perms = await get_role_permissions(actor["role"])

    # resolve emails → user records
    async def resolve(emails):
        emails = [e.lower().strip() for e in emails]
        if not emails:
            return []
        found = await db.users.find(
            {"email": {"$in": emails}},
            {"_id": 0, "id": 1, "email": 1, "is_active": 1},
        ).to_list(1000)
        found_map = {u["email"]: u for u in found}
        missing = [e for e in emails if e not in found_map]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown email address(es): {', '.join(missing)}",
            )
        inactive = [e for e, u in found_map.items() if not u.get("is_active", True)]
        if inactive:
            raise HTTPException(
                status_code=400,
                detail=f"Disabled user(s): {', '.join(inactive)}",
            )
        # preserve input order, dedupe
        seen = set()
        ordered = []
        for e in emails:
            uid = found_map[e]["id"]
            if uid not in seen and uid != actor["id"]:
                seen.add(uid)
                ordered.append(uid)
        return ordered

    to_ids = await resolve(payload.to_emails)
    cc_ids = await resolve(payload.cc_emails)
    bcc_ids = await resolve(payload.bcc_emails)

    # dedupe across fields, preserving precedence: to > cc > bcc
    cc_ids = [i for i in cc_ids if i not in to_ids]
    bcc_ids = [i for i in bcc_ids if i not in to_ids and i not in cc_ids]

    if not to_ids and not cc_ids and not bcc_ids:
        raise HTTPException(status_code=400, detail="Please specify at least one recipient")

    # derive type
    is_direct = len(to_ids) == 1 and not cc_ids and not bcc_ids
    conv_type = "direct" if is_direct else "group"

    # permission check
    if conv_type == "direct" and "conversations.create_direct" not in perms:
        raise HTTPException(status_code=403, detail="You cannot create direct conversations")
    if conv_type == "group" and "conversations.create_group" not in perms:
        raise HTTPException(status_code=403, detail="You cannot create group conversations")

    participants = list(dict.fromkeys([actor["id"]] + to_ids + cc_ids + bcc_ids))

    # dedupe direct conversations (only when truly direct: same 2 participants, no cc/bcc)
    if is_direct:
        existing = await db.conversations.find_one(
            {
                "type": "direct",
                "participants": {"$all": participants, "$size": 2},
                "cc_ids": {"$in": [None, []]},
                "bcc_ids": {"$in": [None, []]},
            },
            {"_id": 0},
        )
        if existing:
            return await _serialize_conversation(existing, actor["id"])

    # auto-name groups if not provided
    name = (payload.name or "").strip() or None
    if conv_type == "group" and not name:
        first_names = []
        for uid in (to_ids + cc_ids)[:3]:
            u = await db.users.find_one({"id": uid}, {"_id": 0, "name": 1})
            if u:
                first_names.append(u["name"].split(" ")[0])
        extra = len(to_ids + cc_ids) - len(first_names)
        suffix = f" +{extra}" if extra > 0 else ""
        name = (", ".join(first_names) + suffix) if first_names else "Group"

    conv = {
        "id": str(uuid.uuid4()),
        "type": conv_type,
        "name": name,
        "participants": participants,
        "to_ids": to_ids,
        "cc_ids": cc_ids,
        "bcc_ids": bcc_ids,
        "created_by": actor["id"],
        # Pre-seed `senders` with the creator so the conversation appears in
        # their Sent folder immediately, even if the initial message creation
        # races/fails. The subsequent $addToSet on each message keeps the list
        # accurate when other participants reply.
        "senders": [actor["id"]],
        "created_at": now_iso(),
        "read_state": {actor["id"]: now_iso()},
    }
    await db.conversations.insert_one(conv)
    conv.pop("_id", None)
    await log_activity(
        user_id=actor["id"], user_email=actor.get("email"), user_name=actor.get("name"),
        action="conversation.created",
        target_type="conversation", target_id=conv["id"],
        details={
            "type": conv_type,
            "name": name,
            "to_count": len(to_ids),
            "cc_count": len(cc_ids),
            "bcc_count": len(bcc_ids),
            "impersonated_by_admin": current["id"] if actor["id"] != current["id"] else None,
        },
    )
    return await _serialize_conversation(conv, actor["id"])


@api.get("/conversations/{conv_id}")
async def get_conversation(
    conv_id: str,
    as_user_id: Optional[str] = Query(None),
    current=Depends(get_current_user),
):
    caller_perms = await get_role_permissions(current.get("role", "user"))
    is_caller_admin = "users.manage" in caller_perms

    # Admins can fetch any conversation; standard users only theirs.
    if is_caller_admin:
        conv = await db.conversations.find_one({"id": conv_id}, {"_id": 0})
    else:
        conv = await db.conversations.find_one({"id": conv_id, "participants": current["id"]}, {"_id": 0})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    # Compute perspective (admin "view-as" mode)
    perspective = current["id"]
    if is_caller_admin and as_user_id:
        perspective = as_user_id
    return await _serialize_conversation(conv, perspective, include_owner=is_caller_admin)


@api.post("/conversations/{conv_id}/read")
async def mark_read(conv_id: str, request: Request, current=Depends(get_current_user)):
    conv = await db.conversations.find_one({"id": conv_id, "participants": current["id"]})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    now = now_iso()
    await db.conversations.update_one(
        {"id": conv_id},
        {"$set": {f"read_state.{current['id']}": now}},
    )
    # Per-message read tracking: mark every message in the conv as read by this user
    # if they haven't read it yet. This gives admins a precise audit later.
    await db.messages.update_many(
        {
            "conversation_id": conv_id,
            "sender_id": {"$ne": current["id"]},
            "read_by": {"$not": {"$elemMatch": {"user_id": current["id"]}}},
        },
        {"$push": {"read_by": {"user_id": current["id"], "at": now}}},
    )
    await log_activity(
        user_id=current["id"], user_email=current.get("email"), user_name=current.get("name"),
        action="conversation.read",
        target_type="conversation", target_id=conv_id,
        request=request,
    )
    return {"ok": True}


# ---- Conversation actions (star / archive / trash) ----
async def _conv_or_404(conv_id: str, user_id: str):
    conv = await db.conversations.find_one({"id": conv_id, "participants": user_id})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


@api.post("/conversations/{conv_id}/star")
async def star_conversation(conv_id: str, current=Depends(get_current_user)):
    await _conv_or_404(conv_id, current["id"])
    await db.conversations.update_one(
        {"id": conv_id}, {"$addToSet": {"starred_by": current["id"]}}
    )
    return {"ok": True}


@api.delete("/conversations/{conv_id}/star")
async def unstar_conversation(conv_id: str, current=Depends(get_current_user)):
    await _conv_or_404(conv_id, current["id"])
    await db.conversations.update_one(
        {"id": conv_id}, {"$pull": {"starred_by": current["id"]}}
    )
    return {"ok": True}


@api.post("/conversations/{conv_id}/archive")
async def archive_conversation(conv_id: str, current=Depends(get_current_user)):
    await _conv_or_404(conv_id, current["id"])
    await db.conversations.update_one(
        {"id": conv_id},
        {
            "$addToSet": {"archived_by": current["id"]},
            "$pull": {"trashed_by": current["id"]},
        },
    )
    return {"ok": True}


@api.delete("/conversations/{conv_id}/archive")
async def unarchive_conversation(conv_id: str, current=Depends(get_current_user)):
    await _conv_or_404(conv_id, current["id"])
    await db.conversations.update_one(
        {"id": conv_id}, {"$pull": {"archived_by": current["id"]}}
    )
    return {"ok": True}


@api.post("/conversations/{conv_id}/trash")
async def trash_conversation(conv_id: str, current=Depends(get_current_user)):
    await _conv_or_404(conv_id, current["id"])
    await db.conversations.update_one(
        {"id": conv_id},
        {
            "$addToSet": {"trashed_by": current["id"]},
            "$pull": {"archived_by": current["id"]},
        },
    )
    return {"ok": True}


@api.delete("/conversations/{conv_id}/trash")
async def untrash_conversation(conv_id: str, current=Depends(get_current_user)):
    await _conv_or_404(conv_id, current["id"])
    await db.conversations.update_one(
        {"id": conv_id}, {"$pull": {"trashed_by": current["id"]}}
    )
    return {"ok": True}


# ---------- Drafts ----------
async def _serialize_draft(d: dict) -> dict:
    attachments = []
    if d.get("attachment_ids"):
        files = await db.files.find(
            {"id": {"$in": d["attachment_ids"]}, "is_deleted": False},
            {"_id": 0},
        ).to_list(50)
        for f in files:
            attachments.append({
                "id": f["id"],
                "original_filename": f["original_filename"],
                "content_type": f["content_type"],
                "size": f["size"],
            })
    return {
        "id": d["id"],
        "to_emails": d.get("to_emails", []),
        "cc_emails": d.get("cc_emails", []),
        "bcc_emails": d.get("bcc_emails", []),
        "subject": d.get("subject", ""),
        "content": d.get("content", ""),
        "content_html": d.get("content_html", ""),
        "attachments": attachments,
        "conversation_id": d.get("conversation_id"),
        "created_at": d["created_at"],
        "updated_at": d["updated_at"],
    }


@api.get("/drafts")
async def list_drafts(current=Depends(get_current_user)):
    docs = await db.drafts.find(
        {"user_id": current["id"]}, {"_id": 0}
    ).sort("updated_at", -1).to_list(200)
    return [await _serialize_draft(d) for d in docs]


@api.post("/drafts")
async def create_draft(payload: DraftIn, current=Depends(get_current_user)):
    now = now_iso()
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": current["id"],
        "to_emails": [e.lower() for e in payload.to_emails],
        "cc_emails": [e.lower() for e in payload.cc_emails],
        "bcc_emails": [e.lower() for e in payload.bcc_emails],
        "subject": (payload.subject or "")[:200],
        "content": payload.content or "",
        "content_html": sanitize_html(payload.content_html or ""),
        "attachment_ids": payload.attachment_ids or [],
        "conversation_id": payload.conversation_id,
        "created_at": now,
        "updated_at": now,
    }
    await db.drafts.insert_one(doc)
    doc.pop("_id", None)
    return await _serialize_draft(doc)


@api.put("/drafts/{draft_id}")
async def update_draft(draft_id: str, payload: DraftIn, current=Depends(get_current_user)):
    existing = await db.drafts.find_one({"id": draft_id, "user_id": current["id"]})
    if not existing:
        raise HTTPException(status_code=404, detail="Draft not found")
    update = {
        "to_emails": [e.lower() for e in payload.to_emails],
        "cc_emails": [e.lower() for e in payload.cc_emails],
        "bcc_emails": [e.lower() for e in payload.bcc_emails],
        "subject": (payload.subject or "")[:200],
        "content": payload.content or "",
        "content_html": sanitize_html(payload.content_html or ""),
        "attachment_ids": payload.attachment_ids or [],
        "conversation_id": payload.conversation_id,
        "updated_at": now_iso(),
    }
    await db.drafts.update_one({"id": draft_id}, {"$set": update})
    doc = await db.drafts.find_one({"id": draft_id}, {"_id": 0})
    return await _serialize_draft(doc)


@api.delete("/drafts/{draft_id}")
async def delete_draft(draft_id: str, current=Depends(get_current_user)):
    res = await db.drafts.delete_one({"id": draft_id, "user_id": current["id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Draft not found")
    return {"ok": True}


# ---------- Folder counts (sidebar) ----------
@api.get("/inbox/folder-counts")
async def folder_counts(current=Depends(get_current_user)):
    uid = current["id"]
    return {
        "drafts": await db.drafts.count_documents({"user_id": uid}),
        "starred": await db.conversations.count_documents(
            {"participants": uid, "starred_by": uid, "trashed_by": {"$ne": uid}}
        ),
        "archive": await db.conversations.count_documents(
            {"participants": uid, "archived_by": uid, "trashed_by": {"$ne": uid}}
        ),
        "trash": await db.conversations.count_documents(
            {"participants": uid, "trashed_by": uid}
        ),
    }



# ---------- Messages ----------
async def _serialize_message(
    msg: dict,
    users_cache: dict | None = None,
    *,
    expose_read_by: bool = False,
) -> dict:
    sender = None
    if users_cache is not None:
        sender = users_cache.get(msg["sender_id"])
    if sender is None:
        sender = await db.users.find_one({"id": msg["sender_id"]}, {"_id": 0, "name": 1, "email": 1})
    sender_name = sender["name"] if sender else "Unknown"
    sender_email = sender.get("email") if sender else None
    attachments = []
    for a in msg.get("attachments", []):
        attachments.append({
            "id": a["id"],
            "original_filename": a["original_filename"],
            "content_type": a["content_type"],
            "size": a["size"],
        })

    # Hydrate read_by with name/email — admin-only data (skip the sender themselves)
    read_by_out: list[dict] = []
    if expose_read_by:
        for r in (msg.get("read_by") or []):
            uid = r.get("user_id")
            if not uid or uid == msg["sender_id"]:
                continue
            u = users_cache.get(uid) if users_cache is not None else None
            if u is None:
                u = await db.users.find_one({"id": uid}, {"_id": 0, "name": 1, "email": 1})
            read_by_out.append({
                "user_id": uid,
                "name": (u or {}).get("name"),
                "email": (u or {}).get("email"),
                "at": r.get("at"),
            })
        read_by_out.sort(key=lambda x: x.get("at") or "")

    return {
        "id": msg["id"],
        "conversation_id": msg["conversation_id"],
        "sender_id": msg["sender_id"],
        "sender_name": sender_name,
        "sender_email": sender_email,
        "subject": msg.get("subject", ""),
        "content": msg.get("content", ""),
        "content_html": msg.get("content_html", ""),
        "attachments": attachments,
        "signature_doc_id": msg.get("signature_doc_id"),
        "created_at": msg["created_at"],
        "read_by": read_by_out,
    }


@api.get("/conversations/{conv_id}/messages")
async def list_messages(
    conv_id: str,
    since: Optional[str] = Query(None, description="ISO timestamp, returns msgs after this"),
    limit: int = 200,
    current=Depends(get_current_user),
):
    caller_perms = await get_role_permissions(current.get("role", "user"))
    is_caller_admin = "users.manage" in caller_perms

    # Admins can read messages from any conversation; standard users only their own.
    if is_caller_admin:
        conv = await db.conversations.find_one({"id": conv_id})
    else:
        conv = await db.conversations.find_one({"id": conv_id, "participants": current["id"]})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    query: dict = {"conversation_id": conv_id}
    if since:
        query["created_at"] = {"$gt": since}
    msgs = await db.messages.find(query, {"_id": 0}).sort("created_at", 1).to_list(limit)

    # Read-receipts (`read_by`) are admin-only — never expose to standard users.
    expose_read_by = is_caller_admin

    # Build a single users cache for senders + all read_by users to avoid N+1
    needed_ids: set[str] = set()
    for m in msgs:
        needed_ids.add(m.get("sender_id"))
        if expose_read_by:
            for r in (m.get("read_by") or []):
                uid = r.get("user_id")
                if uid:
                    needed_ids.add(uid)
    needed_ids.discard(None)
    users_cache: dict = {}
    if needed_ids:
        docs = await db.users.find(
            {"id": {"$in": list(needed_ids)}},
            {"_id": 0, "id": 1, "name": 1, "email": 1},
        ).to_list(len(needed_ids))
        users_cache = {d["id"]: d for d in docs}

    return [
        await _serialize_message(m, users_cache, expose_read_by=expose_read_by)
        for m in msgs
    ]


@api.delete("/messages/{message_id}")
async def admin_delete_message(
    message_id: str,
    request: Request,
    current=Depends(get_current_user),
):
    """Admin-only: physically delete a message from any conversation.
    The message vanishes for every participant instantly. Used for moderation
    (mistakes, leaks, abusive content)."""
    perms = await get_role_permissions(current.get("role", "user"))
    if "users.manage" not in perms:
        raise HTTPException(status_code=403, detail="Admins only")
    msg = await db.messages.find_one({"id": message_id}, {"_id": 0})
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    await db.messages.delete_one({"id": message_id})

    # Refresh the parent conversation's last_message_at so it reflects reality
    # after the deletion (admin might have nuked the latest message).
    latest = await db.messages.find_one(
        {"conversation_id": msg["conversation_id"]},
        {"_id": 0, "created_at": 1},
        sort=[("created_at", -1)],
    )
    if latest:
        await db.conversations.update_one(
            {"id": msg["conversation_id"]},
            {"$set": {"last_message_at": latest["created_at"]}},
        )
    else:
        await db.conversations.update_one(
            {"id": msg["conversation_id"]},
            {"$unset": {"last_message_at": ""}},
        )

    await log_activity(
        user_id=current["id"], user_email=current.get("email"), user_name=current.get("name"),
        action="message.deleted_by_admin",
        target_type="message", target_id=message_id,
        details={
            "conversation_id": msg["conversation_id"],
            "original_sender_id": msg.get("sender_id"),
            "subject": (msg.get("subject") or "")[:140],
            "preview": (msg.get("content") or "")[:140],
        },
        request=request,
    )
    return {"ok": True, "deleted_id": message_id}


@api.post("/conversations/{conv_id}/messages")
async def send_message(
    conv_id: str,
    payload: MessageCreateIn,
    request: Request,
    current=Depends(get_current_user),
):
    # Admin impersonation (same semantics as in create_conversation)
    actor = current
    if payload.as_sender_id and payload.as_sender_id != current["id"]:
        caller_perms = await get_role_permissions(current["role"])
        if "users.manage" not in caller_perms:
            raise HTTPException(status_code=403, detail="Only admins can send on behalf of other users")
        impersonated = await db.users.find_one({"id": payload.as_sender_id, "is_active": True}, {"_id": 0})
        if not impersonated:
            raise HTTPException(status_code=400, detail="Selected sender does not exist or is disabled")
        actor = impersonated

    perms = await get_role_permissions(actor["role"])
    if "messages.send" not in perms:
        raise HTTPException(status_code=403, detail="You cannot send messages")

    conv = await db.conversations.find_one({"id": conv_id, "participants": actor["id"]})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    content = (payload.content or "").strip()
    sanitized_html = sanitize_html(payload.content_html or "")
    # If HTML present and text content empty, derive plain text from HTML for fallback / preview
    if sanitized_html and not content:
        content = html_to_text(sanitized_html)
    attachments = []
    if payload.attachment_ids:
        if "messages.send_attachments" not in perms:
            raise HTTPException(status_code=403, detail="You cannot send attachments")
        for fid in payload.attachment_ids:
            f = await db.files.find_one(
                {"id": fid, "uploaded_by": actor["id"], "is_deleted": False},
                {"_id": 0},
            )
            if not f:
                raise HTTPException(status_code=400, detail=f"Attachment not found: {fid}")
            attachments.append({
                "id": f["id"],
                "original_filename": f["original_filename"],
                "content_type": f["content_type"],
                "size": f["size"],
                "storage_path": f["storage_path"],
            })

    if not content and not attachments:
        raise HTTPException(status_code=400, detail="Empty message")

    msg = {
        "id": str(uuid.uuid4()),
        "conversation_id": conv_id,
        "sender_id": actor["id"],
        "subject": (payload.subject or "").strip()[:200],
        "content": content,
        "content_html": sanitized_html,
        "attachments": attachments,
        "created_at": now_iso(),
    }
    await db.messages.insert_one(msg)
    msg.pop("_id", None)
    # mark sender as read + record they sent + untrash/unarchive for sender
    await db.conversations.update_one(
        {"id": conv_id},
        {
            "$set": {f"read_state.{actor['id']}": msg["created_at"]},
            "$addToSet": {"senders": actor["id"]},
            "$pull": {"trashed_by": actor["id"], "archived_by": actor["id"]},
        },
    )
    await log_activity(
        user_id=actor["id"], user_email=actor.get("email"), user_name=actor.get("name"),
        action="message.sent",
        target_type="conversation", target_id=conv_id,
        details={
            "message_id": msg["id"],
            "subject": msg.get("subject", "")[:140],
            "preview": (msg.get("content") or "")[:140],
            "impersonated_by_admin": current["id"] if actor["id"] != current["id"] else None,
        },
        request=request,
    )

    # External email notification (admin-triggered only) — fire-and-forget so the
    # API response is not blocked by Resend latency. The notification informs
    # the recipient on their REAL email address that they have a new in-platform
    # message. Standard users sending messages do NOT trigger this.
    sender_caller_perms = await get_role_permissions(current.get("role", "user"))
    if "users.manage" in sender_caller_perms:
        origin = (request.headers.get("origin") or "").strip().rstrip("/")
        if not origin.startswith("https://"):
            origin = (os.environ.get("FRONTEND_URL") or "").rstrip("/")
        app_url = f"{origin}/app/inbox" if origin else "/app/inbox"
        sender_display = actor.get("name") or actor.get("email") or "A teammate"
        asyncio.create_task(
            _send_external_message_notifications(
                conv=conv,
                actor_id=actor["id"],
                sender_display=sender_display,
                app_url=app_url,
            )
        )

    return await _serialize_message(msg)


async def _send_external_message_notifications(
    *,
    conv: dict,
    actor_id: str,
    sender_display: str,
    app_url: str,
) -> None:
    """Background task: notify every non-sender conversation participant by
    email that they have a new message on the platform. Best-effort, never
    raises. The email is a teaser only — no message content is included."""
    try:
        recipient_ids = [
            p for p in (conv.get("participants") or [])
            if p and p != actor_id
        ]
        if not recipient_ids:
            return
        users = await db.users.find(
            {
                "id": {"$in": recipient_ids},
                "is_active": True,
                # Only users whose admin has explicitly opted them in receive
                # an external email alert when a new internal message
                # arrives. Default is OFF.
                "email_notifications_enabled": True,
            },
            {"_id": 0, "id": 1, "email": 1, "name": 1},
        ).to_list(50)
        for u in users:
            email = (u.get("email") or "").strip()
            if not email:
                continue
            await send_new_message_notification(
                recipient_email=email,
                recipient_name=u.get("name") or "",
                sender_name=sender_display,
                app_url=app_url,
            )
    except Exception as e:  # noqa: BLE001
        logger.warning("external-message-notif task failed: %s", e)


# ---------- Files ----------
@api.post("/files/upload")
async def upload_file(file: UploadFile = File(...), current=Depends(get_current_user)):
    perms = await get_role_permissions(current["role"])
    if "messages.send_attachments" not in perms:
        raise HTTPException(status_code=403, detail="You cannot upload attachments")

    content_type = file.content_type or "application/octet-stream"
    if not any(content_type.startswith(p) for p in ALLOWED_MIME_PREFIXES):
        raise HTTPException(status_code=400, detail=f"File type not allowed: {content_type}")

    data = await file.read()
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (max 15 MB)")

    ext = file.filename.split(".")[-1].lower() if file.filename and "." in file.filename else "bin"
    safe_ext = "".join(c for c in ext if c.isalnum())[:8] or "bin"
    file_uuid = str(uuid.uuid4())
    storage_path = f"{APP_NAME}/uploads/{current['id']}/{file_uuid}.{safe_ext}"

    try:
        result = put_object(storage_path, data, content_type)
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")

    rec = {
        "id": file_uuid,
        "storage_path": result["path"],
        "original_filename": file.filename or f"file.{safe_ext}",
        "content_type": content_type,
        "size": result.get("size", len(data)),
        "uploaded_by": current["id"],
        "is_deleted": False,
        "created_at": now_iso(),
    }
    await db.files.insert_one(rec)
    await log_activity(
        user_id=current["id"], user_email=current.get("email"), user_name=current.get("name"),
        action="file.uploaded",
        target_type="file", target_id=rec["id"],
        details={
            "filename": rec["original_filename"][:140],
            "content_type": content_type,
            "size_bytes": rec["size"],
        },
    )
    return {
        "id": rec["id"],
        "original_filename": rec["original_filename"],
        "content_type": rec["content_type"],
        "size": rec["size"],
    }


@api.get("/files/{file_id}")
async def download_file(
    file_id: str,
    request: Request,
    auth: Optional[str] = Query(None),
):
    # auth via cookie or query token (for img tags)
    token = extract_token(request) or auth
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = payload.get("sub")
    user = await db.users.find_one({"id": user_id})
    if not user or not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="User not found")

    rec = await db.files.find_one({"id": file_id, "is_deleted": False}, {"_id": 0})
    if not rec:
        raise HTTPException(status_code=404, detail="File not found")

    # access control: must be uploader, participant in a conv where the file was sent,
    # or a signer (or the creator) on a signature document referencing this file.
    if rec["uploaded_by"] != user_id:
        msg = await db.messages.find_one({"attachments.id": file_id}, {"_id": 0, "conversation_id": 1})
        if msg:
            conv = await db.conversations.find_one({"id": msg["conversation_id"], "participants": user_id})
            if conv:
                pass  # OK — participant in the conversation
            else:
                raise HTTPException(status_code=403, detail="Forbidden")
        else:
            email = (user.get("email") or "").lower()
            sig_docs = await db.signature_docs.find(
                {
                    "$or": [
                        {"original_file_id": file_id},
                        {"signed_file_id": file_id},
                        {"fields.value_file_id": file_id},
                    ]
                },
                {"_id": 0, "created_by": 1, "signers": 1},
            ).to_list(50)
            if not sig_docs:
                raise HTTPException(status_code=403, detail="Forbidden")
            # Allow access if ANY referencing doc grants the user creator/signer rights
            allowed = False
            for sd in sig_docs:
                if sd.get("created_by") == user_id:
                    allowed = True
                    break
                for s in sd.get("signers", []):
                    if s.get("user_id") == user_id or (s.get("email") or "").lower() == email:
                        allowed = True
                        break
                if allowed:
                    break
            if not allowed:
                raise HTTPException(status_code=403, detail="Forbidden")

    data: bytes = b""
    ct: str = "application/octet-stream"
    try:
        data, ct = get_object(rec["storage_path"])
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise HTTPException(status_code=500, detail="Download failed")

    headers = {
        "Content-Disposition": f'inline; filename="{rec["original_filename"]}"',
        "Cache-Control": "private, max-age=300",
    }
    return Response(content=data, media_type=rec.get("content_type", ct), headers=headers)


# ---------- Message templates (admin-managed, all users can read) ----------
async def _serialize_template(doc: dict) -> dict:
    """Build the public payload from a stored template doc, looking up the
    creator name for display in the admin UI."""
    creator_name = None
    if doc.get("created_by"):
        u = await db.users.find_one({"id": doc["created_by"]}, {"_id": 0, "name": 1})
        if u:
            creator_name = u.get("name")
    return {
        "id": doc["id"],
        "name": doc.get("name", ""),
        "description": doc.get("description"),
        "variants": doc.get("variants") or [],
        "created_by": doc.get("created_by"),
        "created_by_name": creator_name,
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
        "usage_count": int(doc.get("usage_count") or 0),
    }


def _normalize_variants(variants_in) -> List[dict]:
    """Assign a stable id to each variant so the client can reference them
    by id when picking which one to insert."""
    out = []
    for v in variants_in:
        data = v.model_dump() if hasattr(v, "model_dump") else dict(v)
        data["id"] = data.get("id") or str(uuid.uuid4())
        out.append({"id": data["id"], "label": data["label"], "body_html": data["body_html"]})
    return out


@api.get("/templates")
async def list_templates(_=Depends(get_current_user)):
    """All authenticated users can browse the catalogue (admin manages
    write access). Sorted by most-used first then name to surface the
    workhorses."""
    docs = await db.message_templates.find({}, {"_id": 0}).sort([("usage_count", -1), ("name", 1)]).to_list(500)
    return [await _serialize_template(d) for d in docs]


@api.post("/templates")
async def create_template(payload: MessageTemplateCreateIn, current=Depends(require_permission("users.manage"))):
    doc = {
        "id": str(uuid.uuid4()),
        "name": payload.name.strip(),
        "description": (payload.description or "").strip() or None,
        "variants": _normalize_variants(payload.variants),
        "created_by": current["id"],
        "created_at": now_iso(),
        "updated_at": None,
        "usage_count": 0,
    }
    await db.message_templates.insert_one(doc)
    return await _serialize_template(doc)


@api.patch("/templates/{tpl_id}")
async def update_template(
    tpl_id: str,
    payload: MessageTemplateUpdateIn,
    _=Depends(require_permission("users.manage")),
):
    existing = await db.message_templates.find_one({"id": tpl_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Template not found")
    update: dict = {}
    if payload.name is not None:
        update["name"] = payload.name.strip()
    if payload.description is not None:
        update["description"] = payload.description.strip() or None
    if payload.variants is not None:
        update["variants"] = _normalize_variants(payload.variants)
    if update:
        update["updated_at"] = now_iso()
        await db.message_templates.update_one({"id": tpl_id}, {"$set": update})
    doc = await db.message_templates.find_one({"id": tpl_id}, {"_id": 0})
    return await _serialize_template(doc)


@api.delete("/templates/{tpl_id}")
async def delete_template(tpl_id: str, _=Depends(require_permission("users.manage"))):
    res = await db.message_templates.delete_one({"id": tpl_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Template not found")
    return {"ok": True}


@api.post("/templates/{tpl_id}/used")
async def mark_template_used(tpl_id: str, _=Depends(get_current_user)):
    """Bump the usage counter when a user actually inserts a template into
    a draft / message. Idempotent and cheap; failure is non-fatal so the
    compose UX never blocks on it."""
    try:
        await db.message_templates.update_one(
            {"id": tpl_id},
            {"$inc": {"usage_count": 1}},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("mark_template_used failed for %s: %s", tpl_id, exc)
    return {"ok": True}


# ---------- Invite codes (admin) ----------
async def _serialize_invite(inv: dict) -> dict:
    creator = await db.users.find_one({"id": inv.get("created_by")}, {"_id": 0, "name": 1})
    used_by_user = None
    if inv.get("used_by"):
        u = await db.users.find_one({"id": inv["used_by"]}, {"_id": 0, "email": 1})
        used_by_user = u.get("email") if u else None
    return {
        "id": inv["id"],
        "code": inv["code"],
        "created_by": inv.get("created_by"),
        "created_by_name": creator.get("name") if creator else None,
        "used": inv.get("used", False),
        "used_by": inv.get("used_by"),
        "used_by_email": used_by_user,
        "used_at": inv.get("used_at"),
        "created_at": inv["created_at"],
        "expires_at": inv["expires_at"],
    }


@api.get("/invite-codes")
async def list_invites(_=Depends(require_permission("users.manage"))):
    docs = await db.invite_codes.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return [await _serialize_invite(d) for d in docs]


@api.post("/invite-codes")
async def create_invite(current=Depends(require_permission("users.manage"))):
    now = datetime.now(timezone.utc)
    inv = {
        "id": str(uuid.uuid4()),
        "code": generate_invite_code(),
        "created_by": current["id"],
        "used": False,
        "used_by": None,
        "used_at": None,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=INVITE_CODE_TTL_DAYS)).isoformat(),
    }
    # ensure uniqueness
    for _ in range(5):
        if not await db.invite_codes.find_one({"code": inv["code"]}):
            break
        inv["code"] = generate_invite_code()
    await db.invite_codes.insert_one(inv)
    return await _serialize_invite(inv)


@api.delete("/invite-codes/{invite_id}")
async def delete_invite(invite_id: str, _=Depends(require_permission("users.manage"))):
    res = await db.invite_codes.delete_one({"id": invite_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Code not found")
    return {"ok": True}


@api.post("/invite-codes/{invite_id}/email")
async def email_invite(
    invite_id: str,
    payload: InviteEmailIn,
    request: Request,
    current=Depends(require_permission("users.manage")),
):
    """Send the invitation code by email to the recipient via Resend."""
    inv = await db.invite_codes.find_one({"id": invite_id}, {"_id": 0})
    if not inv:
        raise HTTPException(status_code=404, detail="Code not found")
    if inv.get("used"):
        raise HTTPException(status_code=400, detail="This invitation code has already been used")
    try:
        if datetime.fromisoformat(inv["expires_at"]) < datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="This invitation code has expired")
    except (ValueError, TypeError):
        pass

    # Build the registration URL. Use the centralized helper so all email
    # links (invitations + password reset + future emails) point to the same
    # origin — controlled by the FRONTEND_URL env var when set.
    origin = _origin_from_request(request)
    register_url = f"{origin}/register?code={inv['code']}" if origin else f"/register?code={inv['code']}"

    # Format expiry date for the email body (e.g. "May 21, 2026")
    try:
        expires_label = datetime.fromisoformat(inv["expires_at"]).strftime("%B %d, %Y")
    except (ValueError, TypeError):
        expires_label = inv["expires_at"]

    ok = await send_invitation_email(
        recipient_email=payload.recipient_email,
        recipient_name=(payload.recipient_name or "").strip(),
        code=inv["code"],
        register_url=register_url,
        inviter_name=current.get("name", ""),
        expires_at=expires_label,
    )
    if not ok:
        raise HTTPException(
            status_code=502,
            detail="Failed to send email. Check the RESEND_API_KEY configuration.",
        )
    return {"ok": True, "recipient": payload.recipient_email}


# ---------- Presence ----------
PRESENCE_ONLINE_SECONDS = 30


def _is_online(last_seen_at: Optional[str]) -> bool:
    if not last_seen_at:
        return False
    try:
        ts = datetime.fromisoformat(last_seen_at)
    except (ValueError, TypeError):
        return False
    delta = (datetime.now(timezone.utc) - ts).total_seconds()
    return 0 <= delta < PRESENCE_ONLINE_SECONDS


@api.post("/presence/heartbeat")
async def presence_heartbeat(payload: dict | None = None, current=Depends(get_current_user)):
    """Update last_seen_at + current_path + current_context for the user.
    The optional `context` payload carries fine-grained info about what the
    user is doing right now (reading conv X, composing Y, signing doc Z, …)
    so admins can mirror the user's activity from the dashboard."""
    now = now_iso()
    update = {"last_seen_at": now}
    if payload and isinstance(payload, dict):
        path = (payload.get("path") or "").strip()[:120]
        if path:
            update["current_path"] = path
        ctx = payload.get("context")
        if isinstance(ctx, dict):
            # Whitelist + length-cap each field to avoid abuse
            update["current_context"] = {
                "type": (ctx.get("type") or "")[:40] or None,
                "id": (ctx.get("id") or "")[:64] or None,
                "title": (ctx.get("title") or "")[:200] or None,
                "meta": ctx.get("meta") if isinstance(ctx.get("meta"), dict) else None,
                "at": now,
            }
        elif ctx is None and "context" in payload:
            # Explicit null → clear context (user left the focused activity)
            update["current_context"] = None
    await db.users.update_one({"id": current["id"]}, {"$set": update})
    return {"ok": True, "last_seen_at": now}


# ---------- Live screen mirror (admin observability) ----------
# Max payload size: ~600KB base64 (~450KB binary). Anything larger is rejected
# to avoid bloating MongoDB and slowing down inserts. The frontend downscales
# and JPEG-compresses before sending so typical payloads are 30-150KB.
MAX_SCREEN_B64 = 600_000


@api.post("/presence/screen")
async def presence_screen(payload: dict, current=Depends(get_current_user)):
    """Store a snapshot of the user's current viewport. Called by the client
    every ~2s while the tab is visible. Admins see the freshest capture in
    near-real-time (1s polling) in the live activity drawer.

    Two modes:
    - Full upload: `{ image, hash, path }` — stores the new frame and hash.
    - Touch only: `{ hash, path, touch: true }` — when the client detected the
      DOM has not changed visually (same JPEG bytes → same hash). Only the
      `captured_at` and `expires_at` fields are refreshed; the heavy image
      payload stays in MongoDB unchanged. If the server's stored hash does
      not match (e.g. doc expired or hash drifted), responds 409 so the
      client resends the full image on its next tick.

    Captures older than 48 hours are auto-purged by the TTL index on
    `expires_at` (see startup hook below).
    """
    payload = payload or {}
    path = (payload.get("path") or "").strip()[:120] or None
    hash_val = payload.get("hash")
    if isinstance(hash_val, str):
        hash_val = hash_val[:64] or None
    else:
        hash_val = None
    now_dt = datetime.now(timezone.utc)
    expires_dt = now_dt + timedelta(hours=48)

    # ---- Touch-only path: skip the heavy image write ----
    if payload.get("touch"):
        if not hash_val:
            raise HTTPException(status_code=400, detail="Missing hash for touch")
        existing = await db.user_screens.find_one(
            {"user_id": current["id"]},
            {"_id": 0, "hash": 1},
        )
        if not existing or existing.get("hash") != hash_val:
            # Client and server are out of sync → ask for a full upload.
            return JSONResponse(status_code=409, content={"resend": True})
        await db.user_screens.update_one(
            {"user_id": current["id"]},
            {"$set": {
                "captured_at": now_dt.isoformat(),
                "expires_at": expires_dt,
                "path": path,
            }},
        )
        return {"ok": True, "captured_at": now_dt.isoformat(), "touched": True}

    # ---- Full upload path ----
    image = payload.get("image", "")
    if not isinstance(image, str) or not image.startswith("data:image/"):
        raise HTTPException(status_code=400, detail="Invalid image payload")
    if len(image) > MAX_SCREEN_B64:
        raise HTTPException(status_code=413, detail="Screenshot too large")
    await db.user_screens.update_one(
        {"user_id": current["id"]},
        {"$set": {
            "user_id": current["id"],
            "image_b64": image,
            "hash": hash_val,
            "captured_at": now_dt.isoformat(),
            "expires_at": expires_dt,  # Date type for TTL index
            "path": path,
        }},
        upsert=True,
    )
    return {"ok": True, "captured_at": now_dt.isoformat(), "touched": False}


@api.get("/admin/users/{user_id}/screen")
async def admin_user_screen(
    user_id: str,
    _=Depends(require_permission("users.manage")),
):
    """Return the latest live screen capture for the target user, or 204 if
    no capture is available yet."""
    doc = await db.user_screens.find_one(
        {"user_id": user_id},
        {"_id": 0, "expires_at": 0},  # expires_at is for internal TTL only
    )
    if not doc:
        return JSONResponse(status_code=204, content=None)
    return doc


@api.get("/presence")
async def presence_list(_=Depends(get_current_user)):
    """Return online state for all users (id, online, last_seen_at)."""
    docs = await db.users.find({}, {"_id": 0, "id": 1, "last_seen_at": 1}).to_list(2000)
    return [
        {"id": d["id"], "online": _is_online(d.get("last_seen_at")), "last_seen_at": d.get("last_seen_at")}
        for d in docs
    ]


# ---------- Signature documents ----------
SIGNER_COLORS = ["#2563eb", "#dc2626", "#16a34a", "#ca8a04", "#7c3aed", "#0891b2", "#db2777", "#65a30d"]


async def _serialize_signature_doc(
    doc: dict,
    *,
    current_user_id: Optional[str] = None,
    is_admin: bool = False,
) -> dict:
    creator = await db.users.find_one({"id": doc.get("created_by")}, {"_id": 0, "name": 1})

    # Auto-migrate legacy docs (created before the field-based flow): give each
    # pending signer a default signature field on the bottom-right of the last
    # page so the new UI can render and submit them seamlessly.
    if not doc.get("fields"):
        try:
            file_rec = await db.files.find_one({"id": doc.get("original_file_id")}, {"_id": 0, "storage_path": 1})
            page_count = 1
            if file_rec:
                try:
                    from pypdf import PdfReader as _PdfReader
                    import io as _io
                    pdf_bytes, _ = get_object(file_rec["storage_path"])
                    page_count = max(1, len(_PdfReader(_io.BytesIO(pdf_bytes)).pages))
                except Exception:  # noqa: BLE001
                    page_count = 1
            new_fields = []
            for i, s in enumerate(doc.get("signers", [])):
                if s.get("status") == "signed":
                    continue
                new_fields.append({
                    "id": str(uuid.uuid4()),
                    "type": "signature",
                    "page": page_count - 1,
                    "x": 0.55,
                    "y": 0.80 + (i * 0.05),
                    "w": 0.30,
                    "h": 0.06,
                    "signer_email": s.get("email"),
                    "required": True,
                    "placeholder": None,
                    "filled": False,
                    "filled_at": None,
                    "value_text": None,
                    "value_bool": None,
                    "value_file_id": None,
                })
            if new_fields:
                await db.signature_docs.update_one(
                    {"id": doc["id"]},
                    {"$set": {"fields": new_fields}},
                )
                doc["fields"] = new_fields
        except Exception as e:  # noqa: BLE001
            logger.warning("Legacy signature doc migration failed for %s: %s", doc.get("id"), e)

    signers_out = []
    for s in doc.get("signers", []):
        signers_out.append({
            "user_id": s.get("user_id"),
            "email": s.get("email"),
            "name": s.get("name"),
            "color": s.get("color"),
            "status": s.get("status", "pending"),
            "signed_at": s.get("signed_at"),
        })
    fields_out = []
    for f in doc.get("fields", []):
        fields_out.append({
            "id": f.get("id"),
            "type": f.get("type"),
            "page": int(f.get("page", 0)),
            "x": float(f.get("x", 0)),
            "y": float(f.get("y", 0)),
            "w": float(f.get("w", 0)),
            "h": float(f.get("h", 0)),
            "signer_email": f.get("signer_email", "").lower(),
            "required": bool(f.get("required", True)),
            "placeholder": f.get("placeholder"),
            "filled": bool(f.get("filled", False)),
            "filled_at": f.get("filled_at"),
            "value_text": f.get("value_text"),
            "value_bool": f.get("value_bool"),
            "value_file_id": f.get("value_file_id"),
        })
    # CC / BCC informational recipients (admin-only feature).
    # Visibility rules (mirrors email semantics):
    #   - creator + admin: see all CC + BCC
    #   - signers / CC: see CC only (no BCC)
    #   - BCC recipients: see only their own BCC entry
    #   - everyone else: nothing
    is_creator = current_user_id and current_user_id == doc.get("created_by")
    cc_raw = list(doc.get("cc") or [])
    bcc_raw = list(doc.get("bcc") or [])
    cc_out = [{
        "user_id": c.get("user_id"),
        "email": c.get("email"),
        "name": c.get("name"),
    } for c in cc_raw]
    if is_creator or is_admin:
        bcc_out = [{
            "user_id": c.get("user_id"),
            "email": c.get("email"),
            "name": c.get("name"),
        } for c in bcc_raw]
    elif current_user_id:
        bcc_out = [
            {"user_id": c.get("user_id"), "email": c.get("email"), "name": c.get("name")}
            for c in bcc_raw if c.get("user_id") == current_user_id
        ]
    else:
        bcc_out = []

    return {
        "id": doc["id"],
        "title": doc.get("title", ""),
        "message": doc.get("message", ""),
        "original_file_id": doc.get("original_file_id"),
        "signed_file_id": doc.get("signed_file_id"),
        "created_by": doc.get("created_by"),
        "created_by_name": creator.get("name") if creator else None,
        "signers": signers_out,
        "fields": fields_out,
        "cc": cc_out,
        "bcc": bcc_out,
        "status": doc.get("status", "pending"),
        "created_at": doc.get("created_at"),
        "completed_at": doc.get("completed_at"),
    }


@api.post("/signature-docs")
async def create_signature_doc(
    payload: SignatureDocCreateIn,
    current=Depends(get_current_user),
):
    """Create a DocuSign-style signature request with positioned fields."""
    # Admin impersonation: send the request as another user (same semantics as
    # ConversationCreateIn.as_sender_id). The PDF must have been uploaded by
    # the IMPERSONATED user, not the admin, so that file ownership checks pass.
    actor = current
    if payload.as_sender_id and payload.as_sender_id != current["id"]:
        caller_perms = await get_role_permissions(current["role"])
        if "users.manage" not in caller_perms:
            raise HTTPException(status_code=403, detail="Only admins can send on behalf of other users")
        impersonated = await db.users.find_one({"id": payload.as_sender_id, "is_active": True}, {"_id": 0})
        if not impersonated:
            raise HTTPException(status_code=400, detail="Selected sender does not exist or is disabled")
        actor = impersonated

    file_rec = await db.files.find_one({"id": payload.file_id, "is_deleted": False}, {"_id": 0})
    if not file_rec:
        raise HTTPException(status_code=404, detail="PDF file not found")
    if file_rec.get("content_type") != "application/pdf":
        raise HTTPException(status_code=400, detail="File must be a PDF")
    # When impersonating, we accept either: (a) the impersonated user uploaded the
    # file, or (b) the calling admin uploaded it (since the admin is allowed to
    # use any PDF they themselves uploaded as the source).
    if file_rec.get("uploaded_by") not in {actor["id"], current["id"]}:
        raise HTTPException(status_code=403, detail="You can only request signatures on PDFs you uploaded")

    # Resolve signers + assign colours
    signers_db = []
    seen_emails = set()
    for s in payload.signers:
        email = s.email.lower().strip()
        if email in seen_emails:
            continue
        seen_emails.add(email)
        u = await db.users.find_one({"email": email}, {"_id": 0, "id": 1, "name": 1})
        signers_db.append({
            "user_id": u["id"] if u else None,
            "email": email,
            "name": s.name or (u["name"] if u else email.split("@")[0]),
            "color": SIGNER_COLORS[len(signers_db) % len(SIGNER_COLORS)],
            "status": "pending",
            "signed_at": None,
        })

    if not signers_db:
        raise HTTPException(status_code=400, detail="At least one signer is required")

    # CC / BCC: informational recipients — admin-only. They receive a notification
    # in their Inbox but cannot open the PDF (access-control on /api/files unchanged).
    cc_db: list[dict] = []
    bcc_db: list[dict] = []
    if payload.cc_emails or payload.bcc_emails:
        caller_perms = await get_role_permissions(current["role"])
        if "users.manage" not in caller_perms:
            raise HTTPException(
                status_code=403,
                detail="Only admins can add CC / BCC recipients to a signature request",
            )

        async def _resolve_recipients(emails: list[str], exclude: set[str]) -> list[dict]:
            out: list[dict] = []
            seen: set[str] = set()
            for raw in emails:
                email = raw.lower().strip()
                if not email or email in seen or email in exclude:
                    continue
                seen.add(email)
                u = await db.users.find_one({"email": email}, {"_id": 0, "id": 1, "name": 1})
                out.append({
                    "user_id": u["id"] if u else None,
                    "email": email,
                    "name": (u["name"] if u else None),
                })
            return out

        signer_emails_set = {s["email"] for s in signers_db}
        cc_db = await _resolve_recipients(payload.cc_emails, signer_emails_set)
        # BCC excludes CC + signers
        bcc_exclude = signer_emails_set | {c["email"] for c in cc_db}
        bcc_db = await _resolve_recipients(payload.bcc_emails, bcc_exclude)

    # Validate fields: every field must reference a known signer email
    signer_emails = {s["email"] for s in signers_db}
    fields_db = []
    for f in payload.fields:
        femail = f.signer_email.lower().strip()
        if femail not in signer_emails:
            raise HTTPException(status_code=400, detail=f"Field references unknown signer {femail}")
        fields_db.append({
            "id": f.id or str(uuid.uuid4()),
            "type": f.type,
            "page": int(f.page),
            "x": float(f.x),
            "y": float(f.y),
            "w": float(f.w),
            "h": float(f.h),
            "signer_email": femail,
            "required": bool(f.required),
            "placeholder": (f.placeholder or "")[:80] if f.placeholder else None,
            "filled": False,
            "filled_at": None,
            "value_text": None,
            "value_bool": None,
            "value_file_id": None,
        })

    doc = {
        "id": str(uuid.uuid4()),
        "title": payload.title.strip()[:200],
        "message": (payload.message or "").strip()[:2000],
        "original_file_id": payload.file_id,
        "signed_file_id": None,
        "created_by": actor["id"],
        "signers": signers_db,
        "fields": fields_db,
        "cc": cc_db,
        "bcc": bcc_db,
        "audit_log": [],
        "status": "pending",
        "created_at": now_iso(),
        "completed_at": None,
    }
    await db.signature_docs.insert_one(doc)

    # Notify each registered signer with a message in their inbox
    await _notify_signers_on_create(doc, actor)
    # Notify CC / BCC recipients with an informational message (no PDF link)
    await _notify_informational_recipients(doc, actor)
    await log_activity(
        user_id=actor["id"], user_email=actor.get("email"), user_name=actor.get("name"),
        action="signature.created",
        target_type="signature_doc", target_id=doc["id"],
        details={
            "title": doc.get("title", "")[:140],
            "signers": [s.get("email") for s in doc.get("signers", [])],
            "cc": [c.get("email") for c in doc.get("cc", [])],
            "bcc": [c.get("email") for c in doc.get("bcc", [])],
            "fields_count": len(doc.get("fields", [])),
            "impersonated_by_admin": current["id"] if actor["id"] != current["id"] else None,
        },
    )

    caller_perms_final = await get_role_permissions(current.get("role", "user"))
    is_admin_caller = "users.manage" in caller_perms_final
    return await _serialize_signature_doc(
        doc,
        current_user_id=current["id"],
        is_admin=is_admin_caller,
    )


async def _notify_signers_on_create(doc: dict, creator: dict) -> None:
    """Create / reuse a direct conversation between the creator and each signer
    that is a registered user, and post a notification message linking to the
    Documents page."""
    try:
        sender_name = creator.get("name") or creator.get("email") or "Someone"
        for s in doc.get("signers", []):
            signer_uid = s.get("user_id")
            if not signer_uid or signer_uid == creator["id"]:
                continue

            participants = [creator["id"], signer_uid]
            existing = await db.conversations.find_one(
                {
                    "type": "direct",
                    "participants": {"$all": participants, "$size": 2},
                    "cc_ids": {"$in": [None, []]},
                    "bcc_ids": {"$in": [None, []]},
                },
                {"_id": 0},
            )
            if existing:
                conv_id = existing["id"]
            else:
                conv_id = str(uuid.uuid4())
                await db.conversations.insert_one({
                    "id": conv_id,
                    "type": "direct",
                    "name": None,
                    "participants": participants,
                    "to_ids": [signer_uid],
                    "cc_ids": [],
                    "bcc_ids": [],
                    "created_by": creator["id"],
                    "senders": [creator["id"]],
                    "created_at": now_iso(),
                    "read_state": {creator["id"]: now_iso()},
                })

            title_safe = (doc.get("title") or "").replace("<", "&lt;").replace(">", "&gt;")
            note_safe = (doc.get("message") or "").replace("<", "&lt;").replace(">", "&gt;")
            note_block = f"<p style=\"color:#52525b;font-style:italic\">&ldquo;{note_safe}&rdquo;</p>" if note_safe else ""
            content_html = (
                f"<p>{sender_name} sent you a document to sign:</p>"
                f"<p><strong>📝 {title_safe}</strong></p>"
                f"{note_block}"
                f"<p><a href=\"/app/documents\" data-skadd-action=\"sign-doc\" data-doc-id=\"{doc['id']}\">"
                f"Open Documents to review and sign →</a></p>"
            )
            plain = f"{sender_name} sent you a document to sign: {doc.get('title','')}"

            msg = {
                "id": str(uuid.uuid4()),
                "conversation_id": conv_id,
                "sender_id": creator["id"],
                "subject": f"Document to sign: {doc.get('title','')[:140]}",
                "content": plain,
                "content_html": content_html,
                "attachments": [],
                "signature_doc_id": doc["id"],
                "created_at": now_iso(),
            }
            await db.messages.insert_one(msg)

            await db.conversations.update_one(
                {"id": conv_id},
                {
                    "$set": {f"read_state.{creator['id']}": msg["created_at"]},
                    "$addToSet": {"senders": creator["id"]},
                    "$pull": {
                        "trashed_by": signer_uid,
                        "archived_by": signer_uid,
                    },
                },
            )
    except Exception as e:  # noqa: BLE001
        logger.warning("Failed to notify signers for doc %s: %s", doc.get("id"), e)


async def _notify_informational_recipients(doc: dict, creator: dict) -> None:
    """Notify CC + BCC users with a plain Inbox message — no signature_doc_id
    reference, so the UI does NOT show an "Open to sign" link and the file
    access-control on /api/files keeps the PDF hidden from them."""
    try:
        sender_name = creator.get("name") or creator.get("email") or "Someone"
        all_recipients = []
        for c in doc.get("cc", []):
            if c.get("user_id"):
                all_recipients.append(("cc", c["user_id"]))
        for c in doc.get("bcc", []):
            if c.get("user_id"):
                all_recipients.append(("bcc", c["user_id"]))

        title_safe = (doc.get("title") or "").replace("<", "&lt;").replace(">", "&gt;")

        for kind, recipient_uid in all_recipients:
            if recipient_uid == creator["id"]:
                continue

            participants = [creator["id"], recipient_uid]
            existing = await db.conversations.find_one(
                {
                    "type": "direct",
                    "participants": {"$all": participants, "$size": 2},
                    "cc_ids": {"$in": [None, []]},
                    "bcc_ids": {"$in": [None, []]},
                },
                {"_id": 0},
            )
            if existing:
                conv_id = existing["id"]
            else:
                conv_id = str(uuid.uuid4())
                await db.conversations.insert_one({
                    "id": conv_id,
                    "type": "direct",
                    "name": None,
                    "participants": participants,
                    "to_ids": [recipient_uid],
                    "cc_ids": [],
                    "bcc_ids": [],
                    "created_by": creator["id"],
                    "senders": [creator["id"]],
                    "created_at": now_iso(),
                    "read_state": {creator["id"]: now_iso()},
                })

            label = "in copy (CC)" if kind == "cc" else "in blind copy (BCC)"
            content_html = (
                f"<p>{sender_name} sent a signature request and put you {label}.</p>"
                f"<p><strong>📝 {title_safe}</strong></p>"
                f"<p style=\"color:#71717a;font-size:12px\">"
                f"This message is informational only — you don't need to sign and the document is not attached.</p>"
            )
            plain = f"{sender_name} put you {label} on signature request: {doc.get('title','')}"

            msg = {
                "id": str(uuid.uuid4()),
                "conversation_id": conv_id,
                "sender_id": creator["id"],
                "subject": f"[{kind.upper()}] {doc.get('title','')[:140]}",
                "content": plain,
                "content_html": content_html,
                "attachments": [],
                # Deliberately NO signature_doc_id — recipients are not signers
                "created_at": now_iso(),
            }
            await db.messages.insert_one(msg)

            await db.conversations.update_one(
                {"id": conv_id},
                {
                    "$set": {f"read_state.{creator['id']}": msg["created_at"]},
                    "$addToSet": {"senders": creator["id"]},
                    "$pull": {
                        "trashed_by": recipient_uid,
                        "archived_by": recipient_uid,
                    },
                },
            )
    except Exception as e:  # noqa: BLE001
        logger.warning("Failed to notify CC/BCC for doc %s: %s", doc.get("id"), e)


@api.get("/signature-docs")
async def list_signature_docs(
    filter: str = Query("all", pattern="^(all|to_sign|sent|completed)$"),
    current=Depends(get_current_user),
):
    """List signature docs visible to the current user."""
    uid = current["id"]
    email = current.get("email", "").lower()

    if filter == "to_sign":
        query = {
            "status": "pending",
            "signers": {"$elemMatch": {
                "status": "pending",
                "$or": [{"user_id": uid}, {"email": email}],
            }},
        }
    elif filter == "sent":
        query = {"created_by": uid}
    elif filter == "completed":
        query = {
            "status": "completed",
            "$or": [
                {"created_by": uid},
                {"signers.user_id": uid},
                {"signers.email": email},
            ],
        }
    else:
        query = {
            "$or": [
                {"created_by": uid},
                {"signers.user_id": uid},
                {"signers.email": email},
            ],
        }

    docs = await db.signature_docs.find(query, {"_id": 0}).sort("created_at", -1).to_list(500)
    caller_perms = await get_role_permissions(current.get("role", "user"))
    is_admin = "users.manage" in caller_perms
    return [
        await _serialize_signature_doc(d, current_user_id=uid, is_admin=is_admin)
        for d in docs
    ]


@api.get("/signature-docs/{doc_id}")
async def get_signature_doc(doc_id: str, current=Depends(get_current_user)):
    doc = await db.signature_docs.find_one({"id": doc_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Signature doc not found")
    uid = current["id"]
    email = current.get("email", "").lower()
    signer_match = any(
        s.get("user_id") == uid or (s.get("email") or "").lower() == email
        for s in doc.get("signers", [])
    )
    caller_perms = await get_role_permissions(current.get("role", "user"))
    is_admin = "users.manage" in caller_perms
    if doc.get("created_by") != uid and not signer_match and not is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return await _serialize_signature_doc(doc, current_user_id=uid, is_admin=is_admin)


async def _maybe_finalise_signed_pdf(doc_id: str) -> dict:
    """If every signer has signed, build the flattened signed PDF + audit page."""
    doc = await db.signature_docs.find_one({"id": doc_id}, {"_id": 0})
    if not doc:
        return doc
    if not all(s.get("status") == "signed" for s in doc.get("signers", [])):
        return doc

    original_file = await db.files.find_one({"id": doc["original_file_id"]}, {"_id": 0})
    if not original_file:
        return doc
    try:
        pdf_bytes, _ = get_object(original_file["storage_path"])

        # Resolve image bytes for each image-type field
        field_images: dict = {}
        for f in doc.get("fields", []):
            if f.get("type") in ("signature", "initial", "mention") and f.get("value_file_id"):
                sf = await db.files.find_one({"id": f["value_file_id"]}, {"_id": 0})
                if not sf:
                    continue
                img_bytes, _ = get_object(sf["storage_path"])
                field_images[f["id"]] = img_bytes

        # Audit rows derived from signers + audit_log
        audit_rows = []
        log_by_email = {ev.get("email"): ev for ev in doc.get("audit_log", [])}
        for s in doc["signers"]:
            ev = log_by_email.get(s["email"], {})
            audit_rows.append({
                "name": s.get("name") or s.get("email"),
                "email": s.get("email"),
                "signed_at": s.get("signed_at") or "",
                "ip": ev.get("ip", "—"),
            })

        signed_bytes = build_signed_pdf(
            original_pdf_bytes=pdf_bytes,
            fields=doc.get("fields", []),
            field_images=field_images,
            audit_rows=audit_rows,
            doc_title=doc.get("title", ""),
        )
        signed_file_id = str(uuid.uuid4())
        signed_storage = f"{APP_NAME}/signatures/{doc_id}/{signed_file_id}.pdf"
        signed_result = put_object(signed_storage, signed_bytes, "application/pdf")
        await db.files.insert_one({
            "id": signed_file_id,
            "storage_path": signed_result["path"],
            "original_filename": f"signed-{doc.get('title','document')[:40]}.pdf",
            "content_type": "application/pdf",
            "size": signed_result.get("size", len(signed_bytes)),
            "uploaded_by": doc["created_by"],
            "is_deleted": False,
            "created_at": now_iso(),
        })
        await db.signature_docs.update_one(
            {"id": doc_id},
            {"$set": {
                "status": "completed",
                "completed_at": now_iso(),
                "signed_file_id": signed_file_id,
            }},
        )
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to build signed PDF for %s: %s", doc_id, e)
    return await db.signature_docs.find_one({"id": doc_id}, {"_id": 0})


@api.post("/signature-docs/{doc_id}/submit")
async def submit_signature_fields(
    doc_id: str,
    payload: SubmitFieldsIn,
    request: Request,
    current=Depends(get_current_user),
):
    """Submit all field values for the current signer in one go. Marks the
    signer as signed once every required field they own has a value."""
    doc = await db.signature_docs.find_one({"id": doc_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Signature doc not found")
    if doc.get("status") == "completed":
        raise HTTPException(status_code=400, detail="Document already fully signed")

    uid = current["id"]
    email = current.get("email", "").lower()

    # Locate the signer entry
    target_idx = None
    for i, s in enumerate(doc.get("signers", [])):
        if s.get("user_id") == uid or (s.get("email") or "").lower() == email:
            target_idx = i
            break
    if target_idx is None:
        raise HTTPException(status_code=403, detail="You are not a signer on this document")
    signer = doc["signers"][target_idx]
    if signer.get("status") == "signed":
        raise HTTPException(status_code=400, detail="You have already signed this document")

    # Build a map of my fields
    my_fields_by_id = {f["id"]: i for i, f in enumerate(doc.get("fields", [])) if f.get("signer_email") == signer["email"]}
    if not my_fields_by_id:
        raise HTTPException(status_code=400, detail="No fields assigned to you on this document")

    # Apply each value
    now = now_iso()
    set_ops = {}
    for value in payload.values:
        if value.id not in my_fields_by_id:
            continue
        idx = my_fields_by_id[value.id]
        field = doc["fields"][idx]
        ftype = field["type"]
        if ftype in ("signature", "initial", "mention"):
            if not value.value_image_b64:
                continue
            try:
                img_bytes = decode_signature_b64(value.value_image_b64)
            except Exception:
                raise HTTPException(status_code=400, detail=f"Invalid image data for field {value.id}")
            if len(img_bytes) > 5 * 1024 * 1024:
                raise HTTPException(status_code=400, detail="Field image too large")
            file_id = str(uuid.uuid4())
            storage_path = f"{APP_NAME}/signatures/{doc_id}/{file_id}.png"
            res = put_object(storage_path, img_bytes, "image/png")
            await db.files.insert_one({
                "id": file_id,
                "storage_path": res["path"],
                "original_filename": f"{ftype}-{uid}.png",
                "content_type": "image/png",
                "size": res.get("size", len(img_bytes)),
                "uploaded_by": uid,
                "is_deleted": False,
                "created_at": now,
            })
            set_ops[f"fields.{idx}.value_file_id"] = file_id
            set_ops[f"fields.{idx}.value_text"] = None
            set_ops[f"fields.{idx}.value_bool"] = None
        elif ftype == "checkbox":
            set_ops[f"fields.{idx}.value_bool"] = bool(value.value_bool)
            set_ops[f"fields.{idx}.value_text"] = None
            set_ops[f"fields.{idx}.value_file_id"] = None
        else:  # date / text
            set_ops[f"fields.{idx}.value_text"] = (value.value_text or "")[:200]
            set_ops[f"fields.{idx}.value_bool"] = None
            set_ops[f"fields.{idx}.value_file_id"] = None
        set_ops[f"fields.{idx}.filled"] = True
        set_ops[f"fields.{idx}.filled_at"] = now

    if not set_ops:
        raise HTTPException(status_code=400, detail="No matching fields submitted")

    # Refuse if any of MY required fields would remain unfilled
    doc_in_progress = {**doc}
    # apply the staged set_ops to a copy of fields in memory to assess
    for path, val in set_ops.items():
        if not path.startswith("fields."):
            continue
        _, idx_str, attr = path.split(".", 2)
        doc_in_progress["fields"][int(idx_str)][attr] = val
    missing = [
        f for f in doc_in_progress["fields"]
        if f.get("signer_email") == signer["email"] and f.get("required") and not f.get("filled")
    ]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Required fields are still empty: {', '.join(sorted({m['type'] for m in missing}))}",
        )

    # Persist field values + mark signer signed
    set_ops[f"signers.{target_idx}.status"] = "signed"
    set_ops[f"signers.{target_idx}.signed_at"] = now
    set_ops[f"signers.{target_idx}.user_id"] = uid

    # Append audit entry
    ip = (request.client.host if request.client else None) or request.headers.get("x-forwarded-for", "").split(",")[0].strip() or "—"
    user_agent = request.headers.get("user-agent", "")[:200]
    audit_entry = {
        "at": now,
        "email": signer["email"],
        "name": signer.get("name"),
        "ip": ip,
        "user_agent": user_agent,
    }

    await db.signature_docs.update_one(
        {"id": doc_id},
        {"$set": set_ops, "$push": {"audit_log": audit_entry}},
    )

    doc = await _maybe_finalise_signed_pdf(doc_id)
    await log_activity(
        user_id=current["id"], user_email=current.get("email"), user_name=current.get("name"),
        action="signature.signed",
        target_type="signature_doc", target_id=doc_id,
        details={
            "title": (doc or {}).get("title", "")[:140],
            "fields_signed": len(payload.values),
            "doc_completed": (doc or {}).get("status") == "completed",
        },
        request=request,
    )
    sign_caller_perms = await get_role_permissions(current.get("role", "user"))
    return await _serialize_signature_doc(
        doc,
        current_user_id=current["id"],
        is_admin="users.manage" in sign_caller_perms,
    )


@api.delete("/signature-docs/{doc_id}")
async def delete_signature_doc(doc_id: str, current=Depends(get_current_user)):
    """Only the creator can cancel a signature request that is still pending."""
    doc = await db.signature_docs.find_one({"id": doc_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Signature doc not found")
    if doc.get("created_by") != current["id"]:
        raise HTTPException(status_code=403, detail="Only the creator can cancel this request")
    if doc.get("status") == "completed":
        raise HTTPException(status_code=400, detail="Cannot cancel a completed document")
    await db.signature_docs.delete_one({"id": doc_id})
    return {"ok": True}


@api.get("/admin/users/{user_id}/live")
async def admin_user_live(
    user_id: str,
    since: Optional[str] = None,
    _=Depends(require_permission("users.manage")),
):
    """Per-user real-time dashboard data — used by the admin Live view drawer.
    Returns the user's profile, online state, current page, and recent activity."""
    user = await db.users.find_one(
        {"id": user_id},
        {"_id": 0, "id": 1, "name": 1, "email": 1, "role": 1,
         "is_active": 1, "last_seen_at": 1, "current_path": 1, "current_context": 1, "created_at": 1},
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    online = _is_online(user.get("last_seen_at"))

    # Aggregate counts for the last 24h
    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    pipeline = [
        {"$match": {"user_id": user_id, "created_at": {"$gte": since_24h}}},
        {"$group": {"_id": "$action", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    actions_24h = {row["_id"]: row["count"] async for row in db.activity_logs.aggregate(pipeline)}

    # Recent activity tail
    cutoff = since or (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    tail = await db.activity_logs.find(
        {"user_id": user_id, "created_at": {"$gt": cutoff}},
        {"_id": 0},
    ).sort("created_at", -1).limit(50).to_list(50)

    return {
        "user": {**user, "online": online},
        "actions_24h": actions_24h,
        "total_actions_24h": sum(actions_24h.values()),
        "recent_activity": tail,
    }


# ---------- Admin activity tracking ----------
@api.get("/admin/activity/live")
async def admin_activity_live(
    since: Optional[str] = None,
    _=Depends(require_permission("users.manage")),
):
    """Real-time dashboard data: aggregated stats + online users + recent
    activity tail. Designed to be polled every few seconds."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    online_threshold = (now - timedelta(seconds=45)).isoformat()
    hour_ago = (now - timedelta(hours=1)).isoformat()

    # Online users (heartbeat within last 45s)
    online = await db.users.find(
        {"last_seen_at": {"$gte": online_threshold}, "is_active": True},
        {"_id": 0, "id": 1, "email": 1, "name": 1, "role": 1, "last_seen_at": 1, "current_path": 1, "current_context": 1},
    ).to_list(200)

    # Activity counts today, grouped by action
    pipeline_today = [
        {"$match": {"created_at": {"$gte": today_start}}},
        {"$group": {"_id": "$action", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    actions_today = {row["_id"]: row["count"] async for row in db.activity_logs.aggregate(pipeline_today)}

    # Top active users today
    pipeline_top = [
        {"$match": {"created_at": {"$gte": today_start}, "user_id": {"$ne": None}}},
        {"$group": {
            "_id": "$user_id",
            "user_name": {"$last": "$user_name"},
            "user_email": {"$last": "$user_email"},
            "count": {"$sum": 1},
            "last_at": {"$max": "$created_at"},
        }},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_users = []
    async for row in db.activity_logs.aggregate(pipeline_top):
        top_users.append({
            "user_id": row["_id"],
            "user_name": row.get("user_name"),
            "user_email": row.get("user_email"),
            "count": row["count"],
            "last_at": row["last_at"],
        })

    # Recent activity tail (last hour, or `since` if provided)
    cutoff = since if since else hour_ago
    tail = await db.activity_logs.find(
        {"created_at": {"$gt": cutoff}},
        {"_id": 0},
    ).sort("created_at", -1).limit(80).to_list(80)

    # Counts of unique users today
    user_set = set()
    async for row in db.activity_logs.find(
        {"created_at": {"$gte": today_start}, "user_id": {"$ne": None}},
        {"_id": 0, "user_id": 1},
    ):
        user_set.add(row["user_id"])

    # Hourly histogram for the last 12 hours — used to draw the sparkline
    histogram: list[dict] = []
    for h in range(11, -1, -1):
        slot_start = (now - timedelta(hours=h + 1)).replace(minute=0, second=0, microsecond=0)
        slot_end = slot_start + timedelta(hours=1)
        count = await db.activity_logs.count_documents({
            "created_at": {"$gte": slot_start.isoformat(), "$lt": slot_end.isoformat()},
        })
        histogram.append({"hour": slot_start.strftime("%H:00"), "count": count})

    # High-level category counts (auth / messaging / signing / files)
    def _category(action: str) -> str:
        if action.startswith("auth."):
            return "auth"
        if action.startswith("signature."):
            return "signing"
        if action.startswith("file."):
            return "files"
        if action.startswith("message.") or action.startswith("conversation."):
            return "messaging"
        return "other"
    by_category: dict[str, int] = {}
    for act, count in actions_today.items():
        cat = _category(act)
        by_category[cat] = by_category.get(cat, 0) + count

    # Failed login attempts today (security signal)
    failed_logins = actions_today.get("auth.login.failed", 0)

    return {
        "now": now.isoformat(),
        "stats": {
            "online_count": len(online),
            "total_actions_today": sum(actions_today.values()),
            "unique_users_today": len(user_set),
            "actions_by_type": actions_today,
            "by_category": by_category,
            "failed_logins_today": failed_logins,
            "histogram_12h": histogram,
        },
        "online_users": online,
        "top_users_today": top_users,
        "recent_activity": tail,
    }


@api.get("/admin/activity")
async def admin_activity_log(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    _=Depends(require_permission("users.manage")),
):
    """Admin-only: paginated activity log with optional filters."""
    query: dict = {}
    if user_id:
        query["user_id"] = user_id
    if action:
        query["action"] = action
    if since:
        query["created_at"] = {"$gte": since}
    rows = await db.activity_logs.find(query, {"_id": 0}).sort("created_at", -1).limit(limit).to_list(limit)
    return rows


@api.get("/admin/users/{target_id}/stats")
async def admin_user_stats(
    target_id: str,
    _=Depends(require_permission("users.manage")),
):
    """Admin-only: usage summary for a given user."""
    user = await db.users.find_one({"id": target_id}, {"_id": 0, "id": 1, "email": 1, "name": 1, "is_active": 1, "last_seen_at": 1, "created_at": 1})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Counts from activity_logs
    pipeline = [
        {"$match": {"user_id": target_id}},
        {"$group": {"_id": "$action", "count": {"$sum": 1}, "last_at": {"$max": "$created_at"}}},
    ]
    action_counts = {row["_id"]: {"count": row["count"], "last_at": row["last_at"]}
                     async for row in db.activity_logs.aggregate(pipeline)}

    # Messages received (in convs they're part of, not authored by them)
    msg_received = await db.messages.count_documents({
        "sender_id": {"$ne": target_id},
        "conversation_id": {"$in": [c["id"] async for c in db.conversations.find(
            {"participants": target_id}, {"_id": 0, "id": 1})]},
    })
    # Messages read by this user
    msg_read = await db.messages.count_documents({"read_by.user_id": target_id})

    # Pending signatures awaiting them
    pending_sigs = await db.signature_docs.count_documents({
        "status": "pending",
        "signers": {"$elemMatch": {
            "status": "pending",
            "$or": [{"user_id": target_id}, {"email": (user.get("email") or "").lower()}],
        }},
    })

    return {
        "user": user,
        "actions": action_counts,
        "messages_received": msg_received,
        "messages_read": msg_read,
        "pending_signatures": pending_sigs,
    }


@api.get("/admin/messages/{message_id}/reads")
async def admin_message_reads(
    message_id: str,
    _=Depends(require_permission("users.manage")),
):
    """Admin-only: per-message read receipts."""
    msg = await db.messages.find_one(
        {"id": message_id},
        {"_id": 0, "id": 1, "conversation_id": 1, "subject": 1, "sender_id": 1, "created_at": 1, "read_by": 1},
    )
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    # Enrich read_by with names
    read_by = msg.get("read_by") or []
    if read_by:
        uids = [r["user_id"] for r in read_by]
        users = await db.users.find({"id": {"$in": uids}}, {"_id": 0, "id": 1, "name": 1, "email": 1}).to_list(200)
        by_uid = {u["id"]: u for u in users}
        for r in read_by:
            u = by_uid.get(r["user_id"], {})
            r["name"] = u.get("name")
            r["email"] = u.get("email")
    msg["read_by"] = read_by
    return msg


@api.post("/signature-docs/{doc_id}/sign")
async def sign_signature_doc_legacy(
    doc_id: str,
    payload: SignDocIn,
    request: Request,
    current=Depends(get_current_user),
):
    """Backwards-compatible single-image signing for clients that still ship the
    pre-DocuSign bundle. Internally fans out the supplied signature image to all
    of the current signer's image-type fields (signature / initial / mention)
    and submits any required text / checkbox fields with sensible defaults.

    New clients should use POST /signature-docs/{id}/submit instead.
    """
    # Make sure the doc is materialised with its (possibly auto-migrated) fields.
    raw = await db.signature_docs.find_one({"id": doc_id}, {"_id": 0})
    if not raw:
        raise HTTPException(status_code=404, detail="Signature doc not found")
    materialised = await _serialize_signature_doc(raw)

    email = (current.get("email") or "").lower()
    my_fields = [f for f in materialised["fields"] if (f.get("signer_email") or "").lower() == email]
    if not my_fields:
        raise HTTPException(status_code=400, detail="No fields assigned to you on this document")

    # Build a values payload reusing the same signature image everywhere.
    today = now_iso()[:10]
    values = []
    for f in my_fields:
        ftype = f.get("type")
        if ftype in ("signature", "initial", "mention"):
            values.append(FieldValueIn(id=f["id"], value_image_b64=payload.signature_image_b64))
        elif ftype == "date":
            values.append(FieldValueIn(id=f["id"], value_text=today))
        elif ftype == "checkbox":
            values.append(FieldValueIn(id=f["id"], value_bool=True))
        else:
            values.append(FieldValueIn(id=f["id"], value_text=current.get("name") or current.get("email") or ""))

    return await submit_signature_fields(
        doc_id=doc_id,
        payload=SubmitFieldsIn(values=values),
        request=request,
        current=current,
    )


# ---------- Stats ----------
@api.get("/inbox/unread-count")
async def inbox_unread_count(current=Depends(get_current_user)):
    """Total unread messages across all conversations the user participates in."""
    uid = current["id"]
    convs = await db.conversations.find(
        {"participants": uid, "trashed_by": {"$ne": uid}},
        {"_id": 0, "id": 1, "read_state": 1},
    ).to_list(1000)
    if not convs:
        return {"unread": 0}

    read_by_conv = {c["id"]: (c.get("read_state") or {}).get(uid) for c in convs}
    conv_ids = list(read_by_conv.keys())

    # Single aggregation: project candidate messages then count in Python by comparing per-conv last_read
    pipeline = [
        {"$match": {"conversation_id": {"$in": conv_ids}, "sender_id": {"$ne": uid}}},
        {"$project": {"_id": 0, "conversation_id": 1, "created_at": 1}},
    ]
    total = 0
    async for row in db.messages.aggregate(pipeline):
        last_read = read_by_conv.get(row["conversation_id"])
        if last_read and row["created_at"] <= last_read:
            continue
        total += 1
    return {"unread": total}


@api.get("/stats/overview")
async def overview(_=Depends(require_permission("users.manage"))):
    return {
        "users": await db.users.count_documents({}),
        "active_users": await db.users.count_documents({"is_active": True}),
        "roles": await db.roles.count_documents({}) + len(SYSTEM_ROLES),
        "conversations": await db.conversations.count_documents({}),
        "messages": await db.messages.count_documents({}),
        "files": await db.files.count_documents({"is_deleted": False}),
    }


@api.get("/")
async def health():
    return {"status": "ok", "service": "intracom"}


app.include_router(api)


# ---------- Startup ----------
async def seed_admin():
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@intracom.app").lower().strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin123!")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "id": str(uuid.uuid4()),
            "email": admin_email,
            "name": "Administrator",
            "password_hash": hash_password(admin_password),
            "role": "admin",
            "is_active": True,
            "created_at": now_iso(),
        })
        logger.info("Admin seeded")
    else:
        # ensure password matches env and role is admin
        updates = {}
        if not verify_password(admin_password, existing["password_hash"]):
            updates["password_hash"] = hash_password(admin_password)
        if existing.get("role") != "admin":
            updates["role"] = "admin"
        if not existing.get("is_active", True):
            updates["is_active"] = True
        if updates:
            await db.users.update_one({"id": existing["id"]}, {"$set": updates})

    # seed a demo regular user
    demo_email = "user@intracom.app"
    if not await db.users.find_one({"email": demo_email}):
        await db.users.insert_one({
            "id": str(uuid.uuid4()),
            "email": demo_email,
            "name": "Sophie Martin",
            "password_hash": hash_password("User123!"),
            "role": "user",
            "is_active": True,
            "created_at": now_iso(),
        })


async def write_test_credentials():
    try:
        mem_dir = Path("/app/memory")
        mem_dir.mkdir(parents=True, exist_ok=True)
        content = (
            "# Test Credentials — IntraCom\n\n"
            "## Admin\n"
            f"- Email: `{os.environ.get('ADMIN_EMAIL', 'admin@intracom.app')}`\n"
            f"- Password: `{os.environ.get('ADMIN_PASSWORD', 'Admin123!')}`\n"
            "- Role: admin\n\n"
            "## Test User\n"
            "- Email: `user@intracom.app`\n"
            "- Password: `User123!`\n"
            "- Role: user\n\n"
            "## Auth Endpoints\n"
            "- POST /api/auth/register/start (envoi OTP)\n"
            "- POST /api/auth/register/verify (validation OTP)\n"
            "- POST /api/auth/register/resend-otp\n"
            "- POST /api/auth/login\n"
            "- POST /api/auth/logout\n"
            "- GET  /api/auth/me\n"
            "- POST /api/auth/refresh\n"
        )
        (mem_dir / "test_credentials.md").write_text(content, encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to write test credentials: {e}")


async def backfill_senders():
    """One-shot migration to repair the `conversations.senders` field for
    legacy documents created before we tracked it explicitly. Two passes:

    1. Conversations with no `senders` field at all → derive the list from
       distinct `messages.sender_id` (so anyone who already sent a message
       in that thread is correctly attributed). If no messages exist, fall
       back to `created_by` so the creator at least sees the empty thread
       in their Sent folder.

    2. Conversations where `senders` exists but is missing `created_by`
       (because someone else later replied while the creator never posted
       a message) — we leave those untouched, the field reflects reality.

    Idempotent: re-running on already-correct docs is a no-op.
    """
    try:
        cursor = db.conversations.find(
            {"$or": [{"senders": {"$exists": False}}, {"senders": None}]},
            {"_id": 0, "id": 1, "created_by": 1},
        )
        repaired = 0
        async for conv in cursor:
            cid = conv.get("id")
            if not cid:
                continue
            distinct_senders = await db.messages.distinct("sender_id", {"conversation_id": cid})
            distinct_senders = [s for s in distinct_senders if s]
            if not distinct_senders and conv.get("created_by"):
                distinct_senders = [conv["created_by"]]
            await db.conversations.update_one(
                {"id": cid}, {"$set": {"senders": distinct_senders}}
            )
            repaired += 1
        if repaired:
            logger.info("backfill_senders: repaired %d conversation(s)", repaired)
    except Exception as exc:  # noqa: BLE001
        logger.error("backfill_senders failed: %s", exc)


@app.on_event("startup")
async def on_startup():
    """Best-effort startup. Every step runs in a background task so the app
    can serve the /api/ health endpoint within milliseconds — Kubernetes can
    then route traffic immediately while indexes / seeds finish in the
    background. Any single step failure is logged and isolated, never
    blocks the rest of the boot. Critical on managed deployments where the
    health-check timeout is shorter than the cumulative round-trip cost of
    ~24 sequential createIndex calls against MongoDB Atlas."""

    async def _safe(label, coro):
        try:
            await coro
        except Exception as exc:  # noqa: BLE001
            logger.error("startup step %s failed: %s", label, exc)

    async def _background_init():
        # Indexes (parallelized — they are idempotent and independent).
        index_specs = [
            ("users.email",        db.users.create_index("email", unique=True)),
            ("users.id",           db.users.create_index("id", unique=True)),
            ("roles.id",           db.roles.create_index("id", unique=True)),
            ("roles.name",         db.roles.create_index("name", unique=True)),
            ("conversations.id",   db.conversations.create_index("id", unique=True)),
            ("conversations.participants", db.conversations.create_index("participants")),
            ("messages.compound",  db.messages.create_index([("conversation_id", 1), ("created_at", 1)])),
            ("files.id",           db.files.create_index("id", unique=True)),
            ("invite_codes.code",  db.invite_codes.create_index("code", unique=True)),
            ("invite_codes.id",    db.invite_codes.create_index("id", unique=True)),
            ("drafts.id",          db.drafts.create_index("id", unique=True)),
            ("drafts.user_id",     db.drafts.create_index("user_id")),
            ("login_attempts.id",  db.login_attempts.create_index("identifier", unique=True)),
            ("pending_reg.id",     db.pending_registrations.create_index("id", unique=True)),
            ("pending_reg.email",  db.pending_registrations.create_index("email")),
            ("signature_docs.id",  db.signature_docs.create_index("id", unique=True)),
            ("signature_docs.by",  db.signature_docs.create_index("created_by")),
            ("signature_docs.sig", db.signature_docs.create_index("signers.user_id")),
            ("activity_logs.id",   db.activity_logs.create_index("id", unique=True)),
            ("activity_logs.user", db.activity_logs.create_index([("user_id", 1), ("created_at", -1)])),
            ("activity_logs.action", db.activity_logs.create_index([("action", 1), ("created_at", -1)])),
            ("user_screens.user_id", db.user_screens.create_index("user_id", unique=True)),
            # TTL: auto-delete screen captures after 48 hours
            ("user_screens.ttl", db.user_screens.create_index("expires_at", expireAfterSeconds=0)),
            ("password_reset_tokens.user_id", db.password_reset_tokens.create_index("user_id")),
            ("password_reset_tokens.token_hash", db.password_reset_tokens.create_index("token_hash", unique=True)),
            # TTL: auto-delete reset tokens after expiry (Mongo purges within ~60s)
            ("password_reset_tokens.ttl", db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)),
            ("message_templates.id", db.message_templates.create_index("id", unique=True)),
        ]
        await asyncio.gather(*[_safe(f"index:{lbl}", c) for lbl, c in index_specs])

        await _safe("seed_admin", seed_admin())
        await _safe("write_test_credentials", write_test_credentials())
        await _safe("backfill_senders", backfill_senders())

        # seed one demo invite code for first registration
        try:
            if not await db.invite_codes.find_one({"used": False}):
                admin = await db.users.find_one({"role": "admin"}, {"_id": 0, "id": 1})
                if admin:
                    now = datetime.now(timezone.utc)
                    await db.invite_codes.insert_one({
                        "id": str(uuid.uuid4()),
                        "code": "DEMO-2026",
                        "created_by": admin["id"],
                        "used": False,
                        "used_by": None,
                        "used_at": None,
                        "created_at": now.isoformat(),
                        "expires_at": (now + timedelta(days=INVITE_CODE_TTL_DAYS)).isoformat(),
                    })
        except Exception as exc:  # noqa: BLE001
            logger.error("seed_invite_code failed: %s", exc)

        try:
            init_storage()
            logger.info("Object storage initialized")
        except Exception as e:
            logger.error("Storage init failed (will retry on demand): %s", e)

    # Fire-and-forget so /api/ becomes reachable immediately for the
    # platform's health probe.
    asyncio.create_task(_background_init())
    logger.info("Startup scheduled; serving traffic immediately")


@app.on_event("shutdown")
async def on_shutdown():
    client.close()
