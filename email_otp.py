"""Email OTP helpers — Resend integration."""
from __future__ import annotations

import asyncio
import logging
import os
import secrets

import resend

logger = logging.getLogger(__name__)

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "onboarding@resend.dev")
APP_DISPLAY_NAME = os.environ.get("APP_DISPLAY_NAME", "Skadden Exchange")
APP_TAGLINE = "Internal Communication Platform"

# Brand palette (kept in one place so all templates stay consistent).
ACCENT = "#b91c2c"       # corporate red — badge, button, links
INK = "#1f2328"          # primary text
MUTED = "#6b7280"        # secondary text
BORDER = "#e8e9eb"       # hairlines
PAGE_BG = "#eceef1"
CARD_BG = "#ffffff"
CODE_BG = "#f6f7f8"
HEADING_FONT = "Georgia,'Times New Roman',serif"
# Publicly reachable URL of the site logo. Base64-embedded images are
# unreliable (Outlook and several providers strip data: URIs entirely),
# so a normal hosted URL is the safer, standard choice for email clients.
LOGO_URL = f"{os.environ.get('FRONTEND_URL', '').rstrip('/')}/brand/logo.jpg"

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY


def generate_otp_code() -> str:
    """Generate a cryptographically secure 6-digit OTP."""
    return f"{secrets.randbelow(1_000_000):06d}"


def _shell(preheader: str, body_html: str) -> str:
    """Shared wrapper: a rounded, centered card with a circular brand badge
    (the site logo), generous whitespace, and center-aligned content."""
    return f"""<!doctype html>
<html>
<head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /></head>
<body style="margin:0;padding:0;background:{PAGE_BG};font-family:Arial,Helvetica,sans-serif;color:{INK};">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">{preheader}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:48px 16px;">
    <tr><td align="center">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background:{CARD_BG};border:1px solid {BORDER};border-radius:16px;">
        <tr><td align="center" style="padding:40px 44px 0 44px;">
          <img src="{LOGO_URL}" alt="{APP_DISPLAY_NAME}" width="48" height="48" style="display:block;width:48px;height:48px;border-radius:50%;object-fit:cover;" />
          <div style="font-family:{HEADING_FONT};font-size:17px;font-weight:700;color:{INK};margin-top:14px;">{APP_DISPLAY_NAME}</div>
          <div style="font-size:11px;color:{MUTED};margin-top:2px;letter-spacing:0.4px;">{APP_TAGLINE}</div>
        </td></tr>
        {body_html}
        <tr><td align="center" style="padding:24px 44px 32px 44px;">
          <div style="width:100%;height:1px;background:{BORDER};margin-bottom:20px;"></div>
          <div style="font-size:11px;color:{MUTED};line-height:1.6;">
            This is an automated message from {APP_DISPLAY_NAME}.<br/>Please do not reply directly to this email.
          </div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""


def _code_block(code: str, size: str = "24px", spacing: str = "6px") -> str:
    return f"""
        <tr><td align="center" style="padding:20px 44px 4px 44px;">
          <div style="display:inline-block;background:{CODE_BG};border:1px solid {BORDER};border-radius:10px;padding:16px 32px;font-family:'Courier New',Courier,monospace;font-size:{size};letter-spacing:{spacing};font-weight:700;color:{INK};">
            {code}
          </div>
        </td></tr>"""


def _button(url: str, label: str) -> str:
    return f"""
        <tr><td align="center" style="padding:24px 44px 4px 44px;">
          <a href="{url}" style="display:inline-block;background:{ACCENT};color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;border-radius:999px;padding:14px 34px;">
            {label}
          </a>
        </td></tr>"""


def _otp_html(name: str, code: str) -> str:
    """Build the inline-styled OTP email."""
    body = f"""
        <tr><td align="center" style="padding:26px 44px 0 44px;">
          <h1 style="font-family:{HEADING_FONT};font-size:21px;font-weight:700;margin:0;color:{INK};text-align:center;">Verify your email address</h1>
        </td></tr>
        <tr><td style="padding:14px 44px 0 44px;font-size:14px;line-height:1.6;color:{MUTED};text-align:center;">
          Hello {name or ""},<br/><br/>
          To complete the creation of your account, enter the following code on the registration page:
        </td></tr>
        {_code_block(code, size="28px", spacing="10px")}
        <tr><td style="padding:20px 44px 8px 44px;font-size:12px;line-height:1.6;color:{MUTED};text-align:center;">
          This code expires in 10 minutes. If you did not request this, you can safely ignore this email.
        </td></tr>"""
    return _shell(f"Your verification code is {code}", body)


async def send_otp_email(recipient_email: str, recipient_name: str, code: str) -> bool:
    """Send the OTP email via Resend. Returns True on success, False otherwise."""
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY missing — OTP email NOT sent. Code (dev mode): %s", code)
        return False

    params = {
        "from": f"{APP_DISPLAY_NAME} <{SENDER_EMAIL}>",
        "to": [recipient_email],
        "subject": f"{APP_DISPLAY_NAME} verification code: {code}",
        "html": _otp_html(recipient_name, code),
    }

    try:
        email = await asyncio.to_thread(resend.Emails.send, params)
        logger.info("OTP email sent to %s (id=%s)", recipient_email, email.get("id") if isinstance(email, dict) else "?")
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("Resend send failed for %s: %s", recipient_email, e)
        return False


def _invite_html(recipient_name: str, code: str, register_url: str, inviter_name: str, expires_at: str) -> str:
    """Build the inline-styled invitation email."""
    greeting = f"Hello {recipient_name}," if recipient_name else "Hello,"
    inviter_line = (
        f"<strong>{inviter_name}</strong> invited you to join {APP_DISPLAY_NAME}, an internal communication platform."
        if inviter_name
        else f"You have been invited to join {APP_DISPLAY_NAME}, an internal communication platform."
    )
    body = f"""
        <tr><td align="center" style="padding:26px 44px 0 44px;">
          <h1 style="font-family:{HEADING_FONT};font-size:21px;font-weight:700;margin:0;color:{INK};text-align:center;">You're invited</h1>
        </td></tr>
        <tr><td style="padding:14px 44px 0 44px;font-size:14px;line-height:1.6;color:{MUTED};text-align:center;">
          {greeting}<br/><br/>
          {inviter_line} Use the invitation code below when you create your account.
        </td></tr>
        {_code_block(code, size="22px", spacing="6px")}
        {_button(register_url, "Create my account")}
        <tr><td style="padding:20px 44px 8px 44px;font-size:12px;line-height:1.6;color:{MUTED};text-align:center;">
          This invitation code is single-use and expires on {expires_at}. If the button does not work, paste this link into your browser:
          <br/><span style="word-break:break-all;color:{ACCENT};">{register_url}</span>
        </td></tr>"""
    return _shell(f"You're invited to join {APP_DISPLAY_NAME}", body)


async def send_invitation_email(
    recipient_email: str,
    recipient_name: str,
    code: str,
    register_url: str,
    inviter_name: str,
    expires_at: str,
) -> bool:
    """Send a branded invitation email containing the code + registration link."""
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY missing — invitation email NOT sent. Code (dev mode): %s", code)
        return False

    params = {
        "from": f"{APP_DISPLAY_NAME} <{SENDER_EMAIL}>",
        "to": [recipient_email],
        "subject": f"You're invited to {APP_DISPLAY_NAME}",
        "html": _invite_html(recipient_name, code, register_url, inviter_name, expires_at),
    }

    try:
        email = await asyncio.to_thread(resend.Emails.send, params)
        logger.info(
            "Invitation email sent to %s (id=%s)",
            recipient_email,
            email.get("id") if isinstance(email, dict) else "?",
        )
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("Resend invite send failed for %s: %s", recipient_email, e)
        return False


def _new_message_html(recipient_name: str, sender_name: str, app_url: str) -> str:
    """Minimal teaser email for a new in-platform message."""
    greeting = f"Hello {recipient_name}," if recipient_name else "Hello,"
    body = f"""
        <tr><td align="center" style="padding:26px 44px 0 44px;">
          <h1 style="font-family:{HEADING_FONT};font-size:21px;font-weight:700;margin:0;color:{INK};text-align:center;">You have a new message</h1>
        </td></tr>
        <tr><td style="padding:14px 44px 0 44px;font-size:14px;line-height:1.6;color:{MUTED};text-align:center;">
          {greeting}<br/><br/>
          <strong>{sender_name}</strong> sent you a new message on {APP_DISPLAY_NAME}. Open the platform to read and reply.
        </td></tr>
        {_button(app_url, "Open messaging")}
        <tr><td style="padding:20px 44px 8px 44px;font-size:12px;line-height:1.6;color:{MUTED};text-align:center;">&nbsp;</td></tr>"""
    return _shell(f"{sender_name} sent you a new message", body)


async def send_new_message_notification(
    recipient_email: str,
    recipient_name: str,
    sender_name: str,
    app_url: str,
) -> bool:
    """Send a teaser email to a user telling them they have a new in-platform
    message. Returns True on success, False otherwise."""
    if not RESEND_API_KEY:
        logger.warning(
            "RESEND_API_KEY missing — new-message notification NOT sent to %s",
            recipient_email,
        )
        return False

    params = {
        "from": f"{APP_DISPLAY_NAME} <{SENDER_EMAIL}>",
        "to": [recipient_email],
        "subject": f"New message from {sender_name} on {APP_DISPLAY_NAME}",
        "html": _new_message_html(recipient_name, sender_name, app_url),
    }
    try:
        email = await asyncio.to_thread(resend.Emails.send, params)
        logger.info(
            "New-message notification sent to %s (id=%s)",
            recipient_email,
            email.get("id") if isinstance(email, dict) else "?",
        )
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("Resend new_message send failed for %s: %s", recipient_email, e)
        return False


def _password_reset_html(name: str, reset_url: str, expires_min: int) -> str:
    """Build the password-reset email."""
    greeting = f"Hello {name}," if name else "Hello,"
    body = f"""
        <tr><td align="center" style="padding:26px 44px 0 44px;">
          <h1 style="font-family:{HEADING_FONT};font-size:21px;font-weight:700;margin:0;color:{INK};text-align:center;">Reset your password</h1>
        </td></tr>
        <tr><td style="padding:14px 44px 0 44px;font-size:14px;line-height:1.6;color:{MUTED};text-align:center;">
          {greeting}<br/><br/>
          We received a request to reset the password on your {APP_DISPLAY_NAME} account.
          Click the button below to choose a new password. This link expires in
          {expires_min} minutes and can only be used once.
        </td></tr>
        {_button(reset_url, "Reset password")}
        <tr><td style="padding:20px 44px 4px 44px;font-size:11px;line-height:1.6;color:{MUTED};word-break:break-all;text-align:center;">
          Or copy this link into your browser:<br/>
          <span style="color:{ACCENT};">{reset_url}</span>
        </td></tr>
        <tr><td style="padding:8px 40px 28px 40px;font-size:12px;line-height:1.6;color:{MUTED};">
          If you did not request a password reset, you can safely ignore this email — your
          password will not change.
        </td></tr>"""
    return _shell("Reset your password", body)


async def send_password_reset_email(
    recipient_email: str,
    recipient_name: str,
    reset_url: str,
    expires_min: int = 60,
) -> bool:
    """Send the password-reset link via Resend. Returns True on success."""
    if not RESEND_API_KEY:
        logger.warning(
            "RESEND_API_KEY missing — password reset email NOT sent. URL (dev mode): %s",
            reset_url,
        )
        return False

    params = {
        "from": f"{APP_DISPLAY_NAME} <{SENDER_EMAIL}>",
        "to": [recipient_email],
        "subject": f"Reset your {APP_DISPLAY_NAME} password",
        "html": _password_reset_html(recipient_name, reset_url, expires_min),
    }
    try:
        email = await asyncio.to_thread(resend.Emails.send, params)
        logger.info(
            "Password-reset email sent to %s (id=%s)",
            recipient_email,
            email.get("id") if isinstance(email, dict) else "?",
        )
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("Resend password-reset send failed for %s: %s", recipient_email, e)
        return False
