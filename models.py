"""Pydantic models for API requests and responses."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field

# ---------- Permissions catalog ----------
ALL_PERMISSIONS = [
    "messages.send",
    "messages.send_attachments",
    "conversations.create_direct",
    "conversations.create_group",
    "users.manage",
    "roles.manage",
]

SYSTEM_ROLES = {
    "admin": ALL_PERMISSIONS,
    "user": [
        "messages.send",
        "messages.send_attachments",
        "conversations.create_direct",
        "conversations.create_group",
    ],
}


# ---------- Auth ----------
class RegisterIn(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=80)
    password: str = Field(..., min_length=6, max_length=200)
    invite_code: str = Field(..., min_length=4, max_length=40)


class RegisterStartIn(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=80)
    password: str = Field(..., min_length=6, max_length=200)
    invite_code: str = Field(..., min_length=4, max_length=40)


class RegisterVerifyIn(BaseModel):
    pending_id: str = Field(..., min_length=8, max_length=80)
    code: str = Field(..., min_length=6, max_length=6)


class RegisterResendOtpIn(BaseModel):
    pending_id: str = Field(..., min_length=8, max_length=80)


class InviteEmailIn(BaseModel):
    recipient_email: EmailStr
    recipient_name: Optional[str] = Field(default=None, max_length=80)


class InviteCodeOut(BaseModel):
    id: str
    code: str
    created_by: str
    created_by_name: Optional[str] = None
    used: bool
    used_by: Optional[str] = None
    used_by_email: Optional[str] = None
    used_at: Optional[str] = None
    created_at: str
    expires_at: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: EmailStr
    name: str
    role: str  # "admin", "user", or custom role id
    role_name: Optional[str] = None
    permissions: List[str] = []
    is_active: bool = True
    email_notifications_enabled: bool = False
    created_at: str
    last_seen_at: Optional[str] = None


# ---------- Users (admin) ----------
class AdminCreateUserIn(BaseModel):
    email: EmailStr
    name: str
    password: str = Field(..., min_length=6)
    role: str = "user"
    email_notifications_enabled: bool = False


class AdminUpdateUserIn(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    email_notifications_enabled: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=6)


# ---------- Roles ----------
class RoleIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=60)
    description: Optional[str] = ""
    permissions: List[str] = []


class RoleOut(BaseModel):
    id: str
    name: str
    description: str = ""
    permissions: List[str] = []
    is_system: bool = False
    created_at: str


# ---------- Conversations ----------
class ConversationCreateIn(BaseModel):
    to_emails: List[EmailStr] = []
    cc_emails: List[EmailStr] = []
    bcc_emails: List[EmailStr] = []
    name: Optional[str] = None  # optional explicit name
    # Admin-only field: if provided, the message will appear to be sent by this user
    # rather than the authenticated admin. Server validates the caller has
    # `users.manage` permission before honouring it.
    as_sender_id: Optional[str] = None


class ConversationOut(BaseModel):
    id: str
    type: str
    name: Optional[str] = None
    participants: List[UserPublic] = []
    to: List[UserPublic] = []
    cc: List[UserPublic] = []
    bcc: List[UserPublic] = []
    created_by: str
    created_at: str
    last_message_at: Optional[str] = None
    last_message_preview: Optional[str] = None
    unread_count: int = 0


# ---------- Messages ----------
class AttachmentIn(BaseModel):
    file_id: str


class DraftIn(BaseModel):
    to_emails: List[EmailStr] = []
    cc_emails: List[EmailStr] = []
    bcc_emails: List[EmailStr] = []
    subject: Optional[str] = ""
    content: Optional[str] = ""
    content_html: Optional[str] = ""
    attachment_ids: List[str] = []
    conversation_id: Optional[str] = None


class DraftOut(BaseModel):
    id: str
    to_emails: List[str] = []
    cc_emails: List[str] = []
    bcc_emails: List[str] = []
    subject: str = ""
    content: str = ""
    content_html: str = ""
    attachments: List[AttachmentOut] = []
    conversation_id: Optional[str] = None
    created_at: str
    updated_at: str


class MessageCreateIn(BaseModel):
    content: str = ""
    content_html: Optional[str] = ""
    subject: Optional[str] = ""
    attachment_ids: List[str] = []
    # Admin-only field: same semantics as ConversationCreateIn.as_sender_id
    as_sender_id: Optional[str] = None


class AttachmentOut(BaseModel):
    id: str
    original_filename: str
    content_type: str
    size: int


class ReadReceipt(BaseModel):
    user_id: str
    name: Optional[str] = None
    email: Optional[str] = None
    at: str


class MessageOut(BaseModel):
    id: str
    conversation_id: str
    sender_id: str
    sender_name: str
    sender_email: Optional[str] = None
    subject: Optional[str] = ""
    content: str
    content_html: Optional[str] = ""
    attachments: List[AttachmentOut] = []
    signature_doc_id: Optional[str] = None
    created_at: str
    read_by: List[ReadReceipt] = []


# ---------- Signature Documents ----------
class SignerIn(BaseModel):
    """Either user_id (existing user) or email (will be matched against existing users)."""
    email: EmailStr
    name: Optional[str] = Field(default=None, max_length=80)


# Allowed field types — keep in sync with frontend PALETTE
SIG_FIELD_TYPES = {"signature", "initial", "date", "text", "checkbox", "mention"}


class SignatureFieldIn(BaseModel):
    """Position is stored in normalized PDF page coordinates (0..1)
    where origin = top-left of the page, like the DOM coordinate system.
    Width / height are also fractions of the page width / height.
    The backend converts to PDF points (origin bottom-left) when stamping."""
    id: Optional[str] = None
    type: str = Field(..., pattern=r"^(signature|initial|date|text|checkbox|mention)$")
    page: int = Field(..., ge=0, le=500)
    x: float = Field(..., ge=0, le=1)
    y: float = Field(..., ge=0, le=1)
    w: float = Field(..., gt=0, le=1)
    h: float = Field(..., gt=0, le=1)
    signer_email: EmailStr
    required: bool = True
    placeholder: Optional[str] = Field(default=None, max_length=80)


class SignatureDocCreateIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    file_id: str = Field(..., min_length=8)
    signers: List[SignerIn] = Field(..., min_length=1, max_length=20)
    fields: List[SignatureFieldIn] = Field(default_factory=list, max_length=200)
    message: Optional[str] = Field(default="", max_length=2000)
    # Admin-only: send the document as if this user was the creator.
    # Server validates the caller has `users.manage` permission.
    as_sender_id: Optional[str] = None
    # Admin-only: informational recipients who DO NOT sign and CANNOT open the PDF.
    # They simply receive an Inbox notification. BCC are hidden from the other
    # recipients (same semantics as email). Max 20 each.
    cc_emails: List[EmailStr] = Field(default_factory=list, max_length=20)
    bcc_emails: List[EmailStr] = Field(default_factory=list, max_length=20)


class FieldValueIn(BaseModel):
    """Value submitted by a signer for a single field. Image fields (signature,
    initial, mention) carry a base64 PNG; text/date carry a string; checkbox a bool."""
    id: str
    value_image_b64: Optional[str] = None
    value_text: Optional[str] = None
    value_bool: Optional[bool] = None


class SignDocIn(BaseModel):
    """Legacy single-signature payload (kept for old clients)."""
    signature_image_b64: str = Field(..., min_length=10)


class SubmitFieldsIn(BaseModel):
    """New multi-field submission used by the DocuSign-style flow."""
    values: List[FieldValueIn] = Field(..., min_length=1, max_length=200)


class SignerOut(BaseModel):
    user_id: Optional[str] = None
    email: EmailStr
    name: Optional[str] = None
    color: Optional[str] = None
    status: str  # "pending" | "signed" | "declined"
    signed_at: Optional[str] = None


class SignatureFieldOut(BaseModel):
    id: str
    type: str
    page: int
    x: float
    y: float
    w: float
    h: float
    signer_email: EmailStr
    required: bool = True
    placeholder: Optional[str] = None
    filled: bool = False
    filled_at: Optional[str] = None
    value_text: Optional[str] = None
    value_bool: Optional[bool] = None
    value_file_id: Optional[str] = None  # for image fields


class CcRecipientOut(BaseModel):
    """Informational (non-signer) recipient on a signature document."""
    user_id: Optional[str] = None
    email: EmailStr
    name: Optional[str] = None


class SignatureDocOut(BaseModel):
    id: str
    title: str
    message: str = ""
    original_file_id: str
    signed_file_id: Optional[str] = None
    created_by: str
    created_by_name: Optional[str] = None
    signers: List[SignerOut] = []
    fields: List[SignatureFieldOut] = []
    cc: List[CcRecipientOut] = []
    bcc: List[CcRecipientOut] = []
    status: str  # "pending" | "completed" | "declined"
    created_at: str
    completed_at: Optional[str] = None


# ---------- Message templates ----------
class TemplateVariantIn(BaseModel):
    """One tonal/contextual variant of a template (e.g. Formal / Casual /
    Urgent). The admin picks which variant to insert at compose time."""
    label: str = Field(..., min_length=1, max_length=80)
    body_html: str = Field(..., min_length=1, max_length=20000)


class TemplateVariantOut(TemplateVariantIn):
    id: str


class MessageTemplateCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=400)
    variants: List[TemplateVariantIn] = Field(..., min_length=1, max_length=10)


class MessageTemplateUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=400)
    variants: Optional[List[TemplateVariantIn]] = Field(default=None, min_length=1, max_length=10)


class MessageTemplateOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    variants: List[TemplateVariantOut]
    created_by: str
    created_by_name: Optional[str] = None
    created_at: str
    updated_at: Optional[str] = None
    usage_count: int = 0
