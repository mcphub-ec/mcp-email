"""
Email IMAP/SMTP MCP Server

Secure MCP bridge for agents to read email through IMAP and send email through
SMTP without receiving mailbox credentials.
"""

import base64
import email
import hashlib
import hmac
import html
import imaplib
import json
import logging
import os
import re
import smtplib
import ssl
from dataclasses import dataclass
from datetime import date, datetime, timezone
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
from email.utils import formatdate, getaddresses, make_msgid, parsedate_to_datetime
from typing import Any, Optional

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()


logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s", "level":"%(levelname)s", "name":"%(name)s", "message":"%(message)s"}',
)
logger = logging.getLogger("email-mcp")

DEFAULT_SEARCH_LIMIT = int(os.getenv("EMAIL_SEARCH_LIMIT_DEFAULT", "20"))
MAX_SEARCH_LIMIT = int(os.getenv("EMAIL_SEARCH_LIMIT_MAX", "100"))
MAX_BODY_CHARS = int(os.getenv("MAX_BODY_CHARS", "20000"))
MAX_ATTACHMENT_BYTES = int(os.getenv("MAX_ATTACHMENT_BYTES", "5000000"))


mcp = FastMCP(
    "Email IMAP/SMTP",
    host=os.getenv("MCP_HOST", "0.0.0.0"),
    instructions=(
        "MCP server for secure IMAP/SMTP email access. Credentials are resolved "
        "from environment variables only. Agents can list accounts, search/read "
        "mail, retrieve bounded attachments, prepare messages, and send prepared "
        "messages only with a confirmation token."
    ),
)


@dataclass(frozen=True)
class EmailAccount:
    account_id: str
    imap_host: str
    imap_port: int
    imap_user: str
    imap_password: str
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_address: str = ""
    tls_mode: str = "starttls"

    @property
    def can_read(self) -> bool:
        return bool(self.imap_host and self.imap_user and self.imap_password)

    @property
    def can_send(self) -> bool:
        return bool(self.smtp_host and self.smtp_user and self.smtp_password and self.from_address)


def _env_key(account_id: str, suffix: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", account_id).strip("_").upper()
    return f"EMAIL_{normalized}_{suffix}"


def _configured_account_ids() -> list[str]:
    raw = os.getenv("EMAIL_ACCOUNTS", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _load_account(account_id: str) -> EmailAccount:
    configured = _configured_account_ids()
    if account_id not in configured:
        raise ValueError(f"Unknown account_id '{account_id}'. Available accounts: {', '.join(configured) or 'none'}")

    def value(suffix: str, default: str = "") -> str:
        return os.getenv(_env_key(account_id, suffix), default)

    account = EmailAccount(
        account_id=account_id,
        imap_host=value("IMAP_HOST"),
        imap_port=int(value("IMAP_PORT", "993")),
        imap_user=value("IMAP_USER"),
        imap_password=value("IMAP_PASSWORD"),
        smtp_host=value("SMTP_HOST"),
        smtp_port=int(value("SMTP_PORT", "587")),
        smtp_user=value("SMTP_USER"),
        smtp_password=value("SMTP_PASSWORD"),
        from_address=value("FROM", value("SMTP_USER", value("IMAP_USER"))),
        tls_mode=value("TLS_MODE", "starttls").lower(),
    )
    if not account.can_read:
        raise ValueError(f"Account '{account_id}' is missing required IMAP environment variables.")
    if account.tls_mode not in {"starttls", "ssl"}:
        raise ValueError(f"Account '{account_id}' has invalid TLS mode: {account.tls_mode}")
    return account


def _master_key() -> bytes:
    key = os.getenv("MCP_MASTER_KEY", "")
    if not key:
        raise ValueError("MCP_MASTER_KEY env var is required to prepare or send email.")
    return key.encode("utf-8")


def _connect_imap(account: EmailAccount) -> imaplib.IMAP4_SSL:
    logger.info("Connecting IMAP account=%s host=%s", account.account_id, account.imap_host)
    client = imaplib.IMAP4_SSL(account.imap_host, account.imap_port)
    client.login(account.imap_user, account.imap_password)
    return client


def _connect_smtp(account: EmailAccount) -> smtplib.SMTP:
    logger.info("Connecting SMTP account=%s host=%s mode=%s", account.account_id, account.smtp_host, account.tls_mode)
    if account.tls_mode == "ssl":
        client = smtplib.SMTP_SSL(account.smtp_host, account.smtp_port, context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(account.smtp_host, account.smtp_port)
        client.starttls(context=ssl.create_default_context())
    client.login(account.smtp_user, account.smtp_password)
    return client


def _decode(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _message_addresses(value: Optional[str]) -> list[str]:
    return [addr for _, addr in getaddresses([_decode(value or "")]) if addr]


def _parse_date(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    except Exception:
        return None


def _decode_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _sanitize_html(html_body: str) -> str:
    sanitized = re.sub(r"(?is)<(script|style|iframe|object|embed|meta|link)[^>]*>.*?</\1>", "", html_body)
    sanitized = re.sub(r"(?is)<(script|style|iframe|object|embed|meta|link)[^>]*/?>", "", sanitized)
    sanitized = re.sub(r"(?i)\son\w+\s*=\s*(['\"]).*?\1", "", sanitized)
    sanitized = re.sub(r"(?i)\s(href|src)\s*=\s*(['\"])\s*javascript:.*?\2", r" \1=\"#\"", sanitized)
    return sanitized[:MAX_BODY_CHARS]


def _extract_message(message: Message, include_body: bool = True) -> dict[str, Any]:
    attachments: list[dict[str, Any]] = []
    text_parts: list[str] = []
    html_parts: list[str] = []
    part_index = 0

    for part in message.walk() if message.is_multipart() else [message]:
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = _decode(part.get_filename())
        payload = part.get_payload(decode=True)
        size = len(payload or b"")

        if disposition == "attachment" or filename:
            attachments.append(
                {
                    "part_id": str(part_index),
                    "filename": filename or f"attachment-{part_index}",
                    "content_type": content_type,
                    "size": size,
                    "downloadable": size <= MAX_ATTACHMENT_BYTES,
                }
            )
        elif include_body and content_type == "text/plain":
            text_parts.append(_decode_payload(part))
        elif include_body and content_type == "text/html":
            html_parts.append(_sanitize_html(_decode_payload(part)))
        part_index += 1

    text_body = "\n".join(item.strip() for item in text_parts if item.strip())[:MAX_BODY_CHARS]
    html_body = "\n".join(item.strip() for item in html_parts if item.strip())[:MAX_BODY_CHARS]

    return {
        "message_id": _decode(message.get("Message-ID")),
        "subject": _decode(message.get("Subject")),
        "from": _message_addresses(message.get("From")),
        "to": _message_addresses(message.get("To")),
        "cc": _message_addresses(message.get("Cc")),
        "date": _parse_date(message.get("Date")),
        "body_text": text_body if include_body else "",
        "body_html": html_body if include_body else "",
        "attachments": attachments,
    }


def _select_mailbox(client: imaplib.IMAP4_SSL, mailbox: str, readonly: bool = True) -> None:
    status, data = client.select(mailbox, readonly=readonly)
    if status != "OK":
        detail = data[0].decode("utf-8", errors="replace") if data else "unknown error"
        raise RuntimeError(f"Could not select mailbox '{mailbox}': {detail}")


def _fetch_message(client: imaplib.IMAP4_SSL, uid: str) -> Message:
    status, data = client.uid("fetch", uid, "(BODY.PEEK[])")
    if status != "OK" or not data:
        raise RuntimeError(f"Could not fetch message UID {uid}.")
    for item in data:
        if isinstance(item, tuple) and item[1]:
            return email.message_from_bytes(item[1])
    raise RuntimeError(f"Message UID {uid} was not returned by IMAP server.")


def _format_imap_date(value: str) -> str:
    parsed = date.fromisoformat(value)
    return parsed.strftime("%d-%b-%Y")


def _build_search_criteria(
    query: Optional[str],
    since: Optional[str],
    before: Optional[str],
    from_: Optional[str],
    to: Optional[str],
    subject: Optional[str],
) -> list[str]:
    criteria: list[str] = ["ALL"]
    if since:
        criteria.extend(["SINCE", _format_imap_date(since)])
    if before:
        criteria.extend(["BEFORE", _format_imap_date(before)])
    if from_:
        criteria.extend(["FROM", from_])
    if to:
        criteria.extend(["TO", to])
    if subject:
        criteria.extend(["SUBJECT", subject])
    if query:
        criteria.extend(["TEXT", query])
    return criteria


def _safe_limit(limit: Optional[int]) -> int:
    requested = DEFAULT_SEARCH_LIMIT if limit is None else int(limit)
    return max(1, min(requested, MAX_SEARCH_LIMIT))


def _canonical_payload(
    account_id: str,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    body_text: str,
    body_html: str,
    reply_to_uid: Optional[str],
) -> str:
    payload = {
        "account_id": account_id,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "subject": subject or "",
        "body_text": body_text or "",
        "body_html": body_html or "",
        "reply_to_uid": reply_to_uid or "",
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _send_token(canonical_payload: str) -> str:
    return _token_for_payload(canonical_payload)


def _as_list(value: Optional[list[str] | str]) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [addr.strip() for _, addr in getaddresses([value]) if addr.strip()]
    return [addr.strip() for _, addr in getaddresses(value) if addr.strip()]


def _build_outbound_message(
    account: EmailAccount,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    body_text: str,
    body_html: str,
) -> EmailMessage:
    message = EmailMessage()
    message["From"] = account.from_address
    message["To"] = ", ".join(to)
    if cc:
        message["Cc"] = ", ".join(cc)
    message["Subject"] = subject or ""
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    if body_html:
        message.set_content(body_text or html.unescape(re.sub(r"<[^>]+>", " ", body_html)))
        message.add_alternative(body_html, subtype="html")
    else:
        message.set_content(body_text or "")
    if bcc:
        message["Bcc"] = ", ".join(bcc)
    return message


def _search_uids(
    client: imaplib.IMAP4_SSL,
    mailbox: str,
    criteria: list[str],
    *,
    readonly: bool = True,
    limit: Optional[int] = None,
) -> list[str]:
    _select_mailbox(client, mailbox, readonly=readonly)
    status, data = client.uid("search", None, *criteria)
    if status != "OK":
        raise RuntimeError("IMAP SEARCH failed.")
    safe_limit = _safe_limit(limit)
    uids = (data[0].split() if data and data[0] else [])[-safe_limit:]
    return [uid.decode("ascii") for uid in uids]


def _canonical_delete_payload(
    account_id: str,
    mailbox: str,
    query: Optional[str],
    since: Optional[str],
    before: Optional[str],
    from_: Optional[str],
    to: Optional[str],
    subject: Optional[str],
    limit: Optional[int],
) -> str:
    payload = {
        "action": "delete_messages",
        "account_id": account_id,
        "mailbox": mailbox,
        "query": query or "",
        "since": since or "",
        "before": before or "",
        "from": from_ or "",
        "to": to or "",
        "subject": subject or "",
        "limit": _safe_limit(limit),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _token_for_payload(canonical_payload: str) -> str:
    digest = hmac.new(_master_key(), canonical_payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _load_reply_context(client: imaplib.IMAP4_SSL, mailbox: str, uid: str) -> dict[str, str]:
    try:
        message = _fetch_message(client, uid)
    except Exception:
        return {}
    return {
        "in_reply_to": _decode(message.get("Message-ID")),
        "references": _decode(message.get("References")),
    }


def _apply_reply_headers(message: EmailMessage, reply_context: dict[str, str]) -> None:
    in_reply_to = reply_context.get("in_reply_to", "")
    if in_reply_to:
        message["In-Reply-To"] = in_reply_to
        references = reply_context.get("references", "")
        message["References"] = f"{references} {in_reply_to}".strip() if references else in_reply_to


@mcp.tool()
def list_accounts() -> dict[str, Any]:
    """List configured account IDs and capabilities without exposing secrets."""
    accounts: list[dict[str, Any]] = []
    for account_id in _configured_account_ids():
        try:
            account = _load_account(account_id)
            accounts.append(
                {
                    "account_id": account.account_id,
                    "can_read": account.can_read,
                    "can_send": account.can_send,
                    "from_address": account.from_address if account.can_send else "",
                }
            )
        except Exception as exc:
            accounts.append({"account_id": account_id, "can_read": False, "can_send": False, "error": str(exc)})
    return {"accounts": accounts}


@mcp.tool()
def list_mailboxes(account_id: str) -> dict[str, Any]:
    """List IMAP mailboxes for a configured account."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        status, data = client.list()
        if status != "OK":
            raise RuntimeError("IMAP LIST failed.")
        mailboxes = []
        for raw in data or []:
            line = raw.decode("utf-8", errors="replace")
            match = re.search(r' "([^"]+)"$', line)
            mailbox = match.group(1) if match else line.rsplit(" ", 1)[-1].strip('"')
            mailboxes.append(mailbox)
        return {"account_id": account_id, "mailboxes": mailboxes}
    finally:
        client.logout()


@mcp.tool()
def search_emails(
    account_id: str,
    mailbox: str = "INBOX",
    query: Optional[str] = None,
    since: Optional[str] = None,
    before: Optional[str] = None,
    from_: Optional[str] = None,
    to: Optional[str] = None,
    subject: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search IMAP messages and return recent metadata without message bodies."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        criteria = _build_search_criteria(query, since, before, from_, to, subject)
        safe_limit = _safe_limit(limit)
        uids = _search_uids(client, mailbox, criteria, readonly=True, limit=safe_limit)
        results = []
        for raw_uid in reversed(uids):
            uid = raw_uid
            message = _fetch_message(client, uid)
            metadata = _extract_message(message, include_body=False)
            results.append(
                {
                    "uid": uid,
                    "subject": metadata["subject"],
                    "from": metadata["from"],
                    "to": metadata["to"],
                    "date": metadata["date"],
                    "has_attachments": bool(metadata["attachments"]),
                    "attachments": metadata["attachments"],
                }
            )
        return {"account_id": account_id, "mailbox": mailbox, "limit": safe_limit, "messages": results}
    finally:
        client.logout()


@mcp.tool()
def get_email(account_id: str, mailbox: str, uid: str, include_body: bool = True) -> dict[str, Any]:
    """Fetch an email by IMAP UID, including bounded body content and attachment metadata."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        _select_mailbox(client, mailbox, readonly=True)
        message = _fetch_message(client, uid)
        parsed = _extract_message(message, include_body=include_body)
        parsed.update({"account_id": account_id, "mailbox": mailbox, "uid": uid})
        return parsed
    finally:
        client.logout()


@mcp.tool()
def get_attachment(account_id: str, mailbox: str, uid: str, part_id: str) -> dict[str, Any]:
    """Fetch a bounded attachment by message UID and part_id."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        _select_mailbox(client, mailbox, readonly=True)
        message = _fetch_message(client, uid)
        for index, part in enumerate(message.walk() if message.is_multipart() else [message]):
            if str(index) != str(part_id):
                continue
            filename = _decode(part.get_filename())
            payload = part.get_payload(decode=True) or b""
            if len(payload) > MAX_ATTACHMENT_BYTES:
                raise ValueError(f"Attachment exceeds MAX_ATTACHMENT_BYTES ({MAX_ATTACHMENT_BYTES}).")
            return {
                "account_id": account_id,
                "mailbox": mailbox,
                "uid": uid,
                "part_id": str(part_id),
                "filename": filename or f"attachment-{part_id}",
                "content_type": part.get_content_type(),
                "size": len(payload),
                "content_base64": base64.b64encode(payload).decode("ascii"),
            }
        raise ValueError(f"Attachment part_id '{part_id}' not found.")
    finally:
        client.logout()


@mcp.tool()
def prepare_email(
    account_id: str,
    to: list[str] | str,
    cc: Optional[list[str] | str] = None,
    bcc: Optional[list[str] | str] = None,
    subject: str = "",
    body_text: str = "",
    body_html: str = "",
    reply_to_uid: Optional[str] = None,
) -> dict[str, Any]:
    """Prepare an outbound email and return a confirmation token. This does not send."""
    account = _load_account(account_id)
    if not account.can_send:
        raise ValueError(f"Account '{account_id}' is not configured for SMTP sending.")
    recipients_to = _as_list(to)
    recipients_cc = _as_list(cc)
    recipients_bcc = _as_list(bcc)
    if not recipients_to and not recipients_cc and not recipients_bcc:
        raise ValueError("At least one recipient is required.")
    canonical = _canonical_payload(
        account_id,
        recipients_to,
        recipients_cc,
        recipients_bcc,
        subject,
        body_text,
        body_html,
        reply_to_uid,
    )
    token = _send_token(canonical)
    return {
        "account_id": account_id,
        "from": account.from_address,
        "to": recipients_to,
        "cc": recipients_cc,
        "bcc": recipients_bcc,
        "subject": subject,
        "body_text_preview": (body_text or "")[:1000],
        "body_html_preview": _sanitize_html(body_html or "")[:1000],
        "reply_to_uid": reply_to_uid,
        "send_token": token,
        "send_requires_same_payload": True,
    }


@mcp.tool()
def send_prepared_email(
    account_id: str,
    to: list[str] | str,
    send_token: str,
    cc: Optional[list[str] | str] = None,
    bcc: Optional[list[str] | str] = None,
    subject: str = "",
    body_text: str = "",
    body_html: str = "",
    reply_to_uid: Optional[str] = None,
) -> dict[str, Any]:
    """Send an email only if the content matches a valid prepare_email token."""
    account = _load_account(account_id)
    if not account.can_send:
        raise ValueError(f"Account '{account_id}' is not configured for SMTP sending.")
    recipients_to = _as_list(to)
    recipients_cc = _as_list(cc)
    recipients_bcc = _as_list(bcc)
    canonical = _canonical_payload(
        account_id,
        recipients_to,
        recipients_cc,
        recipients_bcc,
        subject,
        body_text,
        body_html,
        reply_to_uid,
    )
    expected_token = _send_token(canonical)
    if not send_token or not hmac.compare_digest(send_token, expected_token):
        raise ValueError("Invalid send_token. Call prepare_email with the exact same payload before sending.")

    message = _build_outbound_message(
        account,
        recipients_to,
        recipients_cc,
        recipients_bcc,
        subject,
        body_text,
        body_html,
    )
    recipients = recipients_to + recipients_cc + recipients_bcc
    client = _connect_smtp(account)
    try:
        client.send_message(message, from_addr=account.from_address, to_addrs=recipients)
        logger.info("Sent email account=%s recipients=%d", account_id, len(recipients))
        return {"success": True, "account_id": account_id, "from": account.from_address, "recipients": recipients}
    finally:
        client.quit()


@mcp.tool()
def prepare_delete_messages(
    account_id: str,
    mailbox: str = "INBOX",
    query: Optional[str] = None,
    since: Optional[str] = None,
    before: Optional[str] = None,
    from_: Optional[str] = None,
    to: Optional[str] = None,
    subject: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Prepare a delete operation and return a confirmation token."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        criteria = _build_search_criteria(query, since, before, from_, to, subject)
        safe_limit = _safe_limit(limit)
        uids = _search_uids(client, mailbox, criteria, readonly=True, limit=safe_limit)
        canonical = _canonical_delete_payload(account_id, mailbox, query, since, before, from_, to, subject, safe_limit)
        token = _token_for_payload(canonical)
        return {
            "account_id": account_id,
            "mailbox": mailbox,
            "match_count": len(uids),
            "matching_uids": uids,
            "delete_token": token,
            "delete_requires_same_payload": True,
        }
    finally:
        client.logout()


@mcp.tool()
def email_delete_messages(
    account_id: str,
    mailbox: str = "INBOX",
    delete_token: str = "",
    query: Optional[str] = None,
    since: Optional[str] = None,
    before: Optional[str] = None,
    from_: Optional[str] = None,
    to: Optional[str] = None,
    subject: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Delete messages matching the same criteria used to prepare the delete token."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        safe_limit = _safe_limit(limit)
        canonical = _canonical_delete_payload(account_id, mailbox, query, since, before, from_, to, subject, safe_limit)
        expected_token = _token_for_payload(canonical)
        if not delete_token or not hmac.compare_digest(delete_token, expected_token):
            raise ValueError("Invalid delete_token. Call prepare_delete_messages with the exact same criteria before deleting.")

        criteria = _build_search_criteria(query, since, before, from_, to, subject)
        uids = _search_uids(client, mailbox, criteria, readonly=False, limit=safe_limit)
        deleted: list[str] = []
        for uid in uids:
            status, data = client.uid("store", uid, "+FLAGS.SILENT", r"(\Deleted)")
            if status != "OK":
                detail = data[0].decode("utf-8", errors="replace") if data else "unknown error"
                raise RuntimeError(f"Could not mark UID {uid} as deleted: {detail}")
            deleted.append(uid)
        if deleted:
            expunge_status, expunge_data = client.expunge()
            if expunge_status != "OK":
                detail = expunge_data[0].decode("utf-8", errors="replace") if expunge_data else "unknown error"
                raise RuntimeError(f"Could not expunge mailbox '{mailbox}': {detail}")
        logger.info("Deleted email account=%s mailbox=%s count=%d", account_id, mailbox, len(deleted))
        return {
            "success": True,
            "account_id": account_id,
            "mailbox": mailbox,
            "deleted_count": len(deleted),
            "deleted_uids": deleted,
        }
    finally:
        client.logout()


@mcp.tool()
def email_move_message(
    account_id: str,
    source_mailbox: str,
    uid: str,
    destination_mailbox: str,
) -> dict[str, Any]:
    """Move a single message from one mailbox to another."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        _select_mailbox(client, source_mailbox, readonly=False)
        copy_status, copy_data = client.uid("copy", uid, destination_mailbox)
        if copy_status != "OK":
            detail = copy_data[0].decode("utf-8", errors="replace") if copy_data else "unknown error"
            raise RuntimeError(f"Could not copy UID {uid} to '{destination_mailbox}': {detail}")
        store_status, store_data = client.uid("store", uid, "+FLAGS.SILENT", r"(\Deleted)")
        if store_status != "OK":
            detail = store_data[0].decode("utf-8", errors="replace") if store_data else "unknown error"
            raise RuntimeError(f"Could not mark UID {uid} as deleted after copy: {detail}")
        client.expunge()
        logger.info(
            "Moved email account=%s source=%s destination=%s uid=%s",
            account_id,
            source_mailbox,
            destination_mailbox,
            uid,
        )
        return {
            "success": True,
            "account_id": account_id,
            "source_mailbox": source_mailbox,
            "destination_mailbox": destination_mailbox,
            "uid": uid,
        }
    finally:
        client.logout()


@mcp.tool()
def email_create_folder(account_id: str, mailbox: str) -> dict[str, Any]:
    """Create an IMAP folder/mailbox if it does not already exist."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        status, data = client.create(mailbox)
        if status != "OK":
            detail = data[0].decode("utf-8", errors="replace") if data else "unknown error"
            raise RuntimeError(f"Could not create mailbox '{mailbox}': {detail}")
        logger.info("Created mailbox account=%s mailbox=%s", account_id, mailbox)
        return {"success": True, "account_id": account_id, "mailbox": mailbox}
    finally:
        client.logout()


@mcp.tool()
def email_save_draft(
    account_id: str,
    to: Optional[list[str] | str] = None,
    cc: Optional[list[str] | str] = None,
    bcc: Optional[list[str] | str] = None,
    subject: str = "",
    body_text: str = "",
    body_html: str = "",
    mailbox: str = "Drafts",
) -> dict[str, Any]:
    """Save a message as draft in the target IMAP mailbox."""
    account = _load_account(account_id)
    recipients_to = _as_list(to)
    recipients_cc = _as_list(cc)
    recipients_bcc = _as_list(bcc)

    message = _build_outbound_message(
        account,
        recipients_to,
        recipients_cc,
        recipients_bcc,
        subject,
        body_text,
        body_html,
    )
    client = _connect_imap(account)
    try:
        append_status, append_data = client.append(mailbox, r"(\Draft)", None, message.as_bytes())
        if append_status != "OK":
            detail = append_data[0].decode("utf-8", errors="replace") if append_data else "unknown error"
            raise RuntimeError(f"Could not save draft in '{mailbox}': {detail}")

        draft_uid = None
        try:
            criteria = ["HEADER", "Message-ID", message["Message-ID"]]
            uids = _search_uids(client, mailbox, criteria, readonly=True, limit=1)
            draft_uid = uids[-1] if uids else None
        except Exception:
            draft_uid = None

        logger.info("Saved draft account=%s mailbox=%s", account_id, mailbox)
        return {
            "success": True,
            "account_id": account_id,
            "mailbox": mailbox,
            "draft_uid": draft_uid,
            "message_id": message["Message-ID"],
        }
    finally:
        client.logout()


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("MCP_PORT", "8000"))
    transport_mode = os.getenv("MCP_TRANSPORT_MODE", "sse").lower()
    logger.info("Starting Email MCP Server on http://0.0.0.0:%s/mcp (%s)", port, transport_mode)
    if transport_mode == "sse":
        app = mcp.sse_app()
    elif transport_mode == "http_stream":
        app = mcp.streamable_http_app()
    else:
        raise ValueError(f"Unknown transport mode: {transport_mode}")
    uvicorn.run(app, host="0.0.0.0", port=port)
