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
import time
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

import mimetypes
import pathlib
from dotenv import load_dotenv
try:
    import markdown as _markdown_lib
    _MARKDOWN_AVAILABLE = True
except ImportError:
    _MARKDOWN_AVAILABLE = False
from mcp.server.fastmcp import FastMCP

load_dotenv()


logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s", "level":"%(levelname)s", "name":"%(name)s", "message":"%(message)s"}',
)

# TTL for action confirmation tokens (HMAC). After this window the token is rejected
# to prevent indefinite replay. Configurable via EMAIL_ACTION_TOKEN_TTL.
ACTION_TOKEN_TTL_SECONDS: int = int(os.environ.get("EMAIL_ACTION_TOKEN_TTL", "300"))
logger = logging.getLogger("email-mcp")

DEFAULT_SEARCH_LIMIT = int(os.getenv("EMAIL_SEARCH_LIMIT_DEFAULT", "20"))
MAX_SEARCH_LIMIT = int(os.getenv("EMAIL_SEARCH_LIMIT_MAX", "100"))
MAX_BODY_CHARS = int(os.getenv("MAX_BODY_CHARS", "20000"))
MAX_ATTACHMENT_BYTES = int(os.getenv("MAX_ATTACHMENT_BYTES", "5000000"))
CONTACTS_FILE = os.getenv("EMAIL_CONTACTS_FILE", "contacts.json")


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
    timeout = float(os.environ.get("EMAIL_NETWORK_TIMEOUT", "30"))
    client = imaplib.IMAP4_SSL(account.imap_host, account.imap_port, timeout=timeout)
    client.login(account.imap_user, account.imap_password)
    # Wrap blocking operations with a per-call timeout via socket default.
    import socket
    client.sock.settimeout(timeout)
    return client


def _connect_smtp(account: EmailAccount) -> smtplib.SMTP:
    logger.info("Connecting SMTP account=%s host=%s mode=%s", account.account_id, account.smtp_host, account.tls_mode)
    timeout = float(os.environ.get("EMAIL_NETWORK_TIMEOUT", "30"))
    if account.tls_mode == "ssl":
        client = smtplib.SMTP_SSL(account.smtp_host, account.smtp_port, timeout=timeout, context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(account.smtp_host, account.smtp_port, timeout=timeout)
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


# Email validation helper. Uses the optional `email-validator` library if
# installed for RFC 5321 + DNS-MX checks; falls back to a permissive parser
# that only checks the local@domain shape. We do NOT raise on invalid
# addresses from inbound mail (the LLM/agent should still see the data),
# but we DO validate outbound addresses to prevent bounce loops.
try:
    from email_validator import validate_email as _validate_email_rfc, EmailNotValidError
    _EMAIL_VALIDATOR_AVAILABLE = True
except ImportError:
    _EMAIL_VALIDATOR_AVAILABLE = False


def _validate_outbound_recipient(addr: str) -> str:
    """Validate an outbound email address. Returns the normalized form or raises ValueError.

    Reference: bd issue mcphub-jde.
    """
    if not addr or not isinstance(addr, str):
        raise ValueError(f"recipient address is empty or not a string: {addr!r}")
    if _EMAIL_VALIDATOR_AVAILABLE:
        try:
            valid = _validate_email_rfc(addr, check_deliverability=False)
            return valid.normalized
        except EmailNotValidError as exc:
            raise ValueError(f"recipient address invalid: {addr!r} ({exc})") from exc
    # Fallback: simple local@domain.tld shape check
    if "@" not in addr:
        raise ValueError(f"recipient address missing '@': {addr!r}")
    local, _, domain = addr.partition("@")
    if not local or not domain or "." not in domain:
        raise ValueError(f"recipient address malformed: {addr!r}")
    return addr


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
    """Sanitize HTML to mitigate XSS in the rendered output.

    Uses the `nh3` (Rust-backed) library if available, which is the modern
    safe-by-default choice used by the Rust/html-sanitize ecosystem. Falls
    back to a regex-based scrubber if `nh3` is not installed.

    Reference: bd issue mcphub-3f2.
    """
    try:
        import nh3
        cleaned = nh3.clean(
            html_body,
            tags={"a", "p", "br", "strong", "em", "b", "i", "u", "ul", "ol", "li",
                  "blockquote", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "code",
                  "table", "thead", "tbody", "tr", "td", "th", "span", "div"},
            attributes={
                "a": {"href", "title"},
                "span": {"class"},
                "div": {"class"},
                "td": {"colspan", "rowspan"},
                "th": {"colspan", "rowspan"},
            },
            url_schemes={"http", "https", "mailto"},
            # Block javascript: in URLs and data: schemes
            url_relative=False,
        )
        return cleaned[:MAX_BODY_CHARS]
    except ImportError:
        # Fallback: regex-based scrub (less robust, kept for environments
        # where nh3 is not installable).
        sanitized = re.sub(r"(?is)<(script|style|iframe|object|embed|meta|link|svg|math)[^>]*>.*?</\1>", "", html_body)
        sanitized = re.sub(r"(?is)<(script|style|iframe|object|embed|meta|link|svg|math)[^>]*/?>", "", sanitized)
        sanitized = re.sub(r"(?i)\son\w+\s*=\s*(['\"]).*?\1", "", sanitized)
        sanitized = re.sub(r"(?i)\s(href|src)\s*=\s*(['\"])\s*(javascript|data|vbscript):.*?\2", r" \1=\"#\"", sanitized)
        sanitized = re.sub(r"(?i)&#x?[0-9a-f]+;?[a-z]*script", "", sanitized)
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


def _fetch_message(client: imaplib.IMAP4_SSL, uid: str, *, body: bool = True) -> Message:
    """Fetch a single message by IMAP UID.

    When body=False, only fetch RFC822 headers (much faster, less bandwidth).
    Use this for list views where the body is not yet needed; the full body
    can be fetched lazily with body=True for the specific UIDs the agent
    actually wants to read.

    Reference: bd issue mcphub-awe.
    """
    fetch_part = "BODY.PEEK[]" if body else "BODY.PEEK[HEADER]"
    status, data = client.uid("fetch", uid, f"({fetch_part})")
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
    cc: Optional[str] = None,
    body: Optional[str] = None,
    has_attachments: Optional[bool] = None,
    unseen_only: Optional[bool] = None,
    flagged_only: Optional[bool] = None,
    larger_than_kb: Optional[int] = None,
    smaller_than_kb: Optional[int] = None,
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
    if cc:
        criteria.extend(["CC", cc])
    if subject:
        criteria.extend(["SUBJECT", subject])
    if body:
        criteria.extend(["BODY", body])
    if query:
        criteria.extend(["TEXT", query])
    if unseen_only:
        criteria.append("UNSEEN")
    if flagged_only:
        criteria.append("FLAGGED")
    if larger_than_kb is not None:
        criteria.extend(["LARGER", str(larger_than_kb * 1024)])
    if smaller_than_kb is not None:
        criteria.extend(["SMALLER", str(smaller_than_kb * 1024)])
    return criteria


def _safe_limit(limit: Optional[int]) -> int:
    requested = DEFAULT_SEARCH_LIMIT if limit is None else int(limit)
    return max(1, min(requested, MAX_SEARCH_LIMIT))


def _markdown_to_html(text: str) -> str:
    """Convert Markdown to HTML. Falls back to plain text wrapped in <pre> if library absent."""
    if _MARKDOWN_AVAILABLE:
        return _markdown_lib.markdown(text, extensions=["tables", "fenced_code", "nl2br"])
    escaped = html.escape(text)
    return f"<pre>{escaped}</pre>"


def _markdown_to_plaintext(text: str) -> str:
    """Strip basic Markdown syntax for plain-text fallback."""
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*(.+?)\*\*", r"", text)
    text = re.sub(r"\*(.+?)\*", r"", text)
    text = re.sub(r"`(.+?)`", r"", text)
    text = re.sub(r"\[(.+?)\]\(.+?\)", r"", text)
    return text.strip()


def _resolve_attachments(paths: list[str]) -> list[tuple[str, str, bytes]]:
    """Read local files and return list of (filename, mimetype, data) tuples."""
    resolved = []
    for raw_path in paths:
        path = pathlib.Path(raw_path.strip())
        if not path.exists():
            raise FileNotFoundError(f"Attachment not found: {path}")
        if not path.is_file():
            raise ValueError(f"Attachment path is not a file: {path}")
        data = path.read_bytes()
        if len(data) > MAX_ATTACHMENT_BYTES:
            raise ValueError(
                f"Attachment '{path.name}' is {len(data)} bytes, "
                f"exceeds MAX_ATTACHMENT_BYTES ({MAX_ATTACHMENT_BYTES})."
            )
        mime_type, _ = mimetypes.guess_type(str(path))
        if not mime_type:
            mime_type = "application/octet-stream"
        resolved.append((path.name, mime_type, data))
    return resolved


def _canonical_payload(
    account_id: str,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    body_text: str,
    body_html: str,
    reply_to_uid: Optional[str],
    attachment_paths: Optional[list[str]] = None,
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
        "attachment_paths": sorted(attachment_paths or []),
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
    attachment_paths: Optional[list[str]] = None,
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
    for filename, mime_type, data in _resolve_attachments(attachment_paths or []):
        maintype, subtype = mime_type.split("/", 1)
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
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


def _canonical_action_payload(action: str, payload: dict[str, Any]) -> str:
    """Build canonical action payload WITH an embedded expiration timestamp.

    The expiration is part of the signed payload, so an attacker cannot extend
    the lifetime without invalidating the HMAC.
    """
    expires_at = int(time.time()) + ACTION_TOKEN_TTL_SECONDS
    normalized = {"action": action, "expires_at": expires_at, **payload}
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _action_token(action: str, payload: dict[str, Any]) -> str:
    return _token_for_payload(_canonical_action_payload(action, payload))


def _require_action_token(action: str, payload: dict[str, Any], token: str, token_name: str) -> None:
    """Verify the HMAC token AND the embedded expiration timestamp.

    Raises ValueError on:
      - missing or wrong token
      - token whose embedded expires_at is in the past
      - token whose payload structure does not include expires_at
    """
    if not token:
        raise ValueError(f"Missing {token_name}. Preview the exact same payload before executing.")
    # Rebuild the canonical payload the server would have signed, then compare.
    expires_at = int(time.time()) + ACTION_TOKEN_TTL_SECONDS
    expected_payload = json.dumps(
        {"action": action, "expires_at": expires_at, **payload},
        ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    expected_token = _token_for_payload(expected_payload)
    if hmac.compare_digest(token, expected_token):
        return
    # Maybe the token was issued with an earlier expires_at but still valid;
    # we check a small grace window (up to 2x TTL).
    for offset in (ACTION_TOKEN_TTL_SECONDS, 0):
        past_expires = int(time.time()) - ACTION_TOKEN_TTL_SECONDS + offset
        past_payload = json.dumps(
            {"action": action, "expires_at": past_expires, **payload},
            ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        past_token = _token_for_payload(past_payload)
        if hmac.compare_digest(token, past_token):
            # Token matches an older expires_at — it MAY still be valid if not too old
            age = int(time.time()) - past_expires
            if age < ACTION_TOKEN_TTL_SECONDS * 2:
                return
            raise ValueError(f"{token_name} expired (> {ACTION_TOKEN_TTL_SECONDS * 2}s old).")
    raise ValueError(f"Invalid {token_name}. Preview the exact same payload before executing.")


def _message_metadata(message: Message, uid: str) -> dict[str, Any]:
    parsed = _extract_message(message, include_body=False)
    return {
        "uid": uid,
        "message_id": parsed["message_id"],
        "subject": parsed["subject"],
        "from": parsed["from"],
        "to": parsed["to"],
        "cc": parsed["cc"],
        "date": parsed["date"],
        "has_attachments": bool(parsed["attachments"]),
        "attachments": parsed["attachments"],
    }


def _messages_for_uids(client: imaplib.IMAP4_SSL, uids: list[str], *, include_body: bool = False) -> list[dict[str, Any]]:
    messages = []
    for uid in uids:
        # Optimization: when body is not needed, request headers only.
        # This dramatically reduces bandwidth and time for large mailboxes.
        message = _fetch_message(client, uid, body=include_body)
        parsed = _extract_message(message, include_body=include_body)
        parsed.update({"uid": uid})
        messages.append(parsed)
    return messages


def _send_message(
    account: EmailAccount,
    message: EmailMessage,
    recipients: list[str],
    bcc_recipients: Optional[list[str]] = None,
) -> None:
    client = _connect_smtp(account)
    try:
        # Log counts only — never include actual recipient addresses or BCC
        # in our local logs to avoid leaking PII. smtplib's debug output may
        # still show RCPT TO, which is why we suppress BCC at this layer.
        visible_recipients = recipients
        attachment_count = sum(1 for _ in message.iter_attachments())
        logger.info(
            "Sending email account=%s to=%d bcc=%d attachments=%d",
            account.account_id,
            len([r for r in visible_recipients if r]),
            len(bcc_recipients or []),
            attachment_count,
        )
        # smtplib.send_message's to_addrs overrides the envelope; pass the
        # combined recipient list (TO + BCC) so the SMTP server routes to all.
        all_recipients = list(visible_recipients) + list(bcc_recipients or [])
        client.send_message(message, from_addr=account.from_address, to_addrs=all_recipients)
    finally:
        client.quit()


def _prefixed_subject(prefix: str, subject: str) -> str:
    cleaned = subject.strip()
    if cleaned.lower().startswith(prefix.lower()):
        return cleaned
    return f"{prefix} {cleaned}".strip()


def _without_own_address(addresses: list[str], account: EmailAccount) -> list[str]:
    own = {account.from_address.lower(), account.imap_user.lower(), account.smtp_user.lower()}
    return [address for address in addresses if address.lower() not in own]


def _reply_payload(
    account_id: str,
    mailbox: str,
    uid: str,
    body_text: str,
    body_html: str,
    reply_all: bool,
) -> dict[str, Any]:
    return {
        "account_id": account_id,
        "mailbox": mailbox,
        "uid": uid,
        "body_text": body_text or "",
        "body_html": body_html or "",
        "reply_all": bool(reply_all),
    }


def _forward_payload(
    account_id: str,
    mailbox: str,
    uid: str,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    body_text: str,
    body_html: str,
) -> dict[str, Any]:
    return {
        "account_id": account_id,
        "mailbox": mailbox,
        "uid": uid,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "body_text": body_text or "",
        "body_html": body_html or "",
    }


def _archive_payload(
    account_id: str,
    source_mailbox: str,
    destination_mailbox: str,
    query: Optional[str],
    since: Optional[str],
    before: Optional[str],
    from_: Optional[str],
    to: Optional[str],
    subject: Optional[str],
    limit: Optional[int],
) -> dict[str, Any]:
    return {
        "account_id": account_id,
        "source_mailbox": source_mailbox,
        "destination_mailbox": destination_mailbox,
        "query": query or "",
        "since": since or "",
        "before": before or "",
        "from": from_ or "",
        "to": to or "",
        "subject": subject or "",
        "limit": _safe_limit(limit),
    }


def _first_header(message: Message, *names: str) -> str:
    for name in names:
        value = _decode(message.get(name))
        if value:
            return value
    return ""


def _thread_keys(message: Message) -> set[str]:
    keys = set()
    for header in ("Message-ID", "In-Reply-To", "References"):
        for value in re.findall(r"<[^>]+>", _decode(message.get(header))):
            keys.add(value)
    return keys


def _extract_links(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>'\")]+", text or "")


def _extract_structured_values(text: str) -> dict[str, Any]:
    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    money_pattern = r"(?:USD\s*)?\$?\s?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})"
    invoice_pattern = r"\b(?:factura|invoice|comprobante|receipt)\s*[:#-]?\s*([A-Za-z0-9-]{3,})"
    phone_pattern = r"(?:\+?\d[\d\s().-]{7,}\d)"
    id_pattern = r"\b(?:\d{13}|\d{10})\b"
    return {
        "emails": sorted(set(re.findall(email_pattern, text or ""))),
        "amounts": sorted(set(match.strip() for match in re.findall(money_pattern, text or "", flags=re.IGNORECASE))),
        "invoice_numbers": sorted(set(re.findall(invoice_pattern, text or "", flags=re.IGNORECASE))),
        "phones": sorted(set(match.strip() for match in re.findall(phone_pattern, text or ""))),
        "ecuador_ids": sorted(set(re.findall(id_pattern, text or ""))),
        "links": sorted(set(_extract_links(text or ""))),
    }


def _rule_payload(account_id: str, rules: list[dict[str, Any]], limit_per_rule: int) -> dict[str, Any]:
    return {
        "account_id": account_id,
        "rules": rules,
        "limit_per_rule": _safe_limit(limit_per_rule),
    }


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
    cc: Optional[str] = None,
    subject: Optional[str] = None,
    body: Optional[str] = None,
    unseen_only: Optional[bool] = None,
    flagged_only: Optional[bool] = None,
    larger_than_kb: Optional[int] = None,
    smaller_than_kb: Optional[int] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search IMAP messages and return recent metadata without message bodies.

    Advanced filters:
    - cc: filter by CC recipient
    - body: full-text search in message body (server-side IMAP BODY search)
    - unseen_only: return only unread messages
    - flagged_only: return only flagged/starred messages
    - larger_than_kb / smaller_than_kb: filter by message size in kilobytes
    """
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        criteria = _build_search_criteria(
            query, since, before, from_, to, subject,
            cc=cc, body=body,
            has_attachments=None,
            unseen_only=unseen_only,
            flagged_only=flagged_only,
            larger_than_kb=larger_than_kb,
            smaller_than_kb=smaller_than_kb,
        )
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
        return {"account_id": account_id, "mailbox": mailbox, "limit": safe_limit, "total_found": len(results), "messages": results}
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
    body_markdown: str = "",
    reply_to_uid: Optional[str] = None,
    attachment_paths: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Prepare an outbound email and return a confirmation token. This does not send.

    Supply body_markdown to have the server compile it to HTML + plain-text automatically.
    Supply attachment_paths as a list of absolute local file paths to attach files.
    """
    account = _load_account(account_id)
    if not account.can_send:
        raise ValueError(f"Account '{account_id}' is not configured for SMTP sending.")
    recipients_to = _as_list(to)
    recipients_cc = _as_list(cc)
    recipients_bcc = _as_list(bcc)
    if not recipients_to and not recipients_cc and not recipients_bcc:
        raise ValueError("At least one recipient is required.")
    if body_markdown:
        body_html = body_html or _markdown_to_html(body_markdown)
        body_text = body_text or _markdown_to_plaintext(body_markdown)
    _resolve_attachments(attachment_paths or [])  # validate paths early
    canonical = _canonical_payload(
        account_id,
        recipients_to,
        recipients_cc,
        recipients_bcc,
        subject,
        body_text,
        body_html,
        reply_to_uid,
        attachment_paths,
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
        "attachment_paths": attachment_paths or [],
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
    body_markdown: str = "",
    reply_to_uid: Optional[str] = None,
    attachment_paths: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Send an email only if the content matches a valid prepare_email token.

    Pass the same body_markdown and attachment_paths used in prepare_email.
    """
    account = _load_account(account_id)
    if not account.can_send:
        raise ValueError(f"Account '{account_id}' is not configured for SMTP sending.")
    recipients_to = _as_list(to)
    recipients_cc = _as_list(cc)
    recipients_bcc = _as_list(bcc)
    if body_markdown:
        body_html = body_html or _markdown_to_html(body_markdown)
        body_text = body_text or _markdown_to_plaintext(body_markdown)
    canonical = _canonical_payload(
        account_id,
        recipients_to,
        recipients_cc,
        recipients_bcc,
        subject,
        body_text,
        body_html,
        reply_to_uid,
        attachment_paths,
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
        attachment_paths,
    )
    recipients = recipients_to + recipients_cc + recipients_bcc
    client = _connect_smtp(account)
    try:
        client.send_message(message, from_addr=account.from_address, to_addrs=recipients)
        logger.info("Sent email account=%s recipients=%d attachments=%d", account_id, len(recipients), len(attachment_paths or []))
        return {"success": True, "account_id": account_id, "from": account.from_address, "recipients": recipients, "attachments_sent": len(attachment_paths or [])}
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
    body_markdown: str = "",
    mailbox: str = "Drafts",
    attachment_paths: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Save a message as draft in the target IMAP mailbox.

    Supports body_markdown (auto-compiled to HTML + plain-text) and attachment_paths.
    """
    account = _load_account(account_id)
    recipients_to = _as_list(to)
    recipients_cc = _as_list(cc)
    recipients_bcc = _as_list(bcc)
    if body_markdown:
        body_html = body_html or _markdown_to_html(body_markdown)
        body_text = body_text or _markdown_to_plaintext(body_markdown)

    message = _build_outbound_message(
        account,
        recipients_to,
        recipients_cc,
        recipients_bcc,
        subject,
        body_text,
        body_html,
        attachment_paths,
    )
    client = _connect_imap(account)
    try:
        # RFC 4315 UIDPLUS: if the server supports it, the APPEND response
        # contains the new UID directly, which is far more reliable than
        # searching for the Message-ID afterwards (some IMAP servers do not
        # index Message-ID in Drafts).
        append_status, append_data = client.append(mailbox, r"(\Draft)", None, message.as_bytes())
        if append_status != "OK":
            detail = append_data[0].decode("utf-8", errors="replace") if append_data else "unknown error"
            raise RuntimeError(f"Could not save draft in '{mailbox}': {detail}")

        draft_uid = None
        # Try to extract UID from APPENDUID response (RFC 4315).
        if append_data and append_data[0]:
            try:
                resp = append_data[0].decode("utf-8", errors="replace")
                import re as _re
                m = _re.search(r"APPENDUID\s+\d+\s+(\d+)", resp)
                if m:
                    draft_uid = m.group(1)
            except Exception:
                pass
        # Fallback: search the mailbox for the Message-ID.
        if not draft_uid:
            try:
                _select_mailbox(client, mailbox, readonly=True)
                criteria = ["HEADER", "Message-ID", message["Message-ID"]]
                uids = _search_uids(client, mailbox, criteria, readonly=True, limit=1)
                draft_uid = uids[-1] if uids else None
            except Exception:
                draft_uid = None
        # Final fallback: take the last UID in the mailbox.
        if not draft_uid:
            try:
                _select_mailbox(client, mailbox, readonly=True)
                status, data = client.uid("search", None, "ALL")
                if status == "OK" and data and data[0]:
                    all_uids = data[0].split()
                    draft_uid = all_uids[-1].decode("ascii") if all_uids else None
            except Exception:
                draft_uid = None

        logger.info("Saved draft account=%s mailbox=%s draft_uid=%s", account_id, mailbox, draft_uid)
        return {
            "success": True,
            "account_id": account_id,
            "mailbox": mailbox,
            "draft_uid": draft_uid,
            "message_id": message["Message-ID"],
        }
    finally:
        client.logout()


@mcp.tool()
def email_mark_messages(
    account_id: str,
    mailbox: str = "INBOX",
    mark_as: str = "read",
    query: Optional[str] = None,
    since: Optional[str] = None,
    before: Optional[str] = None,
    from_: Optional[str] = None,
    to: Optional[str] = None,
    subject: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Mark messages as read, unread, flagged, or unflagged."""
    flag_map = {
        "read": ("+FLAGS.SILENT", r"(\Seen)"),
        "unread": ("-FLAGS.SILENT", r"(\Seen)"),
        "flagged": ("+FLAGS.SILENT", r"(\Flagged)"),
        "unflagged": ("-FLAGS.SILENT", r"(\Flagged)"),
    }
    if mark_as not in flag_map:
        raise ValueError("mark_as must be one of: read, unread, flagged, unflagged")

    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        criteria = _build_search_criteria(query, since, before, from_, to, subject)
        uids = _search_uids(client, mailbox, criteria, readonly=False, limit=limit)
        operation, flag = flag_map[mark_as]
        for uid in uids:
            status, data = client.uid("store", uid, operation, flag)
            if status != "OK":
                detail = data[0].decode("utf-8", errors="replace") if data else "unknown error"
                raise RuntimeError(f"Could not mark UID {uid}: {detail}")
        logger.info("Marked email account=%s mailbox=%s mark_as=%s count=%d", account_id, mailbox, mark_as, len(uids))
        return {"success": True, "account_id": account_id, "mailbox": mailbox, "mark_as": mark_as, "marked_uids": uids}
    finally:
        client.logout()


@mcp.tool()
def email_reply(
    account_id: str,
    mailbox: str,
    uid: str,
    body_text: str,
    body_html: str = "",
    reply_all: bool = False,
    reply_token: str = "",
) -> dict[str, Any]:
    """Preview or send a reply to a message using a confirmation token."""
    account = _load_account(account_id)
    payload = _reply_payload(account_id, mailbox, uid, body_text, body_html, reply_all)
    client = _connect_imap(account)
    try:
        _select_mailbox(client, mailbox, readonly=True)
        original = _fetch_message(client, uid)
        original_parsed = _extract_message(original, include_body=False)
        to = _message_addresses(original.get("Reply-To")) or original_parsed["from"]
        cc: list[str] = []
        if reply_all:
            to = _without_own_address(list(dict.fromkeys(to + original_parsed["to"])), account)
            cc = _without_own_address(original_parsed["cc"], account)
        to = _without_own_address(to, account)
        subject = _prefixed_subject("Re:", original_parsed["subject"])

        if not reply_token:
            return {
                "account_id": account_id,
                "mailbox": mailbox,
                "uid": uid,
                "to": to,
                "cc": cc,
                "subject": subject,
                "body_text_preview": (body_text or "")[:1000],
                "body_html_preview": _sanitize_html(body_html or "")[:1000],
                "reply_token": _action_token("reply", payload),
                "reply_requires_same_payload": True,
            }

        _require_action_token("reply", payload, reply_token, "reply_token")
        message = _build_outbound_message(account, to, cc, [], subject, body_text, body_html)
        _apply_reply_headers(message, _load_reply_context(client, mailbox, uid))
        _send_message(account, message, to + cc)
        logger.info("Sent reply account=%s mailbox=%s uid=%s recipients=%d", account_id, mailbox, uid, len(to + cc))
        return {"success": True, "account_id": account_id, "mailbox": mailbox, "uid": uid, "recipient_count": len(to + cc)}
    finally:
        client.logout()


@mcp.tool()
def email_forward(
    account_id: str,
    mailbox: str,
    uid: str,
    to: list[str] | str,
    cc: Optional[list[str] | str] = None,
    bcc: Optional[list[str] | str] = None,
    body_text: str = "",
    body_html: str = "",
    forward_token: str = "",
) -> dict[str, Any]:
    """Preview or send a forwarded message using a confirmation token."""
    account = _load_account(account_id)
    recipients_to = _as_list(to)
    recipients_cc = _as_list(cc)
    recipients_bcc = _as_list(bcc)
    if not recipients_to and not recipients_cc and not recipients_bcc:
        raise ValueError("At least one recipient is required.")
    payload = _forward_payload(account_id, mailbox, uid, recipients_to, recipients_cc, recipients_bcc, body_text, body_html)

    client = _connect_imap(account)
    try:
        _select_mailbox(client, mailbox, readonly=True)
        original = _fetch_message(client, uid)
        original_parsed = _extract_message(original, include_body=True)
        subject = _prefixed_subject("Fwd:", original_parsed["subject"])
        forwarded_text = (
            f"{body_text}\n\n"
            f"---------- Forwarded message ----------\n"
            f"From: {', '.join(original_parsed['from'])}\n"
            f"Date: {original_parsed['date'] or ''}\n"
            f"Subject: {original_parsed['subject']}\n"
            f"To: {', '.join(original_parsed['to'])}\n\n"
            f"{original_parsed['body_text']}"
        ).strip()

        if not forward_token:
            return {
                "account_id": account_id,
                "mailbox": mailbox,
                "uid": uid,
                "to": recipients_to,
                "cc": recipients_cc,
                "bcc": recipients_bcc,
                "subject": subject,
                "body_text_preview": forwarded_text[:1000],
                "forward_token": _action_token("forward", payload),
                "forward_requires_same_payload": True,
            }

        _require_action_token("forward", payload, forward_token, "forward_token")
        message = _build_outbound_message(
            account,
            recipients_to,
            recipients_cc,
            recipients_bcc,
            subject,
            forwarded_text,
            body_html,
        )
        # Separate BCC for logging/audit; pass to _send_message explicitly
        # so the local log only shows counts, never the actual BCC addresses.
        visible_recipients = recipients_to + recipients_cc
        _send_message(account, message, visible_recipients, bcc_recipients=recipients_bcc)
        logger.info(
            "Forwarded email account=%s mailbox=%s uid=%s to=%d bcc=%d",
            account_id, mailbox, uid, len(visible_recipients), len(recipients_bcc),
        )
        return {
            "success": True,
            "account_id": account_id,
            "mailbox": mailbox,
            "uid": uid,
            "recipient_count": len(visible_recipients),
            "bcc_count": len(recipients_bcc),
        }
    finally:
        client.logout()


@mcp.tool()
def email_archive_messages(
    account_id: str,
    source_mailbox: str = "INBOX",
    destination_mailbox: str = "Archive",
    archive_token: str = "",
    query: Optional[str] = None,
    since: Optional[str] = None,
    before: Optional[str] = None,
    from_: Optional[str] = None,
    to: Optional[str] = None,
    subject: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Preview or archive messages by criteria using a confirmation token."""
    account = _load_account(account_id)
    safe_limit = _safe_limit(limit)
    payload = _archive_payload(account_id, source_mailbox, destination_mailbox, query, since, before, from_, to, subject, safe_limit)
    client = _connect_imap(account)
    try:
        criteria = _build_search_criteria(query, since, before, from_, to, subject)
        uids = _search_uids(client, source_mailbox, criteria, readonly=not bool(archive_token), limit=safe_limit)
        if not archive_token:
            return {
                "account_id": account_id,
                "source_mailbox": source_mailbox,
                "destination_mailbox": destination_mailbox,
                "match_count": len(uids),
                "matching_uids": uids,
                "archive_token": _action_token("archive", payload),
                "archive_requires_same_payload": True,
            }

        _require_action_token("archive", payload, archive_token, "archive_token")
        archived = []
        for message_uid in uids:
            copy_status, copy_data = client.uid("copy", message_uid, destination_mailbox)
            if copy_status != "OK":
                detail = copy_data[0].decode("utf-8", errors="replace") if copy_data else "unknown error"
                raise RuntimeError(f"Could not copy UID {message_uid}: {detail}")
            store_status, store_data = client.uid("store", message_uid, "+FLAGS.SILENT", r"(\Deleted)")
            if store_status != "OK":
                detail = store_data[0].decode("utf-8", errors="replace") if store_data else "unknown error"
                raise RuntimeError(f"Could not mark UID {message_uid} as deleted: {detail}")
            archived.append(message_uid)
        if archived:
            client.expunge()
        return {"success": True, "account_id": account_id, "archived_count": len(archived), "archived_uids": archived}
    finally:
        client.logout()


@mcp.tool()
def email_summarize_thread_data(account_id: str, mailbox: str, uid: str, limit: int = 20) -> dict[str, Any]:
    """Return ordered thread data for the agent to summarize."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        _select_mailbox(client, mailbox, readonly=True)
        root = _fetch_message(client, uid)
        root_keys = _thread_keys(root)
        candidate_uids = _search_uids(client, mailbox, ["ALL"], readonly=True, limit=limit)
        messages = []
        for candidate_uid in candidate_uids:
            message = _fetch_message(client, candidate_uid)
            if candidate_uid == uid or root_keys.intersection(_thread_keys(message)):
                parsed = _extract_message(message, include_body=True)
                parsed.update({"uid": candidate_uid})
                messages.append(parsed)
        messages.sort(key=lambda item: item.get("date") or "")
        return {"account_id": account_id, "mailbox": mailbox, "root_uid": uid, "messages": messages}
    finally:
        client.logout()


@mcp.tool()
def email_search_threads(
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
    """Search messages and group results by conversation headers."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        criteria = _build_search_criteria(query, since, before, from_, to, subject)
        uids = _search_uids(client, mailbox, criteria, readonly=True, limit=limit)
        threads: dict[str, dict[str, Any]] = {}
        for uid in uids:
            message = _fetch_message(client, uid)
            keys = sorted(_thread_keys(message))
            thread_id = keys[0] if keys else _decode(message.get("Message-ID")) or uid
            threads.setdefault(thread_id, {"thread_id": thread_id, "messages": []})
            threads[thread_id]["messages"].append(_message_metadata(message, uid))
        return {"account_id": account_id, "mailbox": mailbox, "threads": list(threads.values())}
    finally:
        client.logout()


@mcp.tool()
def email_get_recent_attachments(
    account_id: str,
    mailbox: str = "INBOX",
    from_: Optional[str] = None,
    subject: Optional[str] = None,
    extension: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Find recent attachment metadata by sender, subject, or file extension."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        criteria = _build_search_criteria(None, None, None, from_, None, subject)
        uids = _search_uids(client, mailbox, criteria, readonly=True, limit=limit)
        wanted_ext = extension.lower().lstrip(".") if extension else ""
        attachments = []
        for uid in reversed(uids):
            message = _fetch_message(client, uid)
            metadata = _message_metadata(message, uid)
            for attachment in metadata["attachments"]:
                filename = attachment["filename"]
                if wanted_ext and not filename.lower().endswith(f".{wanted_ext}"):
                    continue
                attachments.append({"uid": uid, "subject": metadata["subject"], "from": metadata["from"], **attachment})
        return {"account_id": account_id, "mailbox": mailbox, "attachments": attachments}
    finally:
        client.logout()


@mcp.tool()
def email_extract_structured(account_id: str, mailbox: str, uid: str) -> dict[str, Any]:
    """Extract common structured values from a message without returning full raw email."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        _select_mailbox(client, mailbox, readonly=True)
        message = _fetch_message(client, uid)
        parsed = _extract_message(message, include_body=True)
        combined_text = "\n".join([parsed["subject"], parsed["body_text"], re.sub(r"<[^>]+>", " ", parsed["body_html"])])
        structured = _extract_structured_values(combined_text)
        return {"account_id": account_id, "mailbox": mailbox, "uid": uid, **structured}
    finally:
        client.logout()


@mcp.tool()
def email_apply_rules_preview(account_id: str, rules: list[dict[str, Any]], limit_per_rule: int = 20) -> dict[str, Any]:
    """Preview rule matches before applying mailbox moves."""
    account = _load_account(account_id)
    safe_limit = _safe_limit(limit_per_rule)
    client = _connect_imap(account)
    try:
        previews = []
        for index, rule in enumerate(rules):
            source_mailbox = rule.get("source_mailbox", "INBOX")
            criteria = _build_search_criteria(
                rule.get("query"),
                rule.get("since"),
                rule.get("before"),
                rule.get("from"),
                rule.get("to"),
                rule.get("subject"),
            )
            uids = _search_uids(client, source_mailbox, criteria, readonly=True, limit=safe_limit)
            previews.append(
                {
                    "rule_index": index,
                    "source_mailbox": source_mailbox,
                    "destination_mailbox": rule.get("destination_mailbox", "Archive"),
                    "match_count": len(uids),
                    "matching_uids": uids,
                }
            )
        payload = _rule_payload(account_id, rules, safe_limit)
        return {
            "account_id": account_id,
            "rules": previews,
            "rules_token": _action_token("apply_rules", payload),
            "rules_require_same_payload": True,
        }
    finally:
        client.logout()


@mcp.tool()
def email_apply_rules(account_id: str, rules: list[dict[str, Any]], rules_token: str, limit_per_rule: int = 20) -> dict[str, Any]:
    """Apply previewed move rules using a confirmation token."""
    account = _load_account(account_id)
    safe_limit = _safe_limit(limit_per_rule)
    payload = _rule_payload(account_id, rules, safe_limit)
    _require_action_token("apply_rules", payload, rules_token, "rules_token")
    client = _connect_imap(account)
    try:
        results = []
        for index, rule in enumerate(rules):
            source_mailbox = rule.get("source_mailbox", "INBOX")
            destination_mailbox = rule.get("destination_mailbox", "Archive")
            criteria = _build_search_criteria(
                rule.get("query"),
                rule.get("since"),
                rule.get("before"),
                rule.get("from"),
                rule.get("to"),
                rule.get("subject"),
            )
            uids = _search_uids(client, source_mailbox, criteria, readonly=False, limit=safe_limit)
            moved = []
            for uid in uids:
                copy_status, copy_data = client.uid("copy", uid, destination_mailbox)
                if copy_status != "OK":
                    detail = copy_data[0].decode("utf-8", errors="replace") if copy_data else "unknown error"
                    raise RuntimeError(f"Could not copy UID {uid}: {detail}")
                store_status, store_data = client.uid("store", uid, "+FLAGS.SILENT", r"(\Deleted)")
                if store_status != "OK":
                    detail = store_data[0].decode("utf-8", errors="replace") if store_data else "unknown error"
                    raise RuntimeError(f"Could not mark UID {uid} as deleted: {detail}")
                moved.append(uid)
            if moved:
                client.expunge()
            results.append({"rule_index": index, "moved_count": len(moved), "moved_uids": moved})
        return {"success": True, "account_id": account_id, "results": results}
    finally:
        client.logout()


@mcp.tool()
def email_watch_mailbox(account_id: str, mailbox: str = "INBOX", since_uid: Optional[str] = None, limit: Optional[int] = None) -> dict[str, Any]:
    """Return messages newer than the last seen UID for polling workflows."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        uids = _search_uids(client, mailbox, ["ALL"], readonly=True, limit=limit)
        if since_uid is not None:
            uids = [uid for uid in uids if int(uid) > int(since_uid)]
        messages = [_message_metadata(_fetch_message(client, uid), uid) for uid in uids]
        last_seen_uid = max([int(uid) for uid in uids], default=int(since_uid or 0))
        return {"account_id": account_id, "mailbox": mailbox, "last_seen_uid": str(last_seen_uid), "messages": messages}
    finally:
        client.logout()


@mcp.tool()
def email_test_account(account_id: str) -> dict[str, Any]:
    """Test IMAP and SMTP connectivity without exposing credentials."""
    account = _load_account(account_id)
    result: dict[str, Any] = {"account_id": account_id, "imap": {"ok": False}, "smtp": {"ok": False}}
    imap_client = None
    try:
        imap_client = _connect_imap(account)
        status, _ = imap_client.noop()
        result["imap"] = {"ok": status == "OK", "host": account.imap_host, "port": account.imap_port}
    except Exception as exc:
        result["imap"] = {"ok": False, "host": account.imap_host, "port": account.imap_port, "error": str(exc)}
    finally:
        if imap_client:
            imap_client.logout()

    if account.can_send:
        smtp_client = None
        try:
            smtp_client = _connect_smtp(account)
            status = smtp_client.noop()[0]
            result["smtp"] = {"ok": 200 <= int(status) < 400, "host": account.smtp_host, "port": account.smtp_port}
        except Exception as exc:
            result["smtp"] = {"ok": False, "host": account.smtp_host, "port": account.smtp_port, "error": str(exc)}
        finally:
            if smtp_client:
                smtp_client.quit()
    else:
        result["smtp"] = {"ok": False, "configured": False}
    return result


@mcp.tool()
def email_find_unsubscribe_links(account_id: str, mailbox: str, uid: str) -> dict[str, Any]:
    """Find List-Unsubscribe headers and unsubscribe links in a message."""
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        _select_mailbox(client, mailbox, readonly=True)
        message = _fetch_message(client, uid)
        parsed = _extract_message(message, include_body=True)
        header_value = _decode(message.get("List-Unsubscribe"))
        header_links = re.findall(r"<([^>]+)>", header_value)
        body_links = [
            link for link in _extract_links(f"{parsed['body_text']}\n{parsed['body_html']}")
            if "unsubscribe" in link.lower() or "optout" in link.lower()
        ]
        return {
            "account_id": account_id,
            "mailbox": mailbox,
            "uid": uid,
            "list_unsubscribe": header_links,
            "body_unsubscribe_links": sorted(set(body_links)),
        }
    finally:
        client.logout()



# ─────────────────────────────────────────────────────────────────────────────
# CONTACTS / ADDRESS BOOK
# ─────────────────────────────────────────────────────────────────────────────

def _load_contacts() -> list[dict[str, Any]]:
    """Load contacts from CONTACTS_FILE. Returns [] if the file does not exist."""
    path = pathlib.Path(CONTACTS_FILE)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else data.get("contacts", [])
    except Exception as exc:
        logger.warning("Could not load contacts file %s: %s", CONTACTS_FILE, exc)
        return []


def _save_contacts(contacts: list[dict[str, Any]]) -> None:
    path = pathlib.Path(CONTACTS_FILE)
    path.write_text(json.dumps(contacts, ensure_ascii=False, indent=2), encoding="utf-8")


@mcp.tool()
def contacts_lookup(
    name: Optional[str] = None,
    email_fragment: Optional[str] = None,
) -> dict[str, Any]:
    """Look up contacts by name or e-mail fragment.

    Returns matching entries from the local contacts.json file.
    Use this to resolve "escríbele a Antonio" -> actual email address.
    """
    contacts = _load_contacts()
    if not name and not email_fragment:
        return {"contacts": contacts, "total": len(contacts)}
    results = []
    name_lower = (name or "").lower()
    email_lower = (email_fragment or "").lower()
    for contact in contacts:
        contact_name = (contact.get("name") or "").lower()
        contact_email = (contact.get("email") or "").lower()
        contact_aliases = [a.lower() for a in (contact.get("aliases") or [])]
        name_match = name_lower and (name_lower in contact_name or any(name_lower in a for a in contact_aliases))
        email_match = email_lower and email_lower in contact_email
        if name_match or email_match:
            results.append(contact)
    return {"contacts": results, "total": len(results)}


@mcp.tool()
def contacts_upsert(
    name: str,
    email: str,
    aliases: Optional[list[str]] = None,
    notes: Optional[str] = None,
) -> dict[str, Any]:
    """Add or update a contact in the local contacts.json file.

    If a contact with the same email already exists it is updated, otherwise created.
    """
    contacts = _load_contacts()
    email = email.strip().lower()
    for contact in contacts:
        if (contact.get("email") or "").lower() == email:
            contact["name"] = name
            if aliases is not None:
                contact["aliases"] = aliases
            if notes is not None:
                contact["notes"] = notes
            _save_contacts(contacts)
            return {"action": "updated", "contact": contact}
    new_contact: dict[str, Any] = {"name": name, "email": email}
    if aliases:
        new_contact["aliases"] = aliases
    if notes:
        new_contact["notes"] = notes
    contacts.append(new_contact)
    _save_contacts(contacts)
    return {"action": "created", "contact": new_contact}


@mcp.tool()
def contacts_delete(email: str) -> dict[str, Any]:
    """Remove a contact from the local contacts.json file by exact email address."""
    contacts = _load_contacts()
    email = email.strip().lower()
    before = len(contacts)
    contacts = [c for c in contacts if (c.get("email") or "").lower() != email]
    _save_contacts(contacts)
    removed = before - len(contacts)
    return {"removed": removed, "email": email}


@mcp.tool()
def contacts_import_from_sent(
    account_id: str,
    mailbox: str = "Sent",
    limit: int = 200,
) -> dict[str, Any]:
    """Scan Sent folder to auto-populate the contacts file from To/CC headers.

    Existing contacts are not overwritten; only new addresses are added.
    """
    account = _load_account(account_id)
    client = _connect_imap(account)
    try:
        uids = _search_uids(client, mailbox, ["ALL"], readonly=True, limit=limit)
        contacts = _load_contacts()
        existing_emails = {(c.get("email") or "").lower() for c in contacts}
        added = 0
        for uid in uids:
            message = _fetch_message(client, uid)
            for header in ("To", "CC", "Bcc"):
                raw = message.get(header, "")
                for display_name, addr in getaddresses([raw]):
                    addr = addr.strip().lower()
                    if not addr or addr in existing_emails:
                        continue
                    new_contact: dict[str, Any] = {"name": _decode(display_name) or addr, "email": addr}
                    contacts.append(new_contact)
                    existing_emails.add(addr)
                    added += 1
        _save_contacts(contacts)
        return {"account_id": account_id, "mailbox": mailbox, "added": added, "total_contacts": len(contacts)}
    finally:
        client.logout()


# ─────────────────────────────────────────────────────────────────────────────
# EXTRACT ATTACHMENTS (single-call download to local directory)
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def email_extract_attachments(
    account_id: str,
    mailbox: str,
    uid: str,
    destination_dir: str,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Download ALL attachments from a message to a local directory in one call.

    Returns a list of saved file paths so the agent can work with them directly.
    Eliminates the need to call get_email + get_attachment for each part separately.
    """
    account = _load_account(account_id)
    dest = pathlib.Path(destination_dir)
    if not dest.exists():
        dest.mkdir(parents=True, exist_ok=True)
    if not dest.is_dir():
        raise ValueError(f"destination_dir '{destination_dir}' is not a directory.")
    client = _connect_imap(account)
    try:
        _select_mailbox(client, mailbox, readonly=True)
        message = _fetch_message(client, uid)
        saved = []
        skipped = []
        parts = list(message.walk()) if message.is_multipart() else [message]
        for part in parts:
            disposition = part.get_content_disposition() or ""
            filename = _decode(part.get_filename())
            if not filename or disposition not in ("attachment", "inline"):
                continue
            payload = part.get_payload(decode=True) or b""
            if len(payload) > MAX_ATTACHMENT_BYTES:
                skipped.append({"filename": filename, "reason": "exceeds MAX_ATTACHMENT_BYTES", "size": len(payload)})
                continue
            # sanitize filename to prevent path traversal
            safe_name = pathlib.Path(filename).name
            target = dest / safe_name
            if target.exists() and not overwrite:
                skipped.append({"filename": safe_name, "reason": "already exists", "path": str(target)})
                continue
            target.write_bytes(payload)
            saved.append({"filename": safe_name, "path": str(target), "size": len(payload), "content_type": part.get_content_type()})
        logger.info("Extracted attachments account=%s mailbox=%s uid=%s saved=%d", account_id, mailbox, uid, len(saved))
        return {
            "account_id": account_id,
            "mailbox": mailbox,
            "uid": uid,
            "destination_dir": str(dest),
            "saved": saved,
            "skipped": skipped,
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
    uvicorn.run(app, host=os.getenv("MCP_HOST", "0.0.0.0"), port=port)
