import base64
import importlib
import os
import sys
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import Mock

import pytest


SERVER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_DIR))


def load_server(monkeypatch):
    monkeypatch.setenv("EMAIL_ACCOUNTS", "personal")
    monkeypatch.setenv("EMAIL_PERSONAL_IMAP_HOST", "imap.example.com")
    monkeypatch.setenv("EMAIL_PERSONAL_IMAP_PORT", "993")
    monkeypatch.setenv("EMAIL_PERSONAL_IMAP_USER", "reader@example.com")
    monkeypatch.setenv("EMAIL_PERSONAL_IMAP_PASSWORD", "imap-secret")
    monkeypatch.setenv("EMAIL_PERSONAL_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("EMAIL_PERSONAL_SMTP_PORT", "587")
    monkeypatch.setenv("EMAIL_PERSONAL_SMTP_USER", "sender@example.com")
    monkeypatch.setenv("EMAIL_PERSONAL_SMTP_PASSWORD", "smtp-secret")
    monkeypatch.setenv("EMAIL_PERSONAL_FROM", "sender@example.com")
    monkeypatch.setenv("EMAIL_PERSONAL_TLS_MODE", "starttls")
    monkeypatch.setenv("MCP_MASTER_KEY", "test-master-key")
    if "server" in sys.modules:
        return importlib.reload(sys.modules["server"])
    return importlib.import_module("server")


def sample_message() -> EmailMessage:
    message = EmailMessage()
    message["Message-ID"] = "<msg-102@example.com>"
    message["Subject"] = "=?utf-8?q?Factura_=C3=A9xito?="
    message["From"] = "Alice <alice@example.com>"
    message["To"] = "Bob <bob@example.com>"
    message["Cc"] = "Carol <carol@example.com>"
    message["Date"] = "Wed, 06 May 2026 12:00:00 +0000"
    message["List-Unsubscribe"] = "<https://example.com/unsubscribe?id=123>"
    message.set_content("Hola mundo\nFactura F001-002 por $123.45 RUC 0999999999001 https://example.com/pay")
    message.add_alternative(
        "<html><body><script>bad()</script><p onclick=\"bad()\">Hola</p>"
        "<a href=\"https://example.com/unsubscribe\">unsubscribe</a></body></html>",
        subtype="html",
    )
    message.add_attachment(b"PDF", maintype="application", subtype="pdf", filename="factura.pdf")
    return message


class FakeIMAP:
    def __init__(self, message_bytes: bytes):
        self.mailboxes = {
            "INBOX": {"102": message_bytes},
            "Archive": {},
            "Drafts": {},
        }
        self.message_bytes = message_bytes
        self.selected = []
        self.uid_calls = []
        self.created_mailboxes = []
        self.appended = []
        self.expunge_count = 0
        self.flags = {}
        self.logged_out = False
        self.selected_mailbox = "INBOX"

    def login(self, user, password):
        self.user = user
        self.password = password

    def select(self, mailbox, readonly=True):
        self.selected.append((mailbox, readonly))
        self.selected_mailbox = mailbox
        return "OK", [b"1"]

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "Archive"']

    def uid(self, command, *args):
        normalized = command.lower()
        self.uid_calls.append((normalized, args))
        if normalized == "search":
            mailbox = self.selected_mailbox
            criteria = [item.decode("utf-8") if isinstance(item, bytes) else str(item) for item in args]
            uids = sorted(self.mailboxes.get(mailbox, {}).keys())
            if criteria[:2] == ["HEADER", "Message-ID"] and len(criteria) >= 3:
                needle = criteria[2]
                uids = [
                    uid
                    for uid, raw in self.mailboxes.get(mailbox, {}).items()
                    if needle in raw.decode("utf-8", errors="ignore")
                ]
            if "UID" in criteria:
                start = criteria.index("UID") + 1
                requested = criteria[start].split(",")
                uids = [uid for uid in uids if uid in requested]
            return "OK", [" ".join(uids).encode("ascii")]
        if normalized == "fetch":
            uid = str(args[0])
            raw = self.mailboxes.get(self.selected_mailbox, {}).get(uid, self.message_bytes)
            return "OK", [(f"{uid} (RFC822 {{1}}".encode("ascii"), raw)]
        if normalized == "copy":
            uid = str(args[0])
            dest = str(args[1])
            raw = self.mailboxes.get(self.selected_mailbox, {}).get(uid, self.message_bytes)
            self.mailboxes.setdefault(dest, {})[uid] = raw
            return "OK", [b"copied"]
        if normalized == "store":
            uid = str(args[0])
            operation = str(args[1])
            flag = str(args[2])
            self.flags.setdefault(self.selected_mailbox, {}).setdefault(uid, set())
            if operation.startswith("+"):
                self.flags[self.selected_mailbox][uid].add(flag)
            elif operation.startswith("-"):
                self.flags[self.selected_mailbox][uid].discard(flag)
            if "Deleted" in flag and uid in self.mailboxes.get(self.selected_mailbox, {}):
                del self.mailboxes[self.selected_mailbox][uid]
            return "OK", [b"stored"]
        return "NO", []

    def noop(self):
        return "OK", [b"noop"]

    def create(self, mailbox):
        if mailbox in self.mailboxes:
            return "NO", [b"already exists"]
        self.mailboxes[mailbox] = {}
        self.created_mailboxes.append(mailbox)
        return "OK", [b"created"]

    def append(self, mailbox, flags, date_time, message):
        self.mailboxes.setdefault(mailbox, {})
        next_uid = str(max([int(uid) for uid in self.mailboxes[mailbox].keys()] + [0]) + 1)
        self.mailboxes[mailbox][next_uid] = message
        self.appended.append((mailbox, flags, date_time, message))
        return "OK", [b"appended"]

    def expunge(self):
        self.expunge_count += 1
        return "OK", [b"expunged"]

    def logout(self):
        self.logged_out = True


class FakeSMTP:
    sent = []

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def starttls(self, context=None):
        self.started_tls = True

    def login(self, user, password):
        self.user = user
        self.password = password

    def send_message(self, message, from_addr=None, to_addrs=None):
        FakeSMTP.sent.append((message, from_addr, to_addrs))

    def quit(self):
        self.closed = True

    def noop(self):
        return 250, b"OK"


def test_load_account_and_list_accounts_never_expose_secrets(monkeypatch):
    server = load_server(monkeypatch)

    account = server._load_account("personal")
    listed = server.list_accounts()
    serialized = str(listed)

    assert account.imap_password == "imap-secret"
    assert listed["accounts"][0]["account_id"] == "personal"
    assert listed["accounts"][0]["can_send"] is True
    assert "imap-secret" not in serialized
    assert "smtp-secret" not in serialized


def test_parse_mime_message_decodes_headers_sanitizes_html_and_lists_attachments(monkeypatch):
    server = load_server(monkeypatch)

    parsed = server._extract_message(sample_message(), include_body=True)

    assert parsed["subject"] == "Factura éxito"
    assert parsed["from"] == ["alice@example.com"]
    assert parsed["body_text"].startswith("Hola mundo")
    assert "<script>" not in parsed["body_html"]
    assert "onclick" not in parsed["body_html"]
    assert parsed["attachments"][0]["filename"] == "factura.pdf"
    assert parsed["attachments"][0]["downloadable"] is True


def test_prepare_and_send_token_rejects_modified_payload(monkeypatch):
    server = load_server(monkeypatch)
    FakeSMTP.sent = []
    monkeypatch.setattr(server.smtplib, "SMTP", FakeSMTP)

    prepared = server.prepare_email(
        account_id="personal",
        to=["client@example.com"],
        subject="Hola",
        body_text="Texto original",
    )

    with pytest.raises(ValueError, match="Invalid send_token"):
        server.send_prepared_email(
            account_id="personal",
            to=["client@example.com"],
            subject="Hola",
            body_text="Texto cambiado",
            send_token=prepared["send_token"],
        )

    result = server.send_prepared_email(
        account_id="personal",
        to=["client@example.com"],
        subject="Hola",
        body_text="Texto original",
        send_token=prepared["send_token"],
    )

    assert result["success"] is True
    assert FakeSMTP.sent[0][1] == "sender@example.com"
    assert FakeSMTP.sent[0][2] == ["client@example.com"]


def test_imap_search_and_attachment_fetch_use_readonly_and_size_limit(monkeypatch):
    server = load_server(monkeypatch)
    fake = FakeIMAP(sample_message().as_bytes())
    monkeypatch.setattr(server, "_connect_imap", Mock(return_value=fake))

    search = server.search_emails("personal", mailbox="INBOX", limit=999)
    attachment_part_id = search["messages"][0]["attachments"][0]["part_id"]
    attachment = server.get_attachment("personal", "INBOX", "102", attachment_part_id)

    assert search["limit"] == server.MAX_SEARCH_LIMIT
    assert search["messages"][0]["uid"] == "102"
    assert fake.selected[0] == ("INBOX", True)
    assert ("fetch", ("102", "(BODY.PEEK[])")) in fake.uid_calls
    assert attachment["filename"] == "factura.pdf"
    assert base64.b64decode(attachment["content_base64"]) == b"PDF"


def test_move_delete_draft_and_create_folder(monkeypatch):
    server = load_server(monkeypatch)
    fake = FakeIMAP(sample_message().as_bytes())
    monkeypatch.setattr(server, "_connect_imap", Mock(return_value=fake))

    moved = server.email_move_message(
        account_id="personal",
        source_mailbox="INBOX",
        uid="102",
        destination_mailbox="Clientes/Archivo",
    )
    assert moved["success"] is True
    assert "102" not in fake.mailboxes["INBOX"]
    assert "102" in fake.mailboxes["Clientes/Archivo"]
    assert fake.expunge_count == 1

    draft = server.email_save_draft(
        account_id="personal",
        to=["draft@example.com"],
        subject="Borrador",
        body_text="Contenido",
        mailbox="Drafts",
    )
    assert draft["success"] is True
    assert draft["mailbox"] == "Drafts"
    assert draft["draft_uid"] is not None
    draft_uid = draft["draft_uid"]

    created = server.email_create_folder(account_id="personal", mailbox="Clientes/Nuevos")
    assert created["success"] is True
    assert "Clientes/Nuevos" in fake.created_mailboxes

    prepared_delete = server.prepare_delete_messages(
        account_id="personal",
        mailbox="Drafts",
        subject="Borrador",
        limit=20,
    )
    assert prepared_delete["delete_requires_same_payload"] is True
    assert draft_uid in prepared_delete["matching_uids"]

    deleted = server.email_delete_messages(
        account_id="personal",
        mailbox="Drafts",
        subject="Borrador",
        limit=20,
        delete_token=prepared_delete["delete_token"],
    )
    assert deleted["success"] is True
    assert deleted["deleted_count"] == 1
    assert draft_uid in deleted["deleted_uids"]
    assert fake.expunge_count >= 2


def test_mark_reply_forward_archive_rules_and_extract_tools(monkeypatch):
    server = load_server(monkeypatch)
    fake = FakeIMAP(sample_message().as_bytes())
    monkeypatch.setattr(server, "_connect_imap", Mock(return_value=fake))
    FakeSMTP.sent = []
    monkeypatch.setattr(server.smtplib, "SMTP", FakeSMTP)

    marked = server.email_mark_messages(account_id="personal", mailbox="INBOX", mark_as="read", limit=10)
    assert marked["marked_uids"] == ["102"]
    assert r"(\Seen)" in fake.flags["INBOX"]["102"]

    reply_preview = server.email_reply(
        account_id="personal",
        mailbox="INBOX",
        uid="102",
        body_text="Gracias",
        reply_all=True,
    )
    assert reply_preview["reply_requires_same_payload"] is True
    reply_sent = server.email_reply(
        account_id="personal",
        mailbox="INBOX",
        uid="102",
        body_text="Gracias",
        reply_all=True,
        reply_token=reply_preview["reply_token"],
    )
    assert reply_sent["success"] is True

    forward_preview = server.email_forward(
        account_id="personal",
        mailbox="INBOX",
        uid="102",
        to="manager@example.com",
        body_text="FYI",
    )
    forward_sent = server.email_forward(
        account_id="personal",
        mailbox="INBOX",
        uid="102",
        to="manager@example.com",
        body_text="FYI",
        forward_token=forward_preview["forward_token"],
    )
    assert forward_sent["success"] is True
    assert len(FakeSMTP.sent) == 2

    attachments = server.email_get_recent_attachments(
        account_id="personal",
        mailbox="INBOX",
        extension="pdf",
    )
    assert attachments["attachments"][0]["filename"] == "factura.pdf"

    structured = server.email_extract_structured(account_id="personal", mailbox="INBOX", uid="102")
    assert "0999999999001" in structured["ecuador_ids"]
    assert any("123.45" in amount for amount in structured["amounts"])

    unsubscribe = server.email_find_unsubscribe_links(account_id="personal", mailbox="INBOX", uid="102")
    assert unsubscribe["list_unsubscribe"] == ["https://example.com/unsubscribe?id=123"]

    watched = server.email_watch_mailbox(account_id="personal", mailbox="INBOX", since_uid="101", limit=10)
    assert watched["messages"][0]["uid"] == "102"

    thread = server.email_summarize_thread_data(account_id="personal", mailbox="INBOX", uid="102")
    assert thread["messages"][0]["uid"] == "102"

    threads = server.email_search_threads(account_id="personal", mailbox="INBOX")
    assert threads["threads"][0]["messages"][0]["uid"] == "102"

    archive_preview = server.email_archive_messages(
        account_id="personal",
        source_mailbox="INBOX",
        destination_mailbox="Archive",
        limit=10,
    )
    archive_result = server.email_archive_messages(
        account_id="personal",
        source_mailbox="INBOX",
        destination_mailbox="Archive",
        limit=10,
        archive_token=archive_preview["archive_token"],
    )
    assert archive_result["success"] is True
    assert "102" in fake.mailboxes["Archive"]


def test_rules_preview_apply_and_account_test(monkeypatch):
    server = load_server(monkeypatch)
    fake = FakeIMAP(sample_message().as_bytes())
    monkeypatch.setattr(server, "_connect_imap", Mock(return_value=fake))
    monkeypatch.setattr(server.smtplib, "SMTP", FakeSMTP)

    rules = [{"source_mailbox": "INBOX", "destination_mailbox": "Archive", "subject": "Factura"}]
    preview = server.email_apply_rules_preview(account_id="personal", rules=rules)
    assert preview["rules"][0]["matching_uids"] == ["102"]

    applied = server.email_apply_rules(account_id="personal", rules=rules, rules_token=preview["rules_token"])
    assert applied["success"] is True
    assert applied["results"][0]["moved_uids"] == ["102"]

    account_test = server.email_test_account("personal")
    assert account_test["imap"]["ok"] is True
    assert account_test["smtp"]["ok"] is True


def test_missing_master_key_blocks_prepare_email(monkeypatch):
    server = load_server(monkeypatch)
    monkeypatch.delenv("MCP_MASTER_KEY", raising=False)

    with pytest.raises(ValueError, match="MCP_MASTER_KEY"):
        server.prepare_email(
            account_id="personal",
            to="client@example.com",
            subject="Hola",
            body_text="Texto",
        )
