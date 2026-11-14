#!/usr/bin/env python3
"""Prepared Bevins IMAP transport: bounded retries, durable send/ack state.

Not active by default. --prepare-new records UIDVALIDITY/UIDNEXT metadata only;
--run processes new unread messages above that floor. External model/lookup
providers may be used by the existing loopback scanner. No message body,
recipient address, password, or verdict is stored in the local ledger.

SMTP cannot guarantee exactly-once delivery across a lost final acknowledgement.
An uncertain send is held for operator review and is never blindly resent.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import email
from email import policy
import fcntl
import hashlib
import imaplib
import json
import logging
import os
from pathlib import Path
import re
import smtplib
import sqlite3
import ssl
import stat
import time

import bevins_mail as bm

MAILBOX_USER = os.environ.get("MAILBOX_USER", "") or bm._cred("mailbox_user")
MAILBOX_PASS = os.environ.get("MAILBOX_PASS", "") or bm._cred("mailbox_pass")
IMAP_HOST, IMAP_PORT = os.environ.get("IMAP_HOST", "imap.gmail.com"), int(os.environ.get("IMAP_PORT", "993"))
SMTP_HOST, SMTP_PORT = os.environ.get("SMTP_HOST", "smtp.gmail.com"), int(os.environ.get("SMTP_PORT", "587"))
FOLDER = os.environ.get("MAILBOX", "INBOX")
POLL_SECONDS = max(30, int(os.environ.get("POLL_SECONDS", "60")))
STATE_PATH = Path(os.environ.get("MAIL_STATE_PATH", "/var/lib/bevins-mailpoll/state.sqlite3"))
MAX_ATTEMPTS, MAX_BATCH, MAX_STATE_ROWS = 3, 10, 5000
DAILY_SCANS, DAILY_REPLIES = 50, 50
log = logging.getLogger("bevins-mailpoll")


def _reply_allowlist():
    values = {value.strip().lower() for value in os.environ.get("MAIL_REPLY_ALLOWLIST", "").split(",") if value.strip()}
    if len(values) > 20 or any(len(value) > 254 or not value.isascii() or
            not re.fullmatch(r"[^@\s<>\x00-\x1f]+@[^@\s<>\x00-\x1f]+", value) for value in values):
        raise RuntimeError("invalid private reply policy")
    return values


ALLOWED_REPLY_ADDRESSES = _reply_allowlist()


class Deferred(RuntimeError):
    def __init__(self, seconds=3600): self.seconds = seconds


class DeliveryUncertain(RuntimeError):
    pass


class DeliveryRejected(RuntimeError):
    def __init__(self, permanent=False): self.permanent = permanent


class InvalidForwarder(RuntimeError):
    pass


def namespace():
    material = json.dumps([IMAP_HOST.lower(), IMAP_PORT, MAILBOX_USER.lower(), FOLDER])
    return hashlib.sha256(material.encode()).hexdigest()


class PollState:
    def __init__(self, path=STATE_PATH):
        self.path = Path(path).absolute()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = self.path.parent
        info = directory.stat()
        if directory.resolve() != directory or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError("state directory must be private and owned by this service")
        if self.path.is_symlink(): raise RuntimeError("state file must not be a symlink")
        if self.path.exists():
            info = self.path.stat()
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise RuntimeError("state file must be private and owned by this service")
        self.conn = sqlite3.connect(str(self.path), timeout=2, isolation_level=None)
        os.chmod(self.path, 0o600)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=DELETE")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript("""
          CREATE TABLE IF NOT EXISTS scopes(namespace TEXT PRIMARY KEY, validity INTEGER, floor INTEGER);
          CREATE TABLE IF NOT EXISTS jobs(key TEXT PRIMARY KEY, status TEXT, attempts INTEGER,
            next_due REAL, updated REAL, reason TEXT);
          CREATE TABLE IF NOT EXISTS usage(day TEXT PRIMARY KEY, scans INTEGER DEFAULT 0, replies INTEGER DEFAULT 0);
        """)

    def close(self): self.conn.close()

    @contextmanager
    def lock(self):
        fd = os.open(str(self.path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077: raise RuntimeError("unsafe lock file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally: os.close(fd)

    def prepare(self, scope, validity, floor):
        row = self.conn.execute("SELECT * FROM scopes WHERE namespace=?", (scope,)).fetchone()
        if row:
            if (row["validity"], row["floor"]) != (validity, floor):
                raise RuntimeError("existing scope needs explicit operator reconciliation")
            return
        self.conn.execute("INSERT INTO scopes VALUES(?,?,?)", (scope, validity, floor))

    def floor(self, scope, validity):
        row = self.conn.execute("SELECT * FROM scopes WHERE namespace=?", (scope,)).fetchone()
        if not row: raise RuntimeError("prepare new-message scope before activation")
        if row["validity"] != validity: raise RuntimeError("UID validity changed; operator reconciliation required")
        return row["floor"]

    def key(self, scope, validity, uid):
        return hashlib.sha256(f"{scope}:{validity}:{uid}".encode()).hexdigest()

    def row(self, key):
        row = self.conn.execute("SELECT * FROM jobs WHERE key=?", (key,)).fetchone()
        return dict(row) if row else None

    def claim(self, key, now):
        row = self.row(key)
        if row and row["status"] in ("sent", "ignored", "review"): return row["status"]
        if row and row["status"] == "sending":
            self.review(key, "send_outcome_unknown", now); return "review"
        if row and row["status"] == "inflight":
            self.retry(key, "interrupted_before_send", now); return None
        if row and row["next_due"] > now: return None
        attempts = row["attempts"] if row else 0
        if attempts >= MAX_ATTEMPTS:
            self.review(key, "retry_limit", now); return "review"
        if not row:
            # Do not age out a delivery record that might still need IMAP ack.
            # A full ledger stops new work for explicit operator reconciliation.
            if self.conn.execute("SELECT count(*) FROM jobs").fetchone()[0] >= MAX_STATE_ROWS:
                raise RuntimeError("state capacity reached; operator review required")
        self.conn.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET status=excluded.status,attempts=excluded.attempts,next_due=excluded.next_due,updated=excluded.updated,reason=excluded.reason",
                          (key, "inflight", attempts+1, 0, now, ""))
        return "claimed"

    def review(self, key, reason, now):
        self.conn.execute("UPDATE jobs SET status='review',reason=?,updated=? WHERE key=?", (reason, now, key))

    def retry(self, key, reason, now):
        row = self.row(key)
        if row["attempts"] >= MAX_ATTEMPTS: self.review(key, "retry_limit", now); return
        delay = 60 if row["attempts"] == 1 else 300
        self.conn.execute("UPDATE jobs SET status='pending',next_due=?,updated=?,reason=? WHERE key=?", (now+delay, now, reason, key))

    def defer(self, key, seconds, now):
        self.conn.execute("UPDATE jobs SET status='pending',attempts=max(0,attempts-1),next_due=?,updated=?,reason='deferred' WHERE key=?", (now+seconds, now, key))

    def done(self, key, status, now):
        if status not in ("sent", "ignored"): raise ValueError("invalid completed state")
        self.conn.execute("UPDATE jobs SET status=?,updated=?,reason='' WHERE key=?", (status, now, key))
        if self.conn.execute("SELECT changes()").fetchone()[0] != 1: raise RuntimeError("missing delivery state")

    def budget(self, column, limit, now, key=None):
        if column not in ("scans", "replies"): raise ValueError("invalid budget")
        day = datetime.fromtimestamp(now, timezone.utc).date().isoformat()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute("INSERT INTO usage(day) VALUES(?) ON CONFLICT DO NOTHING", (day,))
            used = self.conn.execute(f"SELECT {column} FROM usage WHERE day=?", (day,)).fetchone()[0]
            if used >= limit: raise Deferred(max(60, (int(now//86400)+1)*86400-now))
            self.conn.execute(f"UPDATE usage SET {column}={column}+1 WHERE day=?", (day,))
            if key is not None:
                self.conn.execute("UPDATE jobs SET status='sending',updated=? WHERE key=? AND status='inflight'", (now, key))
                if self.conn.execute("SELECT changes()").fetchone()[0] != 1: raise RuntimeError("invalid send state")
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK"); raise

    def counts(self):
        return {row[0]:row[1] for row in self.conn.execute("SELECT status,count(*) FROM jobs GROUP BY status")}


def send_via_smtp(message, before_send, accepted):
    if not callable(before_send) or not callable(accepted): raise RuntimeError("durable delivery callbacks required")
    connection = None
    try:
        # Any failure here is before DATA, so no message was accepted.
        connection = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        connection.ehlo(); connection.starttls(context=ssl.create_default_context()); connection.ehlo()
        connection.login(MAILBOX_USER, MAILBOX_PASS)
        before_send()  # FULL-synchronous durable sending state precedes DATA.
        try:
            refused = connection.sendmail(MAILBOX_USER, [str(message["To"])], message.as_bytes())
            if refused: raise DeliveryRejected(permanent=True)
        except smtplib.SMTPRecipientsRefused as error:
            permanent = all(int(value[0]) >= 500 for value in error.recipients.values())
            raise DeliveryRejected(permanent=permanent) from None
        except smtplib.SMTPResponseException as error:
            raise DeliveryRejected(permanent=error.smtp_code >= 500) from None
        except DeliveryRejected: raise
        except Exception: raise DeliveryUncertain("SMTP outcome unknown") from None
        try: accepted()  # Do not resend if subsequent IMAP acknowledgement or QUIT fails.
        except Exception: raise DeliveryUncertain("accepted message could not be durably recorded") from None
    finally:
        if connection is not None:
            try: connection.quit()
            except Exception:
                try: connection.close()
                except Exception: pass


INCOMPLETE = ("Check incomplete. I could not read all of this forwarded message. No scam verdict was produced. "
              "Verify through contact details you already trust before sending money or sharing information. "
              "If someone may be in immediate danger, contact local emergency services yourself.")


def process_message(raw, before_scan, before_send, accepted):
    if not all(callable(callback) for callback in (before_scan, before_send, accepted)):
        raise RuntimeError("durable processing callbacks required")
    message = email.message_from_bytes(raw, policy=policy.default)
    if bm.is_autoreply(message): return "ignored"
    forwarder, subject = bm.reply_address(message), bm.safe_subject(message)
    if not forwarder: raise InvalidForwarder("one valid forwarder address required")
    # Address matching limits destinations; it does not authenticate the sender.
    if forwarder not in ALLOWED_REPLY_ADDRESSES: raise InvalidForwarder("reply destination is not enabled")
    if not bm.rate_ok(forwarder): raise Deferred(3600)
    try:
        _, _, text = bm.extract(message)
    except bm.MailContentError:
        verdict = INCOMPLETE
    else:
        before_scan()
        verdict = bm.scan(text)
        if not verdict.strip(): raise bm.ScanUnavailable("scanner returned no assessment")
    reply = bm.build_reply(forwarder, subject, verdict, message.get("Message-ID"))
    send_via_smtp(reply, before_send, accepted)
    return "sent"


def _number(response, name):
    values = response[1] if response and len(response) > 1 else []
    if not values or not isinstance(values[0], bytes) or not values[0].isdigit():
        raise RuntimeError("mailbox metadata unavailable: " + name)
    number = int(values[0])
    if not 0 < number < 2**32: raise RuntimeError("invalid mailbox metadata")
    return number


def _credentials():
    if not MAILBOX_USER or not MAILBOX_PASS or not bm.SCAN_SECRET or not ALLOWED_REPLY_ADDRESSES:
        raise RuntimeError("mailbox/scanner credentials and private reply policy must be configured before activation")


def prepare_new(state):
    _credentials()
    with state.lock():
        connection = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ssl.create_default_context(), timeout=30)
        try:
            connection.login(MAILBOX_USER, MAILBOX_PASS)
            status, _ = connection.select(FOLDER, readonly=True)
            if status != "OK": raise RuntimeError("mailbox metadata unavailable")
            validity = _number(connection.response("UIDVALIDITY"), "validity")
            floor = _number(connection.response("UIDNEXT"), "next UID")
            state.prepare(namespace(), validity, floor)
            return {"prepared_new_messages_only": True, "uidvalidity": validity, "first_eligible_uid": floor,
                    "message_bodies_read": 0, "messages_sent": 0, "flags_changed": 0}
        finally:
            try: connection.logout()
            except Exception: pass


def poll_once(state):
    _credentials()
    with state.lock():
        connection = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ssl.create_default_context(), timeout=30)
        handled = 0
        try:
            connection.login(MAILBOX_USER, MAILBOX_PASS)
            status, _ = connection.select(FOLDER)
            if status != "OK": raise RuntimeError("mailbox unavailable")
            validity = _number(connection.response("UIDVALIDITY"), "validity")
            scope = namespace(); floor = state.floor(scope, validity)
            status, result = connection.uid("SEARCH", None, "UNSEEN", "UID", f"{floor}:*")
            if status != "OK": raise RuntimeError("mailbox search unavailable")
            ids = result[0].split() if result and result[0] else []
            # A UID range with '*' can include the last older UID. Enforce the floor locally too.
            ids = [value for value in ids if value.isdigit() and floor <= int(value) < 2**32]
            started, acknowledgements = 0, 0
            for uid in sorted(ids, key=int):
                if started >= MAX_BATCH: break
                now = time.time(); key = state.key(scope, validity, int(uid))
                claimed = state.claim(key, now)
                if claimed in ("sent", "ignored"):
                    if acknowledgements < MAX_BATCH:
                        connection.uid("STORE", uid, "+FLAGS.SILENT", r"(\Seen)")
                        acknowledgements += 1
                    continue
                if claimed != "claimed": continue
                started += 1
                try:
                    status, metadata = connection.uid("FETCH", uid, "(RFC822.SIZE)")
                    if status != "OK": raise RuntimeError("message size unavailable")
                    size_data = b" ".join(item for item in metadata if isinstance(item, bytes))
                    found = re.search(rb"RFC822\.SIZE\s+(\d+)", size_data)
                    if not found: raise RuntimeError("message size unavailable")
                    if not 0 < int(found.group(1)) <= bm.MAX_MSG_BYTES:
                        state.review(key, "message_size_limit", now); continue
                    status, parts = connection.uid("FETCH", uid, "(BODY.PEEK[])")
                    if status != "OK": raise RuntimeError("message unavailable")
                    raw = next((part[1] for part in parts if isinstance(part, tuple) and len(part) > 1 and isinstance(part[1], bytes)), None)
                    if not raw or len(raw) > bm.MAX_MSG_BYTES: raise RuntimeError("message unavailable")
                    result = process_message(raw,
                        lambda: state.budget("scans", DAILY_SCANS, time.time()),
                        lambda: state.budget("replies", DAILY_REPLIES, time.time(), key),
                        lambda: state.done(key, "sent", time.time()))
                    if result == "ignored": state.done(key, "ignored", time.time())
                    status, _ = connection.uid("STORE", uid, "+FLAGS.SILENT", r"(\Seen)")
                    if status != "OK": log.warning("IMAP acknowledgement pending; completed send is recorded")
                    handled += 1
                except Deferred as error:
                    state.defer(key, error.seconds, time.time())
                except DeliveryUncertain:
                    if state.row(key)["status"] != "sent":
                        state.review(key, "send_outcome_unknown", time.time())
                        log.warning("Delivery outcome uncertain; manual review required")
                    else: log.warning("Accepted send recorded; acknowledgement remains pending")
                except DeliveryRejected as error:
                    if error.permanent: state.review(key, "smtp_rejected", time.time())
                    else: state.retry(key, "smtp_temporary_rejection", time.time())
                except InvalidForwarder:
                    state.review(key, "invalid_forwarder", time.time())
                except Exception:
                    # A durable accepted send must survive a later IMAP failure.
                    row = state.row(key)
                    if row["status"] not in ("sent", "ignored", "sending", "review"):
                        state.retry(key, "processing_unavailable", time.time())
                    elif row["status"] == "sending":
                        state.review(key, "send_outcome_unknown", time.time())
                    log.warning("Message remains pending or held; no automatic acknowledgement")
                if started >= MAX_BATCH: break
            return handled
        finally:
            try: connection.logout()
            except Exception: pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare-new", action="store_true")
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--status", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s bevins-mailpoll %(levelname)s %(message)s")
    if args.status and not STATE_PATH.exists():
        print(json.dumps({"initialized": False})); return
    state = PollState()
    try:
        if args.status: print(json.dumps({"counts": state.counts()})); return
        if args.prepare_new: print(json.dumps(prepare_new(state))); return
        _credentials()
        while True:
            try: poll_once(state)
            except Exception as error: log.warning("Poll incomplete: %s", type(error).__name__)
            time.sleep(POLL_SECONDS)
    finally: state.close()


if __name__ == "__main__": main()
