#!/usr/bin/env python3
"""
Bevins forwarding-mailbox scam service  —  scam@bevins.example.com

Self-hosted inbound SMTP receiver. A non-technical user forwards a suspicious email
to scam@bevins.example.com; this service:
  1. receives it directly on port 25 (no third-party mail host),
  2. extracts the forwarded/suspicious content (+ any original-sender hint),
  3. runs it through the SAME multi-signal scam engine the web app uses, by POSTing
     to the app's internal /api/scan-email endpoint (localhost, shared-secret authed),
  4. replies to the forwarder with a plain-language verdict (🔴/🟡/🟢 + what to do),
     sent directly to their mail server's MX, DKIM-signed if a key is configured.

Runs as a locked-down systemd service (see deploy/bevins-mail.service). NOT an open relay:
it only accepts mail addressed to MAIL_ADDR and only ever sends replies to the forwarder.

Config (env / systemd):
  SCAN_SECRET        shared secret for the app's /api/scan-email  (required)
  MAIL_ADDR          address we accept for      (default scam@bevins.example.com)
  MAIL_DOMAIN        our sending domain         (default bevins.example.com)
  APP_URL            app base url               (default http://127.0.0.1:8110)
  LISTEN_HOST/PORT   bind                       (default 0.0.0.0:25)
  MAX_MSG_BYTES      reject larger              (default 5_000_000)
  DKIM_KEY_PATH      PEM private key for DKIM   (optional but strongly recommended)
  DKIM_SELECTOR      DKIM selector              (default bevins)
  DEBUG_SINK_DIR     if set, write .eml + verdict to this dir instead of sending (for testing)
"""
import os, sys, ssl, time, smtplib, logging, threading, re
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import parseaddr, formatdate, make_msgid, getaddresses
from concurrent.futures import ThreadPoolExecutor

import requests
from html.parser import HTMLParser
from urllib.parse import urlsplit
try:
    import dns.resolver           # dnspython — MX lookup for direct-to-recipient delivery
except Exception:
    dns = None
try:
    import dkim                   # dkimpy — outbound DKIM signing (deliverability)
except Exception:
    dkim = None

from aiosmtpd.controller import Controller

# ---------- config ----------
def _cred(name):
    """Read a systemd LoadCredential value ($CREDENTIALS_DIRECTORY/<name>), else "" ."""
    d = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if d:
        p = os.path.join(d, name)
        try:
            if os.path.exists(p): return open(p).read().strip()
        except Exception: pass
    return ""
SCAN_SECRET   = os.environ.get("SCAN_SECRET", "") or _cred("scan_secret")
MAIL_ADDR     = os.environ.get("MAIL_ADDR", "scam@bevins.example.com").lower()
MAIL_DOMAIN   = os.environ.get("MAIL_DOMAIN", "bevins.example.com").lower()
APP_URL       = os.environ.get("APP_URL", "http://127.0.0.1:8110").rstrip("/")
LISTEN_HOST   = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT   = int(os.environ.get("LISTEN_PORT", "25"))
MAX_MSG_BYTES = int(os.environ.get("MAX_MSG_BYTES", "5000000"))
DKIM_KEY_PATH = os.environ.get("DKIM_KEY_PATH", "")
DKIM_SELECTOR = os.environ.get("DKIM_SELECTOR", "bevins")
DEBUG_SINK    = os.environ.get("DEBUG_SINK_DIR", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s bevins-mail %(levelname)s %(message)s")
log = logging.getLogger("bevins-mail")

# ---------- per-sender rate limit (in-memory, best-effort) ----------
_hits = {}
_hits_lock = threading.Lock()
def rate_ok(addr, limit=8, window=3600):
    now = time.time()
    with _hits_lock:
        q = [t for t in _hits.get(addr, []) if now - t < window]
        if len(q) >= limit:
            _hits[addr] = q; return False
        q.append(now); _hits[addr] = q; return True

# ---------- email parsing ----------
# Shared bounded text extraction. All extracted material is untrusted message data.
SCAN_MAX_CHARS = 60_000
MAX_MIME_PARTS, MAX_MIME_DEPTH = 100, 12


class MailContentError(ValueError):
    pass


def safe_subject(msg):
    return re.sub(r"[\r\n\x00-\x1f]+", " ", str(msg.get("Subject") or "")).strip()[:120]


def reply_address(msg):
    # Reply-To can name an unrelated party or the original scammer. A copied
    # header is never identity authentication; use one valid top-level From.
    values = msg.get_all("From", [])
    parsed = getaddresses([str(value) for value in values])
    if len(values) != 1 or len(parsed) != 1: return ""
    addr = parsed[0][1].lower()
    return addr if re.fullmatch(r"[^@\s<>\x00-\x1f]+@[^@\s<>\x00-\x1f]+", addr) else ""


class _MailHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.blocked = [], [], []
        self.length = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ("script", "style"):
            self.blocked.append(tag); return
        if self.blocked: return
        if tag in ("p", "div", "br", "li", "tr"): self.handle_data("\n")
        destination = ("href", "xlink:href") if tag in ("a", "area") else ("action",) if tag == "form" else ("formaction",) if tag in ("input", "button") else ()
        if destination:
            for name, value in attrs:
                if name.lower() not in destination or not value: continue
                value = value.strip()
                if len(value) > 2000: raise MailContentError("oversized link")
                if any(ord(c) < 32 for c in value): raise MailContentError("invalid link")
                parsed = urlsplit(value)
                if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
                    if value not in self.links: self.links.append(value)
                elif not parsed.scheme or parsed.scheme.lower() in ("mailto", "tel", "cid"):
                    # Keep schemeless/phone/email targets as supplied; inventing an
                    # origin or scheme would hide uncertainty. Nothing is opened.
                    if value not in self.links: self.links.append(value)
                else: raise MailContentError("unsupported link destination")

    def handle_endtag(self, tag):
        if self.blocked and tag.lower() == self.blocked[-1]: self.blocked.pop()
        elif not self.blocked and tag.lower() in ("p", "div", "li", "tr"): self.handle_data("\n")

    def handle_data(self, value):
        if self.blocked: return
        self.length += len(value)
        if self.length > SCAN_MAX_CHARS: raise MailContentError("message text too long")
        self.text.append(value)


def _html_text(value):
    parser = _MailHTML()
    try: parser.feed(value); parser.close()
    except (ValueError, TypeError): raise MailContentError("unreadable HTML")
    if parser.blocked: raise MailContentError("incomplete active markup")
    visible = "".join(parser.text)
    links = "\n".join("Link destination (unverified): " + url for url in parser.links)
    rendered = visible + ("\n" + links if links else "")
    if len(rendered) > SCAN_MAX_CHARS: raise MailContentError("message text too long")
    return rendered


def _body_text(msg):
    """Walk each MIME node once; retain HTML destinations even in alternatives."""
    visited = 0
    def join(parts):
        text = "\n\n".join(part for part in parts if part)
        if len(text) > SCAN_MAX_CHARS: raise MailContentError("message text too long")
        return text
    def read(part, depth=0):
        nonlocal visited
        visited += 1
        if visited > MAX_MIME_PARTS or depth > MAX_MIME_DEPTH: raise MailContentError("message structure too complex")
        kind = part.get_content_type()
        if kind == "message/rfc822":
            children = part.get_payload()
            if not isinstance(children, list): raise MailContentError("unreadable attached message")
            return join(["Claimed forwarded sender (unverified): " + str(child.get("From") or "unknown") +
                         "\n" + read(child, depth+1) for child in children])
        if part.get_content_disposition() == "attachment": return ""
        if part.is_multipart():
            children = list(part.iter_parts())
            if kind == "multipart/alternative":
                rendered = [(child.get_content_type(), read(child, depth+1)) for child in children]
                # A malicious HTML alternative can say something different from
                # the plain version. Inspect each distinct version, not just its links.
                seen, versions = set(), []
                for typ, text in rendered:
                    key = re.sub(r"\s+", " ", text).strip()
                    if not key or key in seen: continue
                    seen.add(key); versions.append(typ + " version (untrusted):\n" + text)
                return join(versions)
            return join([read(child, depth+1) for child in children])
        if kind not in ("text/plain", "text/html"): return ""
        try: value = part.get_content()
        except Exception: raise MailContentError("unreadable message encoding")
        if not isinstance(value, str): raise MailContentError("unreadable text")
        if len(value) > SCAN_MAX_CHARS: raise MailContentError("message text too long")
        return _html_text(value) if kind == "text/html" else value
    return read(msg)


def extract(msg):
    forwarder, subject = reply_address(msg), safe_subject(msg)
    body = _body_text(msg)
    if not body.strip(): raise MailContentError("no readable message text")
    header = ("Forwarded subject (unverified): " + subject + "\n"
              "Scope: message text and link destinations only. Images and other attachments were not analyzed.\n\n")
    text = header + body
    if len(text) > SCAN_MAX_CHARS: raise MailContentError("message text too long")
    return forwarder, subject, text


class ScanUnavailable(RuntimeError):
    pass


def scan(text):
    if not isinstance(text, str) or not text.strip() or len(text) > SCAN_MAX_CHARS:
        raise ScanUnavailable("invalid scan input")
    target = urlsplit(APP_URL)
    if (target.scheme != "http" or target.hostname not in ("127.0.0.1", "::1") or
            target.username or target.password or target.path not in ("", "/") or target.query or target.fragment):
        raise ScanUnavailable("scanner must use configured loopback origin")
    # Do not let proxy environment or a redirect carry the shared secret elsewhere.
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.post(APP_URL + "/api/scan-email", timeout=(5, 120), allow_redirects=False,
                                    json={"secret": SCAN_SECRET, "text": text})
            if response.status_code != 200: raise ScanUnavailable("scanner did not complete")
            data = response.json()
    except ScanUnavailable: raise
    except Exception: raise ScanUnavailable("scanner did not complete")
    verdict = data.get("verdict") if isinstance(data, dict) else None
    if not isinstance(verdict, str) or not verdict.strip(): raise ScanUnavailable("scanner returned no assessment")
    return verdict

_ORIG_FROM_RE = re.compile(r'^\s*(?:>+\s*)?(?:From|De|Von)\s*:\s*(.+)$', re.I | re.M)



def is_autoreply(msg):
    if (msg.get("Auto-Submitted") or "").lower() not in ("", "no"): return True
    if (msg.get("Precedence") or "").lower() in ("bulk", "auto_reply", "list", "junk"): return True
    if msg.get("X-Autoreply") or msg.get("X-Autorespond"): return True
    frm = parseaddr(msg.get("From") or "")[1].lower()
    if frm.startswith(("mailer-daemon", "postmaster", "no-reply", "noreply")): return True
    if frm == MAIL_ADDR: return True   # never reply to ourselves (loop guard)
    return False

# ---------- scan (reuse the app's engine) ----------

# ---------- reply (direct-to-MX, DKIM-signed) ----------
def _mx_hosts(domain):
    if dns is None: return [domain]
    try:
        ans = dns.resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in sorted(ans, key=lambda r: r.preference)]
    except Exception:
        return [domain]

def _sign(raw, sender_domain):
    if not (dkim and DKIM_KEY_PATH and os.path.exists(DKIM_KEY_PATH)): return raw
    try:
        with open(DKIM_KEY_PATH, "rb") as f: key = f.read()
        sig = dkim.sign(raw, DKIM_SELECTOR.encode(), sender_domain.encode(), key,
                        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"])
        return sig + raw
    except Exception as e:
        log.warning("DKIM sign failed: %s", e); return raw

def build_reply(to_addr, subject, verdict, in_reply_to):
    m = EmailMessage()
    m["From"] = f"Bevins Scam Check <{MAIL_ADDR}>"
    m["To"] = to_addr
    m["Subject"] = "Scam check: " + (re.sub(r"[\r\n\x00-\x1f]+", " ", subject)[:120] if subject else "your forwarded message")
    m["Date"] = formatdate(localtime=False)
    m["Message-ID"] = make_msgid(domain=MAIL_DOMAIN)
    m["Auto-Submitted"] = "auto-replied"     # so we don't trigger other autoresponders
    if in_reply_to:
        m["In-Reply-To"] = in_reply_to; m["References"] = in_reply_to
    m.set_content(verdict + "\n\n—\nAutomatic text check. Sender identity and attachments are unverified. "
                  "Use a contact you already trust before paying or sharing information.")
    return m

def send_reply(msg_obj):
    to_addr = msg_obj["To"]
    domain = to_addr.rsplit("@", 1)[-1]
    raw = _sign(msg_obj.as_bytes(), MAIL_DOMAIN)
    last = None
    for host in _mx_hosts(domain):
        try:
            with smtplib.SMTP(host, 25, timeout=30) as s:
                s.ehlo(MAIL_DOMAIN)
                try: s.starttls(context=ssl.create_default_context()); s.ehlo(MAIL_DOMAIN)
                except Exception: pass          # opportunistic TLS
                s.sendmail(MAIL_ADDR, [to_addr], raw)
            log.info("replied to %s via %s", to_addr, host); return True
        except Exception as e:
            last = e; log.warning("MX %s failed: %s", host, e)
    log.error("all MX delivery failed for %s: %s", to_addr, last); return False

# ---------- SMTP handler ----------
_pool = ThreadPoolExecutor(max_workers=4)

class Handler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if address.lower() != MAIL_ADDR:
            return "550 no such mailbox here"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        if len(envelope.content) > MAX_MSG_BYTES:
            return "552 message too large"
        # accept fast, process in the background so we never block the SMTP transaction
        _pool.submit(self._process, bytes(envelope.content), envelope.mail_from)
        return "250 Message accepted for scanning"

    def _process(self, raw, mail_from):
        try:
            msg = message_from_bytes(raw, policy=policy.default)
            if is_autoreply(msg):
                log.info("ignored auto/loop message from %s", mail_from); return
            forwarder, subject, text = extract(msg)
            forwarder = forwarder or (parseaddr(mail_from)[1] or mail_from).lower()
            if "@" not in forwarder:
                log.info("no usable reply address; dropping"); return
            if not rate_ok(forwarder):
                log.info("rate-limited %s", forwarder); return
            verdict = scan(text)
            if not verdict.strip():
                verdict = ("I couldn't fully analyze that one automatically. To be safe, treat it as suspicious: "
                           "don't click links, don't share codes or payment, and verify with the company directly.")
            reply = build_reply(forwarder, subject, verdict, msg.get("Message-ID"))
            if DEBUG_SINK:
                os.makedirs(DEBUG_SINK, exist_ok=True)
                stamp = str(int(time.time()))
                open(os.path.join(DEBUG_SINK, stamp + ".in.eml"), "wb").write(raw)
                open(os.path.join(DEBUG_SINK, stamp + ".reply.txt"), "w").write(reply.get_content())
                log.info("DEBUG_SINK wrote verdict for %s (%d chars)", forwarder, len(verdict))
            else:
                send_reply(reply)
        except Exception as e:
            log.exception("processing failed: %s", e)

def main():
    if not SCAN_SECRET:
        log.error("SCAN_SECRET not set — refusing to start"); sys.exit(1)
    if dns is None:  log.warning("dnspython missing — MX lookup degraded (pip install dnspython)")
    if dkim is None: log.warning("dkimpy missing — outbound not DKIM-signed (pip install dkimpy)")
    c = Controller(Handler(), hostname=LISTEN_HOST, port=LISTEN_PORT, ident="bevins-mail")
    c.start()
    log.info("listening on %s:%d for %s  (app=%s, dkim=%s, sink=%s)",
             LISTEN_HOST, LISTEN_PORT, MAIL_ADDR, APP_URL, bool(DKIM_KEY_PATH), DEBUG_SINK or "off")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        c.stop()

if __name__ == "__main__":
    main()
