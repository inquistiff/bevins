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
