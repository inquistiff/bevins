"""Full candidate-module tests, real private SQLite, synthetic mail/IMAP/SMTP.

External HTTP, socket connects and DNS are blocked. No real credentials, inbox,
provider calls or email delivery. Tests exercise protocol boundaries and crash
recovery behavior; they do not establish live deliverability.
"""
import email
from email import policy
from email.message import EmailMessage
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import smtplib
import socket
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
CANDIDATE = ROOT
os.environ.update(CREDENTIALS_DIRECTORY="", SCAN_SECRET="fixture-scanner-secret",
                  MAILBOX_USER="checker@example.invalid", MAILBOX_PASS="fixture-mail-password",
                  MAIL_ADDR="checker@example.invalid", MAIL_DOMAIN="example.invalid",
                  APP_URL="http://127.0.0.1:8110",MAIL_REPLY_ALLOWLIST="helper@example.invalid")


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec);sys.modules[name] = obj;spec.loader.exec_module(obj)
    return obj


bm = module("bevins_mail", CANDIDATE / "bevins_mail.py")
poll = module("bevins_mailpoll", CANDIDATE / "bevins_mailpoll.py")


def message(body="Grandma, buy gift cards and send the codes."):
    m = EmailMessage();m["From"]="helper@example.invalid";m["To"]="checker@example.invalid"
    m["Subject"]="Fwd: please check";m["Message-ID"]="<synthetic@example.invalid>";m.set_content(body)
    return m


class FakeIMAP:
    def __init__(self, messages=None, ack="OK", validity=77, next_uid=20):
        self.messages = messages or {20:message().as_bytes()}
        self.ack, self.validity, self.next_uid = ack, validity, next_uid
        self.calls=[];self.fail_fetch=False
    def login(self,*args):self.calls.append(("login",));return "OK",[]
    def select(self,folder,readonly=False):self.calls.append(("select",folder,readonly));return "OK",[]
    def response(self,name):return name,[str(self.validity if name=="UIDVALIDITY" else self.next_uid).encode()]
    def uid(self,command,*args):
        self.calls.append((command,*args))
        if command=="SEARCH":return "OK",[b" ".join(str(uid).encode() for uid in self.messages)]
        uid=int(args[0]);raw=self.messages[uid]
        if command=="STORE":return self.ack,[]
        if self.fail_fetch:raise RuntimeError("synthetic IMAP outage")
        if args[1]=="(RFC822.SIZE)":return "OK",[f"1 (RFC822.SIZE {len(raw)})".encode()]
        return "OK",[(b"1 (BODY[])",raw)]
    def logout(self):self.calls.append(("logout",));return "BYE",[]


class FakeSMTP:
    def __init__(self, mode="ok", quit_fails=False):self.mode=mode;self.quit_fails=quit_fails;self.calls=[];self.sent=[]
    def ehlo(self):self.calls.append("ehlo")
    def starttls(self,**kwargs):self.calls.append("tls")
    def login(self,*args):
        self.calls.append("login")
        if self.mode=="login_fail":raise smtplib.SMTPAuthenticationError(535,b"fixture-secret-must-not-log")
    def sendmail(self,sender,recipients,raw):
        self.calls.append("DATA")
        if self.mode=="uncertain":raise socket.timeout("fixture-secret-must-not-log")
        if self.mode=="temporary":raise smtplib.SMTPDataError(451,b"fixture-secret-must-not-log")
        if self.mode=="permanent":raise smtplib.SMTPDataError(550,b"fixture-secret-must-not-log")
        self.sent.append((sender,recipients,raw));return {}
    def quit(self):
        self.calls.append("quit")
        if self.quit_fails:raise smtplib.SMTPServerDisconnected("after acceptance")
    def close(self):self.calls.append("close")


class MailTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="bevins-mail-tests-",dir="/private/tmp" if Path("/private/tmp").exists() else None)
        self.addCleanup(self.tmp.cleanup)
        self.state=poll.PollState(Path(self.tmp.name)/"state.sqlite3")
        self.addCleanup(lambda:self.state.close())
        self.scope=poll.namespace();self.state.prepare(self.scope,77,20)
        self.imap=FakeIMAP();self.smtp=FakeSMTP();self.scans=[]
        bm._hits.clear()
        def scan(text):self.scans.append(text);return "🔴 Likely a scam\n\nVerify with a trusted contact."
        self.patches=[patch("requests.sessions.Session.request",side_effect=AssertionError("external HTTP blocked")),
                      patch("socket.socket.connect",side_effect=AssertionError("external connect blocked")),
                      patch("socket.getaddrinfo",side_effect=AssertionError("external DNS blocked")),
                      patch.object(poll.imaplib,"IMAP4_SSL",side_effect=lambda *a,**k:self.imap),
                      patch.object(poll.smtplib,"SMTP",side_effect=lambda *a,**k:self.smtp),
                      patch.object(bm,"scan",side_effect=scan)]
        for item in self.patches:item.start()
        self.addCleanup(lambda:[item.stop() for item in reversed(self.patches)])

    def key(self,uid=20,validity=77):return self.state.key(self.scope,validity,uid)
    def stores(self):return [c for c in self.imap.calls if c[0]=="STORE"]
    def run_poll(self):return poll.poll_once(self.state)

    def test_plain_forward_retains_message(self):
        m=message("From: family@example.invalid\nBuy gift cards.")
        who,subject,text=bm.extract(m)
        self.assertEqual(who,"helper@example.invalid");self.assertIn("Buy gift cards",text)

    def test_html_actual_link_and_entities_retained_without_opening(self):
        m=message();m.set_content('<a href="https://evil.example.invalid/?a=1&amp;b=2">Official bank</a>',subtype="html")
        text=bm.extract(m)[2]
        self.assertIn("https://evil.example.invalid/?a=1&b=2",text)
        self.assertIn("Official bank",text)

    def test_alternative_plain_does_not_hide_html_destination(self):
        m=message("Your bank notice.");m.add_alternative('<a href="https://evil.example.invalid/">Bank</a>',subtype="html")
        self.assertIn("https://evil.example.invalid/",bm.extract(m)[2])

    def test_protocol_relative_phone_email_and_relative_destinations_are_retained(self):
        links=("//evil.example.invalid/verify","tel:+12025550101","mailto:claimed@example.invalid","/unknown-origin")
        m=message();m.set_content("".join('<a href="'+link+'">Check</a>' for link in links),subtype="html")
        text=bm.extract(m)[2]
        for link in links:self.assertIn(link,text)

    def test_unsupported_active_destination_is_incomplete(self):
        m=message();m.set_content('<a href="javascript:steal()">Continue</a>',subtype="html")
        with self.assertRaises(bm.MailContentError):bm.extract(m)

    def test_alternative_plain_does_not_hide_different_html_payment_request(self):
        m=message("Routine bank notice.");m.add_alternative("<p>Buy gift cards and send me their codes.</p>",subtype="html")
        text=bm.extract(m)[2]
        self.assertIn("Routine bank notice",text);self.assertIn("Buy gift cards",text)

    def test_forwarded_attachment_body_is_not_duplicated(self):
        m=message("Please check the attached email.");child=message("unique-inner-text");m.add_attachment(child)
        self.assertEqual(bm.extract(m)[2].count("unique-inner-text"),1)

    def test_images_are_not_claimed_as_analyzed(self):
        m=message("Check this attached image.");m.add_attachment(b"fake",maintype="image",subtype="png",filename="image.png")
        self.assertIn("Images and other attachments were not analyzed",bm.extract(m)[2])

    def test_script_and_style_are_not_rendered_as_visible_text(self):
        m=message();m.set_content('<style>secret-css</style><script>secret-code</script><p>Visible</p>',subtype="html")
        text=bm.extract(m)[2]
        self.assertIn("Visible",text);self.assertNotIn("secret-css",text);self.assertNotIn("secret-code",text)

    def test_oversized_and_empty_text_do_not_get_silently_truncated(self):
        for body in ("x"*60001,""):
            with self.subTest(length=len(body)),self.assertRaises(bm.MailContentError):bm.extract(message(body))

    def test_unknown_charset_is_incomplete(self):
        raw=b'From: helper@example.invalid\r\nContent-Type: text/plain; charset=does-not-exist\r\n\r\nhello'
        with self.assertRaises(bm.MailContentError):bm.extract(email.message_from_bytes(raw,policy=policy.default))

    def test_deep_mime_structure_is_incomplete(self):
        root=message("leaf")
        for _ in range(15):
            outer=EmailMessage();outer.make_mixed();outer.attach(root);root=outer
        with self.assertRaises(bm.MailContentError):bm._body_text(root)

    def test_reply_to_cannot_redirect_recipient(self):
        m=message();m["Reply-To"]="unrelated@example.invalid"
        self.assertEqual(bm.reply_address(m),"helper@example.invalid")

    def test_multiple_from_addresses_are_not_used_for_a_reply(self):
        m=message();m.replace_header("From","a@example.invalid, b@example.invalid")
        self.assertEqual(bm.reply_address(m),"")

    def test_body_peek_uid_fetch_and_success_only_ack(self):
        self.run_poll()
        self.assertTrue(any(c[0]=="FETCH" and c[2]=="(BODY.PEEK[])" for c in self.imap.calls))
        self.assertEqual(len(self.stores()),1);self.assertEqual(self.state.row(self.key())["status"],"sent")

    def test_scanner_failure_remains_unread_and_bounded(self):
        with patch.object(bm,"scan",side_effect=bm.ScanUnavailable("offline")),patch.object(poll.time,"time",return_value=1000):self.run_poll()
        self.assertEqual(self.stores(),[]);self.assertEqual(self.state.row(self.key())["status"],"pending")
        for now in (1100,1500):
            bm._hits.clear()
            with patch.object(bm,"scan",side_effect=bm.ScanUnavailable("offline")),patch.object(poll.time,"time",return_value=now):self.run_poll()
        self.assertEqual(self.state.row(self.key())["status"],"review")
        self.assertEqual(self.state.row(self.key())["attempts"],3);self.assertEqual(self.stores(),[])

    def test_transient_smtp_login_failure_is_before_send_and_pending(self):
        self.smtp.mode="login_fail";self.run_poll()
        self.assertEqual(self.stores(),[]);self.assertEqual(self.state.row(self.key())["status"],"pending")
        self.assertNotIn("DATA",self.smtp.calls)

    def test_smtp_unknown_outcome_is_held_without_automatic_resend(self):
        self.smtp.mode="uncertain";self.run_poll();self.run_poll()
        self.assertEqual(self.state.row(self.key())["status"],"review")
        self.assertEqual(self.smtp.calls.count("DATA"),1);self.assertEqual(self.stores(),[])

    def test_explicit_temporary_smtp_rejection_is_retryable(self):
        self.smtp.mode="temporary";self.run_poll()
        self.assertEqual(self.state.row(self.key())["status"],"pending");self.assertEqual(self.stores(),[])

    def test_explicit_permanent_smtp_rejection_is_held(self):
        self.smtp.mode="permanent";self.run_poll()
        self.assertEqual(self.state.row(self.key())["status"],"review");self.assertEqual(self.stores(),[])

    def test_quit_failure_after_acceptance_does_not_lose_success(self):
        self.smtp.quit_fails=True;self.run_poll()
        self.assertEqual(self.state.row(self.key())["status"],"sent");self.assertEqual(len(self.stores()),1)

    def test_accepted_send_not_repeated_after_imap_ack_failure_and_restart(self):
        self.imap.ack="NO";self.run_poll()
        self.state.close();self.state=poll.PollState(Path(self.tmp.name)/"state.sqlite3")
        self.imap.ack="OK";self.run_poll()
        self.assertEqual(len(self.smtp.sent),1);self.assertEqual(len(self.scans),1)

    def test_crash_after_send_started_is_held_on_restart(self):
        now=time.time();self.state.claim(self.key(),now);self.state.budget("replies",50,now,self.key())
        self.run_poll()
        self.assertEqual(self.state.row(self.key())["status"],"review");self.assertEqual(self.smtp.sent,[])

    def test_crash_before_send_obeys_retry_limit(self):
        self.state.claim(self.key(),1000)
        with patch.object(poll.time,"time",return_value=1010):self.run_poll()
        self.assertEqual(self.state.row(self.key())["status"],"pending");self.assertEqual(self.smtp.sent,[])

    def test_preparation_is_read_only_and_does_not_fetch_or_send(self):
        state=poll.PollState(Path(self.tmp.name)/"other.sqlite3")
        try:
            result=poll.prepare_new(state)
            self.assertEqual(result["message_bodies_read"],0)
            self.assertTrue(any(c[0]=="select" and c[2] for c in self.imap.calls))
            self.assertFalse(any(c[0] in ("FETCH","STORE") for c in self.imap.calls))
            self.assertEqual(self.smtp.sent,[])
        finally:state.close()

    def test_uid_floor_filters_backlog_even_if_search_returns_last_older_uid(self):
        self.imap.messages={19:message("old").as_bytes(),20:message("new").as_bytes()};self.run_poll()
        self.assertEqual(len(self.scans),1);self.assertIn("new",self.scans[0]);self.assertNotIn("old",self.scans[0])
        self.assertFalse(any(len(c)>1 and c[1]==b"19" and c[0] in ("FETCH","STORE") for c in self.imap.calls))

    def test_uidvalidity_change_refuses_before_any_body_or_flag_access(self):
        self.imap.validity=78
        with self.assertRaises(RuntimeError):self.run_poll()
        self.assertFalse(any(c[0] in ("FETCH","STORE") for c in self.imap.calls))

    def test_missing_credentials_refuse_before_imap(self):
        with patch.object(poll,"MAILBOX_PASS",""):
            with self.assertRaises(RuntimeError):self.run_poll()
        self.assertEqual(self.imap.calls,[])

    def test_missing_private_reply_policy_refuses_before_imap(self):
        with patch.object(poll,"ALLOWED_REPLY_ADDRESSES",set()):
            with self.assertRaises(RuntimeError):self.run_poll()
        self.assertEqual(self.imap.calls,[])

    def test_unlisted_recipient_does_not_scan_send_or_ack(self):
        m=message();m.replace_header("From","outsider@example.invalid");self.imap.messages={20:m.as_bytes()}
        self.run_poll()
        self.assertEqual(self.scans,[]);self.assertEqual(self.smtp.sent,[]);self.assertEqual(self.stores(),[])
        self.assertEqual(self.state.row(self.key())["status"],"review")

    def test_imap_tls_context_verifies_hostname_and_certificate(self):
        import ssl
        for preparing in (False,True):
            with patch.object(poll.imaplib,"IMAP4_SSL",return_value=self.imap) as constructor:
                if preparing:
                    state=poll.PollState(Path(self.tmp.name)/"tls-prepare.sqlite3")
                    try:poll.prepare_new(state)
                    finally:state.close()
                else:self.run_poll()
                context=constructor.call_args.kwargs["ssl_context"]
                self.assertTrue(context.check_hostname);self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
                self.assertEqual(constructor.call_args.kwargs["timeout"],30)

    def test_no_scope_refuses_before_body_access(self):
        self.state.conn.execute("DELETE FROM scopes")
        with self.assertRaises(RuntimeError):self.run_poll()
        self.assertFalse(any(c[0] in ("FETCH","STORE") for c in self.imap.calls))

    def test_rate_limit_defers_without_ack_or_scanning(self):
        with patch.object(bm,"rate_ok",return_value=False):self.run_poll()
        self.assertEqual(self.state.row(self.key())["status"],"pending")
        self.assertEqual(self.state.row(self.key())["attempts"],0);self.assertEqual(self.stores(),[]);self.assertEqual(self.scans,[])

    def test_daily_scan_and_reply_limits_survive_reopen(self):
        now=time.time()
        for _ in range(2):self.state.budget("scans",2,now)
        with self.assertRaises(poll.Deferred):self.state.budget("scans",2,now)
        self.state.close();self.state=poll.PollState(Path(self.tmp.name)/"state.sqlite3")
        with self.assertRaises(poll.Deferred):self.state.budget("scans",2,now)
        self.state.claim(self.key(),now);self.state.budget("replies",1,now,self.key())
        other=self.key(21);self.state.claim(other,now)
        with self.assertRaises(poll.Deferred):self.state.budget("replies",1,now,other)
        self.assertEqual(self.state.row(other)["status"],"inflight")

    def test_held_jobs_do_not_starve_new_messages(self):
        self.imap.messages={uid:message(str(uid)).as_bytes() for uid in range(20,32)}
        for uid in range(20,31):self.state.claim(self.key(uid),time.time());self.state.review(self.key(uid),"fixture",time.time())
        self.run_poll();self.assertEqual(len(self.scans),1);self.assertIn("31",self.scans[0])

    def test_oversized_mime_uses_incomplete_notice_without_model_call(self):
        self.imap.messages={20:message("x"*60001).as_bytes()};self.run_poll()
        self.assertEqual(self.scans,[]);self.assertEqual(len(self.smtp.sent),1)
        sent=email.message_from_bytes(self.smtp.sent[0][2],policy=policy.default)
        self.assertIn("Check incomplete",sent.get_content());self.assertNotIn("Likely a scam",sent.get_content())

    def test_raw_message_size_limit_leaves_message_unread_for_review(self):
        self.imap.messages={20:b"x"*(bm.MAX_MSG_BYTES+1)};self.run_poll()
        self.assertEqual(self.state.row(self.key())["status"],"review");self.assertEqual(self.stores(),[])
        self.assertFalse(any(c[0]=="FETCH" and c[2]=="(BODY.PEEK[])" for c in self.imap.calls))

    def test_auto_reply_is_ignored_without_scan_or_send(self):
        m=message();m["Auto-Submitted"]="auto-generated";self.imap.messages={20:m.as_bytes()};self.run_poll()
        self.assertEqual(self.scans,[]);self.assertEqual(self.smtp.sent,[]);self.assertEqual(len(self.stores()),1)

    def test_state_has_no_message_address_verdict_or_password(self):
        self.run_poll();raw=Path(self.state.path).read_bytes()
        for value in (b"helper@example.invalid",b"buy gift cards",b"fixture-mail-password",b"Likely a scam"):
            self.assertNotIn(value,raw)
        self.assertEqual(stat.S_IMODE(self.state.path.stat().st_mode),0o600)

    def test_no_smtp_without_durable_callbacks(self):
        with self.assertRaises(RuntimeError):poll.send_via_smtp(message(),None,None)
        self.assertEqual(self.smtp.calls,[])

    def test_scanner_loopback_secret_boundary_and_no_redirects(self):
        captured=[]
        class Session:
            trust_env=True
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def post(self,url,**kwargs):
                captured.append((self.trust_env,url,kwargs))
                class Response:
                    status_code=200
                    def json(self):return {"verdict":"🟡 Needs verification"}
                return Response()
        # Call the original function under the mock's wrapped source, rather than the scanner stand-in.
        original_source=module("bevins_mail_scanner_probe",CANDIDATE/"bevins_mail.py")
        with patch.object(original_source.requests,"Session",Session):self.assertTrue(original_source.scan("fixture text"))
        self.assertFalse(captured[0][0]);self.assertFalse(captured[0][2]["allow_redirects"])
        with patch.object(original_source,"APP_URL","https://outside.example.invalid"):
            with self.assertRaises(original_source.ScanUnavailable):original_source.scan("fixture text")


if __name__=="__main__":
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(MailTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={"checks":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
            "full_modules_imported":True,"real_sqlite":True,"network_blocked":True,
            "real_credentials_used":False,"production_inbox_read":False,"message_sent":False,
            "live_delivery_verified":False,"deployed":False,
            "source_sha256":{name:hashlib.sha256((CANDIDATE/name).read_bytes()).hexdigest() for name in ("bevins_mail.py","bevins_mailpoll.py")}}
    (ROOT/"test-results.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report));raise SystemExit(not result.wasSuccessful())
