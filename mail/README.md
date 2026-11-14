# Bevins forwarding-mailbox service

Lets a user forward a suspicious email to a dedicated address (e.g. `scam@bevins.example.com`)
and get a plain-language verdict back from the Bevins scam engine (`POST /api/scan-email` on the app,
authenticated with `SCAN_SECRET`).

There are two transports:

- **`bevins_mailpoll.py` (recommended).** Hardened IMAP poller for a dedicated mailbox. It uses a verifying
  TLS context with finite timeouts, a UIDVALIDITY plus new-message UID floor (`--prepare-new`), `BODY.PEEK`,
  and success-only `\Seen` acknowledgement. It keeps a private SQLite ledger with an exclusive lock and stops after 3 retries.
  It caps work at 50 scans and 50 replies per UTC day. Uncertain SMTP deliveries are held for manual review and never resent automatically.
  Replies go only to addresses on `MAIL_REPLY_ALLOWLIST`, and an empty list refuses to run. The ledger never stores
  message text, sender addresses, verdicts or passwords.
  `--status` prints ledger counts without touching mail.
- **`bevins_mail.py`.** Direct SMTP receiver (aiosmtpd) with DKIM-signed replies, a `DEBUG_SINK_DIR` dry-run mode,
  and loop, auto-reply and rate-limit guards. It also holds shared parsing helpers used by the poller.

## Status
Both transports pass the local test suite. Neither has been verified against live mail delivery. Treat this
as a reference implementation and test with your own synthetic messages before enabling.

## Run the tests
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-test.txt
python3 test_mail.py
```
The tests replace all IMAP, SMTP and scanner transports with fakes and use only `example.invalid` addresses.

## Deploy
See `../docs/MAIL-DEPLOY.md` and the example units in `../deploy/systemd/`
(`90-prepared-poller.conf` is a drop-in for the poller unit; `99-prepare-only.conf` is a one-shot overlay
that records the starting UID floor without fetching or sending anything). Configuration: `.env.example`,
`mail-policy.env.example`.

Note: message text you submit to the scanner may be processed by the external model and lookup
providers configured on the app.
