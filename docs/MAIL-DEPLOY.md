# Self-hosted scam mailbox — deploy runbook

Example address: **scam@bevins.example.com**. A person forwards a suspicious email there and gets a
plain-language verdict back. `bevins.example.com` and `203.0.113.10` are documentation placeholders
(`203.0.113.10` is from the TEST-NET-3 documentation range). Replace them with your own domain and host address.

The local mail tests pass. Live delivery has not been verified. Treat this as a reference runbook and
test with synthetic messages before you enable replies.

Two ways to receive mail:

- `mail/bevins_mail.py` — direct SMTP on your host (aiosmtpd), then `POST /api/scan-email`, then a DKIM-signed reply.
- `mail/bevins_mailpoll.py` — recommended when you cannot receive port 25 yourself. It polls a hosted mailbox over IMAP. See `mail/README.md`.

`deploy/systemd/bevins-mail.service.example` is a hardened unit (dedicated user, `CAP_NET_BIND_SERVICE` only).

## Prerequisites
1. **Inbound port 25** must reach your host if you run the SMTP receiver. From another network:
   `swaks --to scam@bevins.example.com --server 203.0.113.10` (or send a synthetic message once MX is up).
   If the provider blocks inbound port 25, use the IMAP poller instead of the direct receiver.
2. **Reverse DNS / deliverability.** If PTR is the host's default name rather than your domain, replies can land in spam. Publish SPF, DKIM, and DMARC below, and ask the provider to set PTR to your mail hostname. Confirm a synthetic reply arrives before you rely on it.

## DNS records to add (example.com zone, at your DNS provider)
| Type | Name | Value | Notes |
|------|------|-------|-------|
| MX | `bevins` | `10 bevins.example.com` | routes scam@bevins… to the box (A already → 203.0.113.10) |
| TXT | `bevins` | `v=spf1 ip4:203.0.113.10 -all` | SPF: only the box may send as this subdomain |
| TXT | `bevins._domainkey.bevins` | `v=DKIM1; k=rsa; p=<PUBLIC_KEY>` | DKIM public key (generated below) |
| TXT | `_dmarc.bevins` | `v=DMARC1; p=none; rua=mailto:scam@bevins.example.com` | DMARC (start p=none, tighten later) |

## Box deploy steps 
```bash
# 0) deps
sudo pip install --break-system-packages aiosmtpd dnspython dkimpy

# 1) dedicated locked-down user + writable dir
sudo useradd --system --no-create-home --shell /usr/sbin/nologin bevinsmail || true
sudo mkdir -p /opt/bevins/mail && sudo chown bevinsmail:bevinsmail /opt/bevins/mail

# 2) shared secret (app <-> mail service)  — root-owned cred source
openssl rand -hex 32 | sudo tee /opt/bevins/creds.src/scan_secret >/dev/null
sudo chmod 600 /opt/bevins/creds.src/scan_secret

# 3) DKIM keypair — private stays on box, public goes in the DNS TXT above
sudo openssl genrsa -out /opt/bevins/creds.src/dkim_private.pem 2048
sudo openssl rsa -in /opt/bevins/creds.src/dkim_private.pem -pubout 2>/dev/null \
  | grep -v '^-----' | tr -d '\n'      # <-- paste this as the p= value in the DKIM TXT record

# 4) wire the app: add scan_secret + a server provider key to bevins.service
#    LoadCredential=scan_secret:/opt/bevins/creds.src/scan_secret
#    LoadCredential=server_llm:/opt/bevins/creds.src/server_llm   (your Fireworks or OpenRouter key)
#    (server_llm powers scam scans of forwarded mail; store the FW key root-only, base64 as with the others)

# 5) deploy files + unit
sudo cp mail/bevins_mail.py /opt/bevins/bevins_mail.py
sudo cp deploy/systemd/bevins-mail.service.example /etc/systemd/system/bevins-mail.service
sudo cp app/app.py /opt/bevins/app.py     # the refactored app with /api/scan-email
sudo systemctl daemon-reload
sudo systemctl restart bevins        # picks up scan_secret + server_llm creds

# 6) TEST WITHOUT EXPOSING first: DEBUG_SINK mode writes verdicts to disk instead of emailing
sudo -u bevinsmail DEBUG_SINK_DIR=/opt/bevins/mail SCAN_SECRET=$(sudo cat /opt/bevins/creds.src/scan_secret) \
  python3 /opt/bevins/bevins_mail.py &     # then pipe a sample forwarded scam .eml at it on :25
#   confirm a verdict lands in /opt/bevins/mail/*.reply.txt

# 7) go live
sudo systemctl enable --now bevins-mail
sudo journalctl -u bevins-mail -f          # watch a real forwarded test email end-to-end
```

## Abuse / safety properties already built in
- Not an open relay: only accepts RCPT to scam@bevins…, only ever replies to the forwarder.
- Loop/auto-reply guard (Auto-Submitted, Precedence, mailer-daemon, self-address), per-sender rate limit,
  size cap, crisis + hard-line guards inherited from the shared engine.
- DEBUG_SINK mode to validate scanning before any mail is ever sent.
