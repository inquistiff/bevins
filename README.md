# Bevins

Open-source scam detection for everyday people. Paste a suspicious email, text message, or the transcript of a phone call or voicemail. Forward an email to a mailbox you run. Or check an image's C2PA Content Credentials in the browser. Bevins answers in plain language: what looks risky, the exact words that triggered that, and a safe next step (call back on a number you already know).

It is meant for anyone who wants a careful second look, including older adults and family members helping them. It is also a self-hosted app: you run it, you hold the database, and each person brings their own model-provider key.

**Status: early alpha.** The mail tests pass in CI. The scam engine and the account system have a regression battery that needs Postgres. Live mail delivery is not verified. Do not treat a verdict as proof that a message is safe or that a sender is who they claim to be.

## Features

- **Message check.** Email, SMS, and call or voicemail text you paste. The checker looks for payment pressure, gift cards, secrecy, credential requests, and similar patterns. Quotes have to be exact substrings of what you submitted. A family-emergency request combined with payment or secrecy pressure is treated as high risk.
- **Links.** When the optional keys are set, checks use Google Safe Browsing, VirusTotal, and public threat feeds, and the server refuses to fetch private or loopback addresses.
- **Images.** A browser worker reads C2PA Content Credentials (manifest present or not, signature and file binding, signer not treated as trusted). It does not decide whether the picture is true or whether a request is safe.
- **Forwarded email.** An optional mailbox service accepts a forward and returns a verdict. The IMAP poller is the hardened path. The direct SMTP receiver is also included.
- **Assistant.** A signed-in chat can route a question across models (Thompson sampling), rewrite the prompt, and show a trust card. Health questions stay on a narrower provider path. This is general information, not medical, legal, or financial advice.

## Roadmap

- Richer intake for phone calls and voicemail, beyond pasting a transcript.
- Stronger checks for images that have no Content Credentials.
- Defenses against prompt injection and other attacks on AI assistants: treating untrusted email, web pages, and tool output as data, and making it harder for that text to steer the assistant or the scam checker.
- Clearer false-positive / false-negative reporting so everyday examples can improve the checker without leaking personal data.

## Quick start

You need Python 3.12+ and PostgreSQL 14+. The app role must not have `BYPASSRLS` or superuser. The app creates its tables on startup.

```bash
cd app
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# set DATABASE_URL and ADMIN_BOOTSTRAP_TOKEN
set -a && . ./.env && set +a
python3 app.py
```

Open http://127.0.0.1:8099. The first account uses the bootstrap token. Later accounts can require an invite code from that admin. In production, run `uvicorn app:asgi` behind TLS. Example Caddy and systemd files are in [`deploy/`](deploy/).

The forwarding mailbox is separate. See [`mail/README.md`](mail/README.md) and [`docs/MAIL-DEPLOY.md`](docs/MAIL-DEPLOY.md). Example hostnames in those docs (`bevins.example.com`, `203.0.113.10`) are placeholders.

## Configuration

Copy the example env files and fill them in locally. Do not commit them.

| File | What it configures |
| --- | --- |
| [`app/.env.example`](app/.env.example) | Database, bootstrap token, mail-scan secret, optional provider and threat-intel keys, optional operator-funded key allow-list |
| [`mail/.env.example`](mail/.env.example) | Mailbox address, IMAP or SMTP hosts, reply allow-list |
| [`mail/mail-policy.env.example`](mail/mail-policy.env.example) | Who the poller is allowed to reply to |

`FUNDED_USERS` is empty by default. Nobody spends an operator key unless you list them. An optional `llm-matrix.json` next to `app.py` can score models. It is not in this repository. If you add one, keep the `finnick` field name: it is part of that file format (`finnick.in_use_via`, `finnick.data_tier`), and renaming it breaks the matcher. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Tests

Mail tests do not need secrets, Docker, or a network. CI runs these on every push and pull request:

```bash
cd mail
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-test.txt
python3 test_mail.py
```

The app battery covers auth, row-level tenant isolation, and the scan endpoint. It needs a Postgres container named `bevins-postgres` on `127.0.0.1:5435`. CI starts that container and runs the battery. Locally:

```bash
docker run -d --name bevins-postgres \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:5435:5432 postgres:16
cd app && pip install -r requirements.txt pytest
cd tests && BEVINS_APP_PATH=../app.py pytest -q
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Issues for bugs, feature requests, and redacted false-positive / false-negative samples are in the issue templates. If you use a model to study real samples, read [docs/SAFE-ANALYSIS.md](docs/SAFE-ANALYSIS.md).

## Security

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/inquistiff/bevins/security/advisories/new). Please do not open a public issue for a security flaw. Details are in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. Copyright 2026 Tiffany Bridges. See [LICENSE](LICENSE).

The image checker bundles MIT-licensed C2PA components from Adobe's Content Authenticity Initiative (`@contentauth/c2pa-web` and related packages) and ISC dependencies (`highgain`, `ts-deepmerge`). Those notices stay under their own licenses. See [NOTICE](NOTICE) and [`app/image-origin-v1/THIRD-PARTY-NOTICES.txt`](app/image-origin-v1/THIRD-PARTY-NOTICES.txt).
