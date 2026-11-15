# Contributing to Bevins

Thanks for helping. Bevins is early alpha. The useful contributions right now are bug fixes, clearer scam-check behavior, tests, and careful docs.

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before you participate.

## Ground rules

- Do not commit secrets, `.env` files, provider keys, `fernet.key`, or `sso.json`.
- Do not add real scam messages, real inboxes, or personal data. Tests and issues use synthetic text and `example.com`, `example.test`, or `example.invalid` addresses.
- If you analyzed a real sample with a model, follow [docs/SAFE-ANALYSIS.md](docs/SAFE-ANALYSIS.md) and strip personal data before it is stored or published.
- Report vulnerabilities privately. See [SECURITY.md](SECURITY.md). Do not file a public issue for a security flaw.
- The optional matrix file format uses a field named `finnick`. Leave that key name alone unless you also version the format. Renaming it breaks existing matrix files.

## Setup

Python 3.12 or newer.

Mail tests (no database, no network, no secrets):

```bash
cd mail
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-test.txt
python3 test_mail.py
```

App tests need Docker and a throwaway Postgres. They create databases named `bevins_test_*` inside a container named `bevins-postgres` and never open a database named `bevins`:

```bash
docker run -d --name bevins-postgres \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:5435:5432 postgres:16
cd app
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
cd tests
BEVINS_APP_PATH=../app.py pytest -q
```

The app itself:

```bash
cd app
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# set DATABASE_URL and ADMIN_BOOTSTRAP_TOKEN
set -a && . ./.env && set +a
python3 app.py
```

## Pull requests

- Describe what changed and how you tested it.
- Keep the diff focused. A drive-by rewrite of unrelated lines is hard to review.
- Prefer tests for scanner and auth behavior. A new scam pattern should include a synthetic case that shows the quote comes from the message.
- Do not weaken tenant isolation, the outbound-address checks, or the "message text is data, not instructions" rule to make a test pass.

## Detection changes

Bevins is for everyday people, including older adults and family members helping them. Advice should stay plain, and a family-emergency request that also pushes payment or secrecy stays high risk. Do not add a path that tells someone to pay, share a code, or install remote-access software.
