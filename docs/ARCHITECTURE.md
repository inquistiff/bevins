# Bevins architecture

Bevins is a multi-tenant Flask app with a single-file PWA frontend. It has two jobs:
1. **Scam check.** Help an older adult or a trusted family helper judge a suspicious message, email,
   link or image. The user gets a plain-language verdict (high / uncertain / low risk), the exact
   phrases that triggered it, and a safe next step.
2. **AI expert / model router.** A chat assistant that picks a model for each request, rewrites
   prompts, checks answers and shows a "trust card" (confidence, sources, privacy redactions).

## Components
| Path | Role |
|---|---|
| `app/app.py` | Flask backend: auth, tenancy, router, scam engine, link/URL scanner, `/api/scan-email` |
| `app/index.html` | PWA frontend (single file, service worker served from `/sw.js`) |
| `app/image-origin-v1/` | In-browser C2PA image provenance check (Web Worker + WASM, see THIRD-PARTY-NOTICES) |
| `mail/bevins_mail.py` | Optional direct SMTP receiver: forward a suspicious email, get a verdict reply |
| `mail/bevins_mailpoll.py` | Hardened IMAP poller alternative (UID floor, BODY.PEEK, durable ledger, allow-listed replies) |
| `mail/mail_extract.py` | MIME/HTML extraction helpers |

## Security model
- **Auth:** PBKDF2-HMAC-SHA256 (210k iterations, per-credential salt), high-entropy bearer tokens with
  idle and absolute lifetimes, generic 401s (no account enumeration), constant-time comparisons.
- **SSO:** Apple / Google / Microsoft via server-side `sso.json` (0600). The admin enters secrets in a
  setup page. Checks `aud`/`iss`/`exp`/`email_verified`. No silent SSO-to-password account linking.
  Single-use CSRF state with a 600 s TTL stored in the DB.
- **Tenancy:** every row carries `owner_id`. PostgreSQL Row-Level Security (FORCE) is applied per transaction.
  The app role has no `BYPASSRLS` and fails closed when no context is set.
- **Signup:** the first account needs `ADMIN_BOOTSTRAP_TOKEN`. After that, new accounts need an invite code from an admin. That is per-installation access control for a public project, not a private hosted service.
- **Provider keys:** each user's OpenRouter / Fireworks / Together keys are Fernet-encrypted at rest,
  held server-side and never sent to the browser. Health requests are routed only to regulated providers.
- **Audit:** hash-chained audit log with no secrets or message text.
- **Outbound safety:** blocks requests to private and loopback addresses when fetching links. Uses fixed
  failure categories with no raw text in protected logs.

## Data model (per-user, RLS-isolated)
`users`, `conversations`, `messages`, `byok_keys`, `health_records` (encrypted, opt-in),
`bandit_stats` (per-user Thompson-sampling router learning), plus session, invite and audit tables.

## Router
Request classifier → Thompson bandit per provider+model arm → temperature policy. It also has a prompt
co-pilot (enhancer plus one round of clarifying questions), accuracy guards (confidence score, sources,
math re-check) and a Research mode (decompose → gather from several cheap models → cross-check → cited brief).
An optional `llm-matrix.json` next to `app.py` provides model scores. It is not shipped in this repo.

The matrix file format uses a field named `finnick` (`finnick.in_use_via` for a serving id, `finnick.data_tier` for the data-handling tier). That name is part of the format. Renaming it would stop existing matrix files from matching, so the code leaves it as-is. It is an internal key name, not a person.

The browser ships an illustrative model roster for routing and the in-app matrix. Dollar amounts from that roster are not shown as current prices. Cost bands are a stale relative snapshot. Confirm rates with the provider. The on-device health vault uses the IndexedDB name `bevins-health`.

## Scam engine
An LLM classifier returns strict JSON (`risk`, `context`, `signals[{code, quote}]`). Each quote must be an
exact substring of the input. The result is merged with deterministic signals and URL reputation
(Google Safe Browsing, VirusTotal), and the app checks the real link destinations it supports. A family-emergency
request with payment or secrecy pressure is always high risk. The advice is always to call back on a
number you already know.
