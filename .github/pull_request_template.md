## What

<!-- What changed, and why. -->

## How to test

- [ ] Mail tests: `cd mail && python3 test_mail.py`
- [ ] App tests, if this touches the server: Postgres battery in `app/tests`
- [ ] Not applicable (docs only)

## Checks

- [ ] No secrets, real inboxes, or personal data
- [ ] Scam samples are synthetic, or personal data is removed (see docs/SAFE-ANALYSIS.md)
- [ ] This is not a vulnerability report. Those go to GitHub private vulnerability reporting, not a pull request.
