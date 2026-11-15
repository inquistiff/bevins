# Security policy

Bevins is early software. It gives a plain-language second look at messages and images. It does not replace your own judgment, a bank's fraud team, or law enforcement.

## Supported versions

Security fixes go on the `main` branch. There are no versioned releases yet.

## Reporting a vulnerability

Report suspected vulnerabilities privately with [GitHub private vulnerability reporting](https://github.com/inquistiff/bevins/security/advisories/new).

Please do not open a public issue, discussion, or pull request for a vulnerability. Do not include exploit details, live credentials, or real scam samples that still contain personal data.

Include enough to reproduce the problem: the affected path, what you expected, and what happened. Synthetic data is enough.

The maintainer aims to acknowledge a report within a few days. Please give a reasonable window to investigate and ship a fix before any public write-up.

## What this does not cover

A model calling a message legitimate, or flagging a real message, is a detection-quality issue. Use the false-positive / false-negative issue template for that, with personal information removed. Save private vulnerability reporting for flaws in the software itself (authentication, tenant isolation, credential handling, request forgery, and similar).
