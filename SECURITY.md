# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

Security fixes apply to the current `main` branch and the newest 1.x state. Users should upgrade to the fixed state as soon as it is available. This repository is a starter template rather than a deployed service, so consumers are responsible for patching applications generated from it.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/python-appsec-starter/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include:

- The affected file, function or endpoint.
- A minimal proof of concept.
- Security impact and preconditions.
- Whether the issue affects only the demo, only the reusable middleware, or both.

Do not include real credentials, tokens, cookies, private keys, customer data or personal data in a report. Redact secrets before attaching logs.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed state and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

## Scope notes

The demo server is a teaching and regression harness. Reusable middleware correctness is in scope. Missing authentication, rate limiting or production infrastructure controls documented as non-goals are not vulnerabilities by themselves, but reports are still welcome when the documentation is unclear.
