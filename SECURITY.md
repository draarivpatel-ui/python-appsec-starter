# Security policy

## Supported versions

The `main` branch and the newest tagged template state are supported. This repository is a starter template rather than a deployed service, so consumers are responsible for patching applications generated from it.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Use GitHub private vulnerability reporting for `draarivpatel-ui/python-appsec-starter` when available. Include:

1. Affected file, function, or endpoint.
2. A minimal proof of concept.
3. Security impact and preconditions.
4. Whether the issue affects only the demo, only the reusable middleware, or both.

Please allow reasonable time for triage before public disclosure. Reports that are only theoretical hardening suggestions may be converted into public enhancement issues after triage.

## Scope notes

The demo server is a teaching and regression harness. Reusable middleware correctness is in scope. Missing authentication, rate limiting, or production infrastructure controls documented as non-goals are not vulnerabilities by themselves, but reports are still welcome when the documentation is unclear.
