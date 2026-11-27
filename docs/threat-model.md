# Threat model

## Assets

- Integrity and confidentiality of user session cookies.
- Integrity of state-changing requests.
- Filesystem contents outside the configured fixture or upload root.
- Internal network reachability from the application host.
- Availability of the Python process under adversarial input.
- Confidentiality of secrets and personal data in logs.

## Adversary capabilities

The remote adversary can choose URL paths, query strings, headers, cookies, JSON bodies, filenames, redirect parameters, template-like strings, and uploaded bytes. The adversary can send malformed, nested-encoded, Unicode-confusing, oversized, deeply nested, duplicated, and high-cardinality input. The adversary cannot read server memory or modify trusted configuration.

## Controls

| Threat | Control |
| --- | --- |
| XSS amplification and content sniffing | CSP, nosniff, frame and cross-origin isolation headers |
| Protocol downgrade | HSTS after HTTPS deployment |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |
| Path traversal | Strict decoding, no dot segments, no backslash, root containment, symlink rejection |
| Upload filename abuse | Single-component sanitized filenames and reserved device rejection |
| Open redirect | Relative-only default, HTTPS plus explicit host allowlist for absolute URLs |
| SSRF | Scheme, port, userinfo, host, IP literal, internal-name, and optional DNS checks |
| Session token tampering | HMAC-SHA256 signed cookie payloads with expiry |
| CSRF | SameSite cookies plus signed double-submit verification |
| JSON parser abuse | Byte, depth, node, key, array, string, duplicate-key, and integer bounds |
| HPP and parser differentials | Strict pair grammar, duplicate and case-collision rejection |
| NoSQL and object-path injection | Dollar-key, dot-key, bracket-key, prototype-key, and dunder-key rejection |
| Log injection | One-line escaping, Unicode control escaping, token and secret redaction |

## Non-goals and residual risk

- The starter does not provide authentication, authorization, account recovery, rate limiting, malware scanning, or dependency scanning.
- The SSRF validator does not fetch. Production fetchers must revalidate each redirect and should resolve DNS at connect time while preventing rebinding.
- Compact starter controls are not a replacement for the dedicated `py*cage` packages when their deeper coverage is needed.
- HSTS is emitted by the demo for visibility. Browsers only honor it over HTTPS. Do not treat local HTTP testing as proof of transport security.
- Reverse proxies must be configured to preserve or strip untrusted forwarding headers consistently. This template does not trust `X-Forwarded-For` or `X-Forwarded-Proto`.
