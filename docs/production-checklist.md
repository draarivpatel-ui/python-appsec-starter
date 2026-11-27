# Production checklist

Before deploying an application created from this template:

1. Replace development secrets with distinct high-entropy production secrets.
2. Serve only HTTPS in production and keep `Secure` cookies enabled.
3. Prefer `__Host-session` and `__Host-csrf` cookie names through `SecurityConfig.production_copy()`.
4. Set explicit redirect and outbound host allowlists.
5. Review CSP against the real frontend. Remove any source the application does not need.
6. Keep framework CSRF defenses enabled where the framework provides them.
7. Add authentication, authorization, object-level access checks, rate limits, and audit logging.
8. Revalidate every redirect hop before outbound fetching and validate DNS answers at connect time.
9. Run dependency, secret, container, and infrastructure scanning in your own pipeline.
10. Add abuse-case tests whenever a route accepts new input shapes.
11. Keep error responses free of attacker controlled values.
12. Verify that reverse proxy forwarding headers cannot be spoofed by clients.
13. Run the full test suite on Python 3.9 through 3.13 before release.
