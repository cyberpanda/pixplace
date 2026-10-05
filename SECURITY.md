# Security Policy

Pixplace is experimental software. Please do not run it in production without reviewing the code and your own requirements.

## Reporting a vulnerability

Please **open an issue** in this repository's Issues tab and describe the problem: what is affected, steps to reproduce, and the version (`PP_VERSION`). Use the "Security issue" template if it is offered.

Tips:
- Describe the impact and how to reproduce it, but avoid posting real user data, passwords or tokens.
- If you would rather not discuss details publicly first, open an issue with a short summary and I will follow up, or message me on X: [@realcyberpanda](https://x.com/realcyberpanda).

This is a hobby project maintained in spare time, so response times may vary, but reports are appreciated and taken seriously.

## Hardening checklist for operators

- Run behind a TLS reverse proxy (Caddy/nginx examples in `deploy/`) so traffic is `https`/`wss`
- Change the one-time owner password after the first sign-in, enable 2FA
- Keep the data directory outside any publicly served folder
- Restrict `/admin` (path, IP allow-list) where possible
- Choose the logging mode that matches your privacy obligations

## Donations

No donations, please. Contributions are welcome instead – see [CONTRIBUTING.md](CONTRIBUTING.md).
