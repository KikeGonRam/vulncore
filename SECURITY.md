# Security Policy

## Supported Versions

| Version | Supported | Notes                              |
|---------|-----------|------------------------------------|
| 0.5.x   | ✅ Yes     | Current — Docker + auth            |
| 0.4.x   | ✅ Yes     | Auth + export + webhooks           |
| 0.3.x   | ⚠️ Partial | Dashboard redesign — no auth       |
| 0.2.x   | ❌ No      | Missing auth — do not expose publicly |
| 0.1.x   | ❌ No      | No auth, no WAL, no webhooks       |

---

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in VulnCore itself, report it privately:

1. Go to the [Security tab](../../security/advisories/new) of this repository
2. Click **"Report a vulnerability"**
3. Fill in the details below

We will acknowledge your report within **48 hours** and aim to release a fix within **7 days** for critical issues.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact and affected component
- Suggested fix (optional)

### What to expect

- Acknowledgment within 48 hours
- Regular status updates
- Credit in the security advisory (if desired)
- A CVE assignment if applicable

---

## Scope

### In scope

- Remote code execution via the API or scanner binary
- Authentication or authorization bypass
- SQL injection or data exposure via the API
- Token forgery or HMAC bypass in the auth system
- Supply chain vulnerabilities in direct dependencies with real-world impact
- Secrets or credentials leaked via logs, error messages, or headers

### Out of scope

- Vulnerabilities in the *targets* being scanned (that is the tool's purpose)
- Issues requiring physical access to the server running VulnCore
- Social engineering attacks
- Self-XSS (the dashboard is a single-user admin interface behind auth)
- Vulnerabilities in indirect dependencies with no practical exploit path

---

## Security Architecture

### Authentication

VulnCore uses a stateless Bearer token system:

- Token is derived from `HMAC-SHA256(username, VULNCORE_SECRET)`
- All `/api/*` routes except `/api/health` and `/api/auth/login` require the token
- Token is stored in the browser's `localStorage` — not in a cookie, so no CSRF risk
- There is no token expiry by default — rotate by changing `VULNCORE_SECRET`

**Important:** Change the default `VULNCORE_SECRET` before deploying. The default fallback (`vulncore-default-secret`) is public knowledge.

### Network exposure

VulnCore is designed to run on a trusted internal network or behind a reverse proxy. It does **not** enforce TLS by itself.

**Recommended production setup:**
```
Internet → nginx/Caddy (TLS termination) → VulnCore (localhost:8080)
```

Do not expose port 8080 directly to the internet without TLS.

### Docker hardening

The Docker image runs as the `vulncore` user (non-root). The container has no privileged capabilities by default. Scan data is stored in an isolated named volume.

### SQLite

The database file is stored on disk with no encryption. Protect access to the host filesystem or Docker volume if the data is sensitive.

---

## Known Limitations

- **Single-user only** — there is one username/password pair configured via environment variables. Multi-user support is not planned until v1.0.
- **No token revocation** — tokens remain valid until `VULNCORE_SECRET` is changed.
- **No rate limiting** — the API does not currently rate-limit login attempts. Place a rate-limiting reverse proxy in front for public-facing deployments.
- **No TLS** — VulnCore does not serve HTTPS. Use a reverse proxy (nginx, Caddy, Traefik) in front.

---

## Responsible Disclosure

We ask that you:

1. Give us a reasonable amount of time to fix the issue before any public disclosure
2. Make a good-faith effort not to access or modify data that is not yours
3. Not perform attacks that could harm the availability of the service

We commit to:

1. Responding within 48 hours
2. Working with you to understand and resolve the issue
3. Crediting you in the security advisory (unless you prefer anonymity)
4. Not pursuing legal action against researchers acting in good faith