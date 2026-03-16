# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes     |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in VulnCore, report it privately:

1. Go to the [Security tab](../../security/advisories/new) of this repository
2. Click **"Report a vulnerability"**
3. Fill in the details

We will acknowledge your report within **48 hours** and aim to release a fix within **7 days** for critical issues.

### What to include
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

### What to expect
- Acknowledgment within 48 hours
- Regular updates on our progress
- Credit in the security advisory (if desired)
- A CVE assignment if applicable

## Scope

In scope:
- Remote code execution in the API or scanner
- Authentication/authorization bypass
- SQL injection or data exposure via the API
- Supply chain / dependency vulnerabilities with real impact

Out of scope:
- Vulnerabilities in scanned targets (that's the point of the tool)
- Issues requiring physical access to the server
- Social engineering attacks
