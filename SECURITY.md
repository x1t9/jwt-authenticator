# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Yes     |
| 1.x     | ❌ No      |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report security issues privately by emailing the maintainers or opening a [GitHub Security Advisory](https://github.com/x1t9/jwt-authenticator/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to acknowledge reports within 48 hours and release a patch within 7 days for critical issues.

## Security Best Practices

When using this plugin:
- Use a strong, random `JWT_AUTH_SECRET_KEY` (minimum 32 characters)
- Always serve your site over HTTPS
- Keep access token expiry short (1 hour default is recommended)
- Rotate API keys regularly
- Enable rate limiting in production
- Review Firestore security rules when using Firestore sync
