# Security Policy

This is a session management library. Security bugs here can affect every
application that trusts created, validated, rotated, or revoked sessions, so we
take reports seriously and move fast on them.

**Do not open a public issue for a vulnerability.**

## Supported Versions

We apply security fixes to the current stable release (`latest`). Backports are
case-by-case. Severe session bypass, replay, fixation, revocation, or token
exposure issues may receive an out-of-band patch.

If you are using the `next` prerelease channel, include the exact prerelease
version in your report.

## Reporting a Vulnerability

Contact the maintainers directly through a private channel. If GitHub private
vulnerability reporting is enabled for the repository, use that. Otherwise,
email the Resting Owl maintainers through the private security contact published
by the organization.

When you report, include:

- What the issue is and where you found it.
- Which version or commit is affected.
- Your environment, including Node.js version, runtime framework, and storage
  adapter.
- Steps to reproduce or a proof of concept.
- Expected impact, such as session bypass, token replay, fixation, CSRF bypass,
  revocation failure, sensitive data exposure, or denial of service.
- Any suggested fix, if you have one.

## Response Targets

| Severity | Acknowledgement | Triage   | Fix Target                   |
| -------- | --------------- | -------- | ---------------------------- |
| Critical | 24 hours        | 72 hours | Out-of-band patch ASAP       |
| High     | 2 business days | 5 days   | Next patch release or sooner |
| Medium   | 3 business days | 10 days  | Next scheduled release       |
| Low      | 5 business days | 15 days  | Best-effort, normal roadmap  |

These are targets, not service-level agreements. Maintainers will communicate
when a fix or coordinated disclosure needs more time.

## What Happens After You Report

1. We confirm receipt privately.
2. We validate impact and affected versions.
3. We prepare and test a fix privately.
4. We publish a patched release.
5. We publish disclosure and remediation guidance when appropriate.

## In Scope

- Session validation bypasses.
- Session fixation, replay, or rotation-reuse detection failures.
- Raw token or CSRF token leakage through logs, responses, or persisted storage.
- CSRF validation bypasses in service or middleware behavior.
- Revocation, revoke-all, or selective-revocation failures with security impact.
- Redis adapter atomicity bugs that allow stale or conflicting session state.
- Middleware behavior that incorrectly authenticates a request.

## Out of Scope

- Bugs in unsupported or end-of-life versions.
- Authentication failures before the application calls `createSession`.
- Application authorization logic outside this library.
- Insecure cookie, TLS, CORS, or proxy configuration in the consuming
  application.
- Non-security bugs with no realistic security impact.

## Security Boundary

OwlSessionGuard manages server-side session state and middleware session
attachment. It does not authenticate users, authorize application resources,
issue JWT access tokens, manage MFA, configure TLS, or protect applications from
XSS. Those controls must be implemented by the consuming application or by
dedicated authentication and token-management layers.
