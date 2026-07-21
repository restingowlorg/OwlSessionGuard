# Changelog

All notable changes to this project are managed with
[Changesets](https://github.com/changesets/changesets).

## 1.0.0

- Initial public release of OwlSessionGuard as
  `@restingowlorg/owlsessionguard`.
- Added framework-agnostic session service APIs for create, validate, rotate,
  revoke, revoke-all, list, and selective revocation flows.
- Added in-memory and Redis storage adapters.
- Added Express, Fastify, and NestJS middleware integrations.
- Added session token hashing, CSRF token binding, security-policy evaluation,
  device context extraction, and role-aware session limits.
