# Contributing

Thanks for contributing to `@restingowlorg/owlsessionguard`.

This project is a security-sensitive session management library, so all changes
are expected to meet a higher review and release quality bar.

## Development Setup

```bash
npm install
npx --no-install husky
```

## Branching

- Branch from `develop`, not `main` or `staging`.
- Use names like `feature/...`, `fix/...`, `docs/...`, or `chore/...`.
- PRs target `develop` first.
- `staging` is validation-only and used for prerelease promotion.
- `main` is release-only and updated by the release workflow.
- Open a pull request for every change.

## Pull Request Expectations

PRs should be:

- Small and focused.
- Backed by tests when behavior changes.
- Documented when public behavior changes.
- Accompanied by a changeset for user-facing changes.

## Required Checks

Before opening or updating a PR, run:

```bash
npm run release:validate
```

This runs formatting, linting, type checking, build, package validation, tests,
Redis integration tests, and the consumer smoke test.

## Changesets

Add a changeset for any user-facing change:

```bash
npm run changeset
```

Use:

- `patch` for fixes and safe security improvements.
- `minor` for backward-compatible features.
- `major` for breaking changes.

## Security-Sensitive Changes

Changes involving session creation, validation, rotation, revocation, CSRF,
device binding, IP binding, storage adapters, middleware authentication
behavior, or logging should include:

- Clear rationale.
- Regression tests where feasible.
- Notes about compatibility or migration impact.
- Documentation updates for public behavior.

## Commit Messages

This repository uses Conventional Commits and commitlint.

Examples:

- `fix(core): prevent rotated session replay`
- `feat(redis): add role-aware session limit checks`
- `docs(security): clarify session boundary`
