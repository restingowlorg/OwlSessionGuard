# OwlSessionGuard

<p align="center">
  <img src="docs/assets/restingowl-logo.png" alt="OwlSessionGuard logo" width="320" />
</p>

---

[![npm package](https://img.shields.io/badge/npm-%40restingowlorg%2Fowlsessionguard-CB3837?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@restingowlorg/owlsessionguard) [![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933?style=flat-square&logo=node.js&logoColor=white)](https://www.npmjs.com/package/@restingowlorg/owlsessionguard) [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Open-source OWASP-aligned session management and security middleware for Node.js.

OwlSessionGuard, published as `@restingowlorg/owlsessionguard`, gives your backend a focused session-management surface: high-entropy session tokens, hash-only token storage, automatic rotation, reuse detection, device and IP binding, CSRF token binding, selective revocation, concurrent session limits, and framework adapters for Express, Fastify, and NestJS.

- **Package:** `@restingowlorg/owlsessionguard`
- **Latest stable tag:** `latest`
- **Prerelease tag:** `next`
- **Install:** `npm install @restingowlorg/owlsessionguard`
- **Developer guide:** [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)
- **Security policy:** [SECURITY.md](SECURITY.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

## What You Get

- **Secure session lifecycle:** Create, validate, rotate, revoke, revoke-all, and list user sessions through one typed service.
- **Hash-only token storage:** Raw session tokens are returned once to the caller and are never persisted by the built-in stores.
- **Automatic reuse detection:** Reuse of a rotated token can revoke the affected session tree.
- **Idle and absolute expiration:** Support rolling idle timeouts and hard absolute session lifetime limits.
- **Security binding:** Optional IP and device fingerprint checks with soft or hard enforcement modes.
- **CSRF protection:** HMAC-signed CSRF tokens bound to the server-side session ID.
- **Concurrent session limits:** Enforce global per-user caps and role-specific caps.
- **Storage adapters:** In-memory storage for local/test use and Redis storage for production deployments.
- **Framework middleware:** Express, Fastify, and NestJS integrations attach typed session context to requests.
- **Typed, predictable results:** Public service methods return a consistent `SessionOpResult<T>` envelope.

## Support Matrix

| Area          | Current Support                        |
| ------------- | -------------------------------------- |
| Runtime       | Node.js 18+                            |
| Language      | TypeScript, JavaScript                 |
| Module output | CommonJS                               |
| Frameworks    | Express, Fastify, NestJS               |
| Storage       | In-memory, Redis                       |
| Core flows    | Create, Validate, Rotate, Revoke, List |

## Installation

```bash
npm install @restingowlorg/owlsessionguard
```

Install only the framework peer dependencies you use:

```bash
npm install express
npm install fastify
npm install @nestjs/common @nestjs/core rxjs
```

## Quick Start

```ts
import {
  SessionLibraryConfig,
  SessionReasonCode,
  SessionService,
} from "@restingowlorg/owlsessionguard";
import { MemoryStoreAdapter } from "@restingowlorg/owlsessionguard/storage/memory";

const store = new MemoryStoreAdapter();

const config: SessionLibraryConfig = {
  env: "production",
  transport: {
    mode: "cookie",
    cookie: {
      name: "__Host-session",
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    },
  },
  expiration: {
    idleTimeoutSeconds: 60 * 60,
    absoluteTimeoutSeconds: 60 * 60 * 24,
    rolling: true,
  },
  rotation: {
    gracePeriodSeconds: 5,
  },
  security: {
    enforceTlsInProduction: true,
    ipBinding: "soft",
    fingerprinting: "hard",
    csrf: {
      enabled: true,
      secret: process.env.SESSION_CSRF_SECRET!,
      cookieName: "x-csrf-token",
      headerName: "x-csrf-token",
    },
  },
  device: {
    enabled: true,
    cookie: {
      name: "__Host-device",
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    },
  },
  limits: {
    maxSessionsPerUser: 5,
    maxSessionsPerRole: {
      admin: 2,
    },
  },
  store: {
    provider: "memory",
  },
  observability: {
    debug: false,
    emitEvents: true,
    metrics: true,
  },
};

const sessions = new SessionService(store, config);

const created = await sessions.createSession({
  userId: "user_123",
  roles: ["admin"],
  scopes: ["read", "write"],
  metadata: {
    ipAddress: "203.0.113.10",
    userAgent: "Mozilla/5.0",
    deviceId: "device-cookie-value",
  },
});

if (!created.success) {
  throw new Error(created.error.message);
}

const { token, record } = created.data;

const validated = await sessions.validateSession({
  token,
  csrfToken: created.newCsrfToken,
  context: {
    ipAddress: "203.0.113.10",
    userAgent: "Mozilla/5.0",
    deviceFingerprint: record.metadata.deviceFingerprint,
    method: "POST",
  },
});

if (validated.success) {
  console.log(validated.data.userId);
}

await sessions.revokeSession({
  sessionId: record.id,
  reason: SessionReasonCode.MANUAL_LOGOUT,
});
```

> **Production note:** Use `MemoryStoreAdapter` only for local development, tests, or single-process demos. Production deployments should use `RedisStoreAdapter` or a custom `SessionStoreAdapter` backed by durable infrastructure.

## Storage

### Memory

```ts
import { MemoryStoreAdapter } from "@restingowlorg/owlsessionguard/storage/memory";

const store = new MemoryStoreAdapter();
```

### Redis

```ts
import Redis from "ioredis";
import { RedisStoreAdapter } from "@restingowlorg/owlsessionguard/storage/redis";

const redis = new Redis(process.env.REDIS_URL!);
const store = new RedisStoreAdapter(redis, {
  keyPrefix: "owlsessionguard:",
  ttlBufferSeconds: 60,
  batchSize: 500,
  maxAbsoluteTimeoutSeconds: 2592000,
});
```

| Option                      | Default          | Purpose                                                                                   |
| --------------------------- | ---------------- | ----------------------------------------------------------------------------------------- |
| `keyPrefix`                 | `"owlsessionguard:"` | Redis key namespace prefix.                                                           |
| `ttlBufferSeconds`         | `0`              | Seconds subtracted from session TTL for clock-drift safety.                              |
| `batchSize`                | `500`            | Batch size for SCAN-based queries (e.g., `findLiveSessionsForUser`).                     |
| `maxAbsoluteTimeoutSeconds` | `2592000` (30d) | Hard ceiling on absolute session lifetime in Redis, regardless of config.                 |

## Framework Integration

### Express

Peer dependency: `express`

```ts
import express from "express";
import {
  createExpressMiddleware,
  requireSession,
} from "@restingowlorg/owlsessionguard/express";

const app = express();

app.use(createExpressMiddleware(sessions, config));

app.get("/me", requireSession(), (req, res) => {
  res.json({
    userId: req.session?.userId,
    roles: req.session?.roles,
  });
});
```

### Fastify

Peer dependency: `fastify`

```ts
import Fastify from "fastify";
import {
  fastifyRequireSession,
  fastifySessionPlugin,
} from "@restingowlorg/owlsessionguard/fastify";

const app = Fastify();

await app.register(fastifySessionPlugin, {
  service: sessions,
  config,
});

app.get("/me", { preHandler: fastifyRequireSession() }, async (request) => {
  return {
    userId: request.session?.userId,
    roles: request.session?.roles,
  };
});
```

### NestJS

Peer dependencies: `@nestjs/common`, `@nestjs/core`, `rxjs`

```ts
// session.module.ts
import { Module } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { SessionService } from "@restingowlorg/owlsessionguard";
import { MemoryStoreAdapter } from "@restingowlorg/owlsessionguard/storage/memory";
import { SessionGuard, SessionInterceptor } from "@restingowlorg/owlsessionguard/nestjs";
import { AdminController } from "./admin.controller";

const store = new MemoryStoreAdapter();
const config = {
  env: "production" as const,
  transport: { mode: "cookie" as const },
  expiration: { idleTimeoutSeconds: 3600, absoluteTimeoutSeconds: 86400, rolling: true },
  rotation: { gracePeriodSeconds: 5 },
  security: {
    enforceTlsInProduction: true,
    ipBinding: "off" as const,
    fingerprinting: "off" as const,
    csrf: { enabled: false as const },
  },
  limits: { maxSessionsPerUser: 5 },
  store: { provider: "memory" as const },
  observability: { debug: false, emitEvents: false, metrics: false },
};

const sessionService = new SessionService(store, config);

@Module({
  controllers: [AdminController],
  providers: [
    { provide: SessionService, useValue: sessionService },
    Reflector,
    {
      provide: SessionGuard,
      inject: [SessionService, Reflector],
      useFactory: (service: SessionService, reflector: Reflector) =>
        new SessionGuard(service, config, reflector),
    },
    {
      provide: SessionInterceptor,
      inject: [SessionService],
      useFactory: (service: SessionService) =>
        new SessionInterceptor(service, config),
    },
  ],
})
export class SessionModule {}
```

```ts
// admin.controller.ts
import { Controller, Get, UseGuards } from "@nestjs/common";
import {
  RequireRoles,
  Session,
  SessionGuard,
} from "@restingowlorg/owlsessionguard/nestjs";
import type { SessionRecord } from "@restingowlorg/owlsessionguard";

@Controller("admin")
@UseGuards(SessionGuard)
export class AdminController {
  @Get("me")
  @RequireRoles("admin")
  getCurrentSession(@Session() session: SessionRecord | undefined) {
    return {
      userId: session?.userId,
      roles: session?.roles,
    };
  }
}
```

`SessionGuard` validates the session and enforces roles/scopes — it throws `UnauthorizedException` or `ForbiddenException` on failure. `SessionInterceptor` attaches the session optionally without throwing, useful when you want to read the session if present but still allow unauthenticated access to certain routes.

```ts
// profile.controller.ts — optional session attachment
import { Controller, Get, UseInterceptors } from "@nestjs/common";
import {
  Session,
  SessionInterceptor,
} from "@restingowlorg/owlsessionguard/nestjs";
import type { SessionRecord } from "@restingowlorg/owlsessionguard";

@Controller("profile")
@UseInterceptors(SessionInterceptor)
export class ProfileController {
  @Get("me")
  getProfile(@Session() session: SessionRecord | undefined) {
    if (!session) {
      return { anonymous: true };
    }
    return { userId: session.userId, roles: session.roles };
  }
}
```

## Configuration Options

### Core

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `env`                               | `"development" \| "test" \| "production"` | Drives production-only security validation (e.g., rejects non-HTTPS cookies in production).                                                        |

### Transport

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `transport.mode`                    | `"cookie" \| "header" \| "hybrid"`        | Selects how session tokens are read and written by middleware.                                                                                     |
| `transport.cookie.name`             | `string`                                  | Session cookie name. Use `__Host-` prefix for host-bound cookies.                                                                                  |
| `transport.cookie.httpOnly`         | `boolean`                                 | Prevents JavaScript access to the session cookie.                                                                                                  |
| `transport.cookie.secure`           | `boolean`                                 | Sends the cookie only over HTTPS.                                                                                                                  |
| `transport.cookie.signed`           | `boolean`                                | Signs the cookie with HMAC to detect tampering.                                                                                                    |
| `transport.cookie.sameSite`         | `"lax" \| "strict" \| "none"`            | CSRF protection mode for the cookie.                                                                                                               |
| `transport.cookie.path`             | `string`                                  | Cookie path scope.                                                                                                                                 |
| `transport.cookie.domain`           | `string`                                  | Cookie domain scope.                                                                                                                               |
| `transport.cookie.maxAgeSeconds`    | `number`                                  | Maximum age of the cookie in seconds.                                                                                                              |
| `transport.header.name`             | `string`                                  | Request header name containing the session token.                                                                                                  |
| `transport.header.scheme`           | `string`                                  | Optional prefix stripped from the header value (e.g., `Bearer`).                                                                                   |
| `transport.header.responseHeader`   | `string`                                  | Response header to write rotated tokens into.                                                                                                      |

### Expiration

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `expiration.idleTimeoutSeconds`     | `number`                                  | Maximum inactivity period before a session expires.                                                                                                |
| `expiration.absoluteTimeoutSeconds` | `number`                                  | Hard maximum lifetime regardless of activity.                                                                                                      |
| `expiration.rolling`                | `boolean`                                 | Extends idle expiration on successful validation.                                                                                                  |

### Rotation

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rotation.gracePeriodSeconds`       | `number`                                  | Short retry window for in-flight requests after rotation. Maximum accepted value is 30 seconds.                                                    |

### Security

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `security.enforceTlsInProduction`   | `boolean`                                 | Rejects non-secure cookies when `env` is `"production"`.                                                                                           |
| `security.ipBinding`                | `"off" \| "soft" \| "hard"`               | Compares request IP address to the stored session IP. `"soft"` logs a warning; `"hard"` revokes the session.                                      |
| `security.fingerprinting`           | `"off" \| "soft" \| "hard"`               | Compares request device fingerprint to the stored session fingerprint. `"soft"` logs a warning; `"hard"` revokes the session.                     |
| `security.csrf.enabled`            | `boolean`                                 | Enables HMAC-signed CSRF tokens bound to the session ID for mutating methods.                                                                      |
| `security.csrf.secret`             | `string`                                  | Minimum 32-character HMAC signing key. Required when `enabled` is `true`.                                                                          |
| `security.csrf.previousSecret`     | `string`                                  | Previous secret for gradual key rotation during secret rotation.                                                                                   |
| `security.csrf.cookieName`         | `string`                                  | Cookie name for the CSRF token.                                                                                                                    |
| `security.csrf.headerName`         | `string`                                  | Request header name for the CSRF token.                                                                                                            |

### Device

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `device.enabled`                    | `boolean`                                 | Enables persistent device-cookie extraction for fingerprint checks.                                                                                |
| `device.cookie.name`               | `string`                                  | Device cookie name.                                                                                                                                |
| `device.cookie.httpOnly`           | `boolean`                                 | Prevents JavaScript access to the device cookie.                                                                                                   |
| `device.cookie.secure`             | `boolean`                                 | Sends the device cookie only over HTTPS.                                                                                                           |
| `device.cookie.sameSite`           | `"lax" \| "strict" \| "none"`            | CSRF protection mode for the device cookie.                                                                                                        |
| `device.cookie.path`               | `string`                                  | Device cookie path scope.                                                                                                                          |
| `device.cookie.domain`             | `string`                                  | Device cookie domain scope.                                                                                                                        |
| `device.cookie.maxAgeSeconds`      | `number`                                  | Maximum age of the device cookie in seconds.                                                                                                       |

### Limits

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `limits.maxSessionsPerUser`         | `number`                                  | Maximum active sessions per user (global cap).                                                                                                     |
| `limits.maxSessionsPerRole`         | `Record<string, number>`                  | Optional role-specific active-session limits.                                                                                                      |

### Concurrency

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `concurrency.lockTimeoutMs`         | `number`                                  | Maximum time in ms to wait for a concurrency lock. Default: `50`.                                                                                  |
| `concurrency.pollIntervalMs`        | `number`                                  | Polling interval in ms when waiting for a lock. Default: `5`.                                                                                      |

### Store

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `store.provider`                    | `"memory" \| "redis" \| "mongo" \| "postgres" \| "custom"` | Declares the configured storage backend.                                                          |
| `store.redis.url`                   | `string`                                  | Redis connection URL. Required when `provider` is `"redis"`.                                                                                       |
| `store.redis.keyPrefix`            | `string`                                  | Redis key prefix. Default: `"owlsessionguard:"`.                                                                                                   |
| `store.redis.ttlBufferSeconds`     | `number`                                  | Seconds subtracted from TTL for clock-drift safety. Default: `0`.                                                                                  |
| `store.mongo.uri`                  | `string`                                  | MongoDB connection URI. Required when `provider` is `"mongo"`.                                                                                     |
| `store.mongo.collectionName`       | `string`                                  | MongoDB collection name.                                                                                                                           |
| `store.postgres.url`               | `string`                                  | PostgreSQL connection URL. Required when `provider` is `"postgres"`.                                                                               |
| `store.postgres.tableName`         | `string`                                  | PostgreSQL table name.                                                                                                                             |
| `store.custom.adapter`             | `SessionStoreAdapter`                     | Custom store adapter instance. Required when `provider` is `"custom"`.                                                                             |

> **Note:** `"mongo"` and `"postgres"` are accepted as config provider values for type safety and validation. Built-in adapters for these backends are not shipped in v1.0.0. Use `store.provider: "custom"` with a user-implemented `SessionStoreAdapter` for MongoDB or PostgreSQL.

### Observability

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `observability.debug`               | `boolean`                                 | Enables verbose debug logging for session operations.                                                                                              |
| `observability.emitEvents`          | `boolean`                                 | Enables structured event listener dispatch.                                                                                                        |
| `observability.metrics`             | `boolean`                                 | Enables internal metrics counters.                                                                                                                 |

## Session Operations

### Rotate a Session

```ts
const rotated = await sessions.rotateSession({
  token,
  context: {
    ipAddress: "203.0.113.10",
    userAgent: "Mozilla/5.0",
    deviceFingerprint: record.metadata.deviceFingerprint,
    method: "POST",
  },
  reason: SessionReasonCode.ROTATION,
  roles: ["admin"],
});

if (rotated.success) {
  const nextToken = rotated.data.newToken;
}
```

### Revoke All Sessions for a User

```ts
await sessions.revokeAllSessionsForUser(
  "user_123",
  SessionReasonCode.USER_ALL_SESSIONS_REVOKED,
);
```

### List User Sessions

```ts
const listed = await sessions.listUserSessions("user_123", {
  limit: 20,
  role: "admin",
});

if (listed.success) {
  console.log(listed.data.sessions);
}
```

### Selective Revocation

```ts
await sessions.selectiveRevocation.revokeByRole({
  userId: "user_123",
  role: "admin",
  reason: SessionReasonCode.ROLE_DEPRECATED,
});
```

## Events

When `observability.emitEvents` is enabled, `SessionService` dispatches structured events. Subscribe with `on()` and unsubscribe with `off()`:

```ts
sessions.on("session.created", (payload) => {
  console.log("Session created:", payload.sessionId, payload.userId, payload.timestamp);
});

sessions.on("session.rotated", (payload) => {
  console.log("Session rotated:", payload.oldSessionId, "→", payload.newSessionId);
});

sessions.on("security.rejection", (payload) => {
  console.warn("Security rejection:", payload.reason, payload.sessionId);
});

sessions.off("session.created", listener);
```

### Available Events

| Event                        | Payload                                                                 | Description                                           |
| ---------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------- |
| `session.created`            | `{ sessionId, userId, timestamp }`                                     | Fired after a new session is created.                 |
| `session.rotated`            | `{ oldSessionId, newSessionId, userId, timestamp }`                    | Fired after a session token is rotated.               |
| `session.revoked`            | `{ sessionId, userId, reason, timestamp }`                             | Fired after a session is revoked.                     |
| `session.already_revoked`    | `{ sessionId, userId, timestamp }`                                     | Fired when revoking an already-revoked session.       |
| `session.fallback_fingerprint` | `{ sessionId, userId, deviceContext, timestamp }`                    | Fired when a fallback fingerprint is used.            |
| `sessions.listed`            | `{ userId, status, count, total, timestamp }`                          | Fired after a session list query.                     |
| `security.rejection`         | `{ sessionId, userId, reason, message, affectedSessionIds, expectedIp, actualIp, expectedUserAgent, actualUserAgent, timestamp }` | Fired when a security policy check fails. |
| `security.extractor_failed`  | `{ userId, error, metadata, timestamp }`                               | Fired when device context extraction fails.           |
| `batch.revoked`              | `{ target, timestamp, userId, reason, count, sessionIds, failedSessionIds }` | Fired after a bulk selective revocation completes. |
| `internal_error`             | `{ context, errorClass, category, errorId, timestamp }`                | Fired on unexpected internal errors.                  |

## Session Reason Codes

All `SessionReasonCode` enum values used to tag revocation and rotation reasons:

| Code                         | Value                       | Category           | Description                                       |
| ---------------------------- | --------------------------- | ------------------ | ------------------------------------------------- |
| `MANUAL_LOGOUT`             | `"manual_logout"`           | Normal             | User explicitly logged out.                       |
| `ROTATION`                  | `"rotation"`                | Normal             | Token was rotated (e.g., privilege change).       |
| `IDLE_TIMEOUT`              | `"idle_timeout"`            | Expiration         | Session exceeded inactivity period.               |
| `ABSOLUTE_TIMEOUT`          | `"absolute_timeout"`        | Expiration         | Session exceeded hard lifetime.                   |
| `ROTATION_GRACE_EXPIRED`    | `"rotation_grace_expired"`  | Expiration         | Grace window for in-flight requests expired.      |
| `IP_MISMATCH`               | `"ip_mismatch"`             | Security           | Request IP does not match session IP.             |
| `DEVICE_MISMATCH`           | `"device_mismatch"`         | Security           | Request device does not match session device.     |
| `FINGERPRINT_MISMATCH`      | `"fingerprint_mismatch"`    | Security           | Request fingerprint does not match stored value.  |
| `CSRF_VIOLATION`            | `"csrf_violation"`          | Security           | CSRF token validation failed.                     |
| `SECURITY_BREACH`           | `"security_breach"`         | Security           | Reuse of a rotated token detected.                |
| `ADMIN_REVOKED`             | `"admin_revoked"`           | Administrative     | Administrator revoked the session.                |
| `USER_ALL_SESSIONS_REVOKED` | `"user_all_sessions_revoked"`| Administrative    | All sessions for the user were revoked.           |
| `DEVICE_LOGOUT`             | `"device_logout"`           | Selective          | All sessions on a specific device revoked.        |
| `ROLE_DEPRECATED`           | `"role_deprecated"`         | Selective          | All sessions holding a specific role revoked.     |
| `TIMESTAMP_PURGE`           | `"timestamp_purge"`         | Selective          | All sessions older than a timestamp revoked.      |

## Session Status

`SessionStatus` enum representing the lifecycle stage of a session:

| Status     | Value      | Description                                            |
| ---------- | ---------- | ------------------------------------------------------ |
| `ACTIVE`   | `"active"` | Session is valid and usable.                           |
| `ROTATED`  | `"rotated"`| Session was replaced by a new token (old token is in grace window). |
| `REVOKED`  | `"revoked"`| Session was explicitly revoked.                        |
| `EXPIRED`  | `"expired"`| Session expired (idle or absolute timeout).            |

## Header and Hybrid Transport

### Header Mode

Use `transport.mode: "header"` to send session tokens via HTTP headers instead of cookies:

```ts
const config: SessionLibraryConfig = {
  // ...
  transport: {
    mode: "header",
    header: {
      name: "X-Session-Token",
      scheme: "Bearer",
      responseHeader: "X-New-Session-Token",
    },
  },
};
```

The client sends the token in the `X-Session-Token` header. On rotation, the new token is returned in the `X-New-Session-Token` response header.

### Hybrid Mode

Use `transport.mode: "hybrid"` to accept tokens from both cookies and headers. The cookie is set on creation, but subsequent requests can provide the token via header:

```ts
const config: SessionLibraryConfig = {
  // ...
  transport: {
    mode: "hybrid",
    cookie: {
      name: "session",
      httpOnly: true,
      secure: true,
      sameSite: "lax",
    },
    header: {
      name: "X-Session-Token",
    },
  },
};
```

## Custom Store Adapter

Implement the `SessionStoreAdapter` interface for custom storage backends:

```ts
import { SessionStoreAdapter } from "@restingowlorg/owlsessionguard/storage";
import { SessionRecord, SessionStatus, AdapterListParams, SessionListResult, SessionLimits, SessionReasonCode } from "@restingowlorg/owlsessionguard";

class PostgresStoreAdapter implements SessionStoreAdapter {
  constructor(private readonly pool: Pool) {}

  async create(record: SessionRecord, limits?: SessionLimits): Promise<void> {
    if (limits) {
      const count = await this.countActiveForUser(record.userId);
      if (count >= limits.maxSessionsPerUser) {
        throw new Error("SESSION_LIMIT_EXCEEDED");
      }
    }
    await this.pool.query(
      "INSERT INTO sessions (id, user_id, token_hash, status, roles, scopes, created_at, last_used_at, expires_at, idle_expires_at, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
      [record.id, record.userId, record.tokenHash, record.status, record.roles, record.scopes, record.createdAt, record.lastUsedAt, record.expiresAt, record.idleExpiresAt, JSON.stringify(record.metadata)],
    );
  }

  async rotate(oldId: string, newRecord: SessionRecord, oldUpdates: Partial<SessionRecord>, limits?: SessionLimits, oldRoles?: string[]): Promise<void> {
    // Atomic: update old session status, insert new session
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("UPDATE sessions SET status = $1 WHERE id = $2", [oldUpdates.status, oldId]);
      await this.create(newRecord, limits);
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  }

  async findById(id: string): Promise<SessionRecord | null> {
    const { rows } = await this.pool.query("SELECT * FROM sessions WHERE id = $1", [id]);
    return rows[0] ?? null;
  }

  async findByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    const { rows } = await this.pool.query("SELECT * FROM sessions WHERE token_hash = $1", [tokenHash]);
    return rows[0] ?? null;
  }

  async update(id: string, updates: Partial<SessionRecord>, limits?: SessionLimits): Promise<void> {
    const fields = Object.keys(updates);
    const values = Object.values(updates);
    const setClause = fields.map((f, i) => `${f} = $${i + 2}`).join(", ");
    await this.pool.query(`UPDATE sessions SET ${setClause} WHERE id = $1`, [id, ...values]);
  }

  async delete(id: string): Promise<void> {
    await this.pool.query("DELETE FROM sessions WHERE id = $1", [id]);
  }

  async deleteAllForUser(userId: string): Promise<void> {
    await this.pool.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
  }

  async countActiveForUser(userId: string): Promise<number> {
    const { rows } = await this.pool.query(
      "SELECT COUNT(*)::int as count FROM sessions WHERE user_id = $1 AND status IN ('active', 'rotated')",
      [userId],
    );
    return rows[0].count;
  }

  async findAllForUser(userId: string, params?: AdapterListParams): Promise<SessionListResult> {
    let query = "SELECT * FROM sessions WHERE user_id = $1";
    const values: unknown[] = [userId];
    if (params?.status) {
      query += " AND status = $2";
      values.push(params.status);
    }
    query += " ORDER BY created_at DESC";
    const { rows } = await this.pool.query(query, values);
    return { sessions: rows, total: rows.length, totalIsApproximate: false, nextCursor: null };
  }
}

const store = new PostgresStoreAdapter(pool);
const config: SessionLibraryConfig = {
  // ...
  store: { provider: "custom", custom: { adapter: store } },
};
```

## Response Model

Every public service method returns a discriminated result:

```ts
type SessionOpResult<T> =
  | {
      success: true;
      data: T;
      httpCode: number;
      newToken?: string;
      newCsrfToken?: string;
      clearCsrfToken?: boolean;
    }
  | {
      success: false;
      error: {
        code: string;
        message: string;
        reason?: SessionReasonCode;
      };
      httpCode: number;
      clearCsrfToken?: boolean;
    };
```

## OWASP Alignment

OwlSessionGuard is not an OWASP certification and does not make an application compliant by itself. It implements session controls that map to OWASP guidance:

| Control             | What the library does                                                                                                   | OWASP reference                                                                                                                                              |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Session ID entropy  | Generates 256-bit base64url session tokens with Node.js cryptographic randomness.                                       | [Session ID Entropy](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy)                                  |
| Protect session IDs | Stores token hashes only. Raw tokens are returned to the caller and should be transported in secure cookies or headers. | [Protect Session IDs](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#protect-session-ids)                                |
| Renew session ID    | Provides explicit rotation APIs for privilege changes and sensitive transitions.                                        | [Renew Session ID](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change) |
| Reuse detection     | Detects reuse of rotated tokens and can revoke the affected session tree.                                               | [Detect Session ID Anomalies](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)                                            |
| CSRF tokens         | Uses HMAC-signed CSRF tokens bound to the session ID for mutating methods.                                              | [CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)                                     |

## Security Notes

The calling application remains responsible for:

- Serving all authenticated traffic over HTTPS.
- Authenticating the user before calling `createSession`.
- Setting secure cookie attributes appropriate for the deployment.
- Implementing route-level and resource-level authorization.
- Protecting login, refresh, and session endpoints with rate limits.
- Preventing XSS, since XSS can bypass many browser-side session protections.
- Monitoring emitted events when `observability.emitEvents` is enabled.

## Package Boundary

OwlSessionGuard owns server-side session state: session records, storage adapters, idle and absolute expiration, token rotation, revocation, reuse detection, security binding, and middleware session attachment.

Token signing, JWT verification, and access-token issuance belong in a token-management layer such as OwlTokenGuard or in your application. User authentication belongs in an authentication layer such as owlauth or in your application.

## Community

[![Website](https://img.shields.io/badge/restingowl.com-111827?style=flat-square&logo=googlechrome&logoColor=white)](https://restingowl.com/) [![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/showcase/restingowl/) [![GitHub](https://img.shields.io/badge/Source-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/restingowlorg/OwlSessionGuard) [![Issues](https://img.shields.io/badge/Issues-GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/restingowlorg/OwlSessionGuard/issues) [![Security Policy](https://img.shields.io/badge/Security_Policy-B91C1C?style=flat-square&logo=owasp&logoColor=white)](SECURITY.md) [![Contributing](https://img.shields.io/badge/Contributing-15803D?style=flat-square&logo=git&logoColor=white)](CONTRIBUTING.md)

## License

[MIT License](LICENSE)
