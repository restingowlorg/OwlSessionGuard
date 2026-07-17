# OwlSessionGuard

<p align="center">
  <img src="https://raw.githubusercontent.com/restingowlorg/OwlSessionGuard/main/docs/assets/restingowl-logo.png" alt="OwlSessionGuard logo" width="320" />
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
  keyPrefix: "ossec:",
  ttlBufferSeconds: 60,
});
```

The default Redis key prefix is `ossec:` for backward compatibility with existing deployments. Set `keyPrefix` for new deployments if your Redis namespace requires a different prefix.

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

## Configuration Options

| Option                              | Type                                      | Purpose                                                                                                                                            |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `env`                               | `"development" \| "test" \| "production"` | Drives production-only security validation.                                                                                                        |
| `transport.mode`                    | `"cookie" \| "header" \| "hybrid"`        | Selects how session tokens are read and written by middleware.                                                                                     |
| `transport.cookie`                  | `object`                                  | Configures session cookie name, `HttpOnly`, `Secure`, `SameSite`, path, domain, and max age.                                                       |
| `transport.header`                  | `object`                                  | Configures request header name, optional scheme, and response header for rotated tokens.                                                           |
| `expiration.idleTimeoutSeconds`     | `number`                                  | Maximum inactivity period before a session expires.                                                                                                |
| `expiration.absoluteTimeoutSeconds` | `number`                                  | Hard maximum lifetime regardless of activity.                                                                                                      |
| `expiration.rolling`                | `boolean`                                 | Extends idle expiration on successful validation.                                                                                                  |
| `rotation.gracePeriodSeconds`       | `number`                                  | Short retry window for in-flight requests after rotation. Maximum accepted value is 30 seconds.                                                    |
| `security.ipBinding`                | `"off" \| "soft" \| "hard"`               | Compares request IP address to the stored session IP.                                                                                              |
| `security.fingerprinting`           | `"off" \| "soft" \| "hard"`               | Compares request device fingerprint to the stored session fingerprint.                                                                             |
| `security.csrf`                     | `object`                                  | Enables or disables HMAC-signed CSRF tokens bound to the session ID.                                                                               |
| `device.enabled`                    | `boolean`                                 | Enables persistent device-cookie extraction for fingerprint checks.                                                                                |
| `limits.maxSessionsPerUser`         | `number`                                  | Maximum active sessions per user.                                                                                                                  |
| `limits.maxSessionsPerRole`         | `Record<string, number>`                  | Optional role-specific active-session limits.                                                                                                      |
| `store.provider`                    | `"memory" \| "redis" \| "custom"`         | Declares the configured storage backend. MongoDB and PostgreSQL are reserved config values; built-in adapters currently ship for memory and Redis. |
| `observability.emitEvents`          | `boolean`                                 | Enables structured event listener dispatch.                                                                                                        |

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
