# owl-session-guard

<p align="center">
  <img src="docs/assets/restingowl-logo.png" alt="owl-session-guard logo" width="320" />
</p>

---

[![npm package](https://img.shields.io/badge/npm-%40restingowlorg%2Fowl--session--guard-CB3837?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@restingowlorg/owl-session-guard) [![Node.js](<https://img.shields.io/badge/node-%3E%3D18-339933?style=flat-square&logo=node.js&logoColor=white>)](https://www.npmjs.com/package/@restingowlorg/owl-session-guard) [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Open-source OWASP-aligned session management and security middleware for Node.js.

owl-session-guard, published as `@restingowlorg/owl-session-guard`, gives your Node.js app secure session state, automatic token rotation, concurrent reuse detection, and framework adapters. It provides robust session handling, security binding, and works out of the box with memory and Redis stores.

- **Package:** `@restingowlorg/owl-session-guard`
- **Latest stable tag:** `latest`
- **Prerelease tag:** `next`
- **Install:** `npm install @restingowlorg/owl-session-guard`
- **Developer guide:** [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)

## What You Get

- **Framework Agnostic**: Native middleware for Express, Fastify, and NestJS, or roll your own.
- **Database Agnostic**: Pluggable storage adapters (Memory, Redis) with atomic lock synchronization.
- **Secure Token Sessions**: Uses CSPRNG-generated tokens (256-bit entropy) and strictly hashes tokens at rest.
- **Automatic Reuse Detection (ARD)**: Tree-based cascading revocation automatically destroys session lines if a hijacked rotated token is reused.
- **Security Binding**: Context-aware evaluations enforcing strict or soft IP and fingerprint binding.
- **Lifecycle Management**: Built-in state machine guarding valid transitions (active, rotated, revoked).
- **Idle & Absolute Expiration**: Support for sliding (rolling) idle timeouts and hard absolute limits.
- **Concurrent Session Limits**: Configurable max-active sessions per user, evaluated globally and per-role.
- **CSRF Protection**: Native cryptographic signed-token generation and validation tied explicitly to the session ID.

## Support Matrix

| Area          | Current Support          |
| ------------- | ------------------------ |
| Runtime       | Node.js 18+              |
| Language      | TypeScript, JavaScript   |
| Module output | CommonJS                 |
| Frameworks    | Express, Fastify, NestJS |
| Storage       | In-Memory, Redis         |

## Installation

```bash
npm install @restingowlorg/owl-session-guard
```

## Core Usage

### Initialization

```typescript
import { SessionService } from "@restingowlorg/owl-session-guard";
import { MemoryStoreAdapter } from "@restingowlorg/owl-session-guard/storage/memory";

const store = new MemoryStoreAdapter();
const config = {
  env: "production",
  expiration: {
    idleTimeoutSeconds: 3600,
    absoluteTimeoutSeconds: 86400,
    rolling: true,
  },
  security: {
    ipBinding: "hard",
    csrf: {
      enabled: true,
      secret: "super-secret-key-at-least-32-chars",
    }
  },
  limits: {
    maxSessionsPerUser: 5,
  },
  observability: { emitEvents: true }
};

const sessionService = new SessionService(store, config);
```

### Create Session

```typescript
const result = await sessionService.createSession({
  userId: "user_uuid_123",
  roles: ["admin"],
  scopes: ["read", "write"],
  metadata: {
    ipAddress: "192.168.1.1",
    userAgent: "Mozilla/5.0...",
  },
});

if (result.success) {
  const { token, record } = result.data;
  // Send token to client (e.g., via HttpOnly Secure Cookie)
}
```

### Validate Session

```typescript
const result = await sessionService.validateSession({
  token: requestToken,
  csrfToken: requestCsrfToken, // If CSRF enabled
  context: {
    ipAddress: requestIp,
    method: "POST", // Method drives CSRF normalization
  },
});

if (result.success) {
  const session = result.data;
}
```

### Rotate Session

```typescript
const result = await sessionService.rotateSession({
  token: oldToken,
  context: {
    ipAddress: requestIp,
  },
});
```

### Revoke Session

```typescript
await sessionService.revokeSession({ sessionId: "session_id_here", reason: "USER_LOGOUT" });
```

### Revoke All Sessions for User

```typescript
await sessionService.revokeAllSessionsForUser("user_uuid_123", "SECURITY_BREACH");
```

### List User Sessions

```typescript
const sessionsResult = await sessionService.listUserSessions("user_uuid_123", { limit: 10 });
```

### Selective Revocation

```typescript
// Use the selective revocation engine for targeted session killing
await sessionService.selectiveRevocation.revokeByQuery("user_uuid_123", {
  reason: "SECURITY_BREACH",
  deviceFingerprint: "fp_xyz",
});
```

## Configuration Options

| Option | Type | Purpose |
| ------ | ---- | ------- |
| `env` | `"development" \| "production"` | Disables strict checks (like secure cookies) in development. |
| `expiration.idleTimeoutSeconds` | `number` | Maximum time a session can remain inactive before expiring. |
| `expiration.absoluteTimeoutSeconds` | `number` | Hard limit on session lifetime, regardless of activity. |
| `expiration.rolling` | `boolean` | If true, idle expiration is reset on every validation. |
| `security.ipBinding` | `"none" \| "soft" \| "hard"` | Enforces IP pinning. `hard` rejects mismatches, `soft` just warns. |
| `security.csrf.enabled` | `boolean` | Enables the built-in signed CSRF token architecture. |
| `limits.maxSessionsPerUser` | `number` | Global cap on active concurrent sessions per user. |
| `observability.emitEvents` | `boolean` | Enables structured telemetry via event listeners. |

## Middleware Examples

### Express

Peer dependencies: `express`

```typescript
import { createExpressMiddleware, requireSession } from "@restingowlorg/owl-session-guard/express";
import express from "express";

const app = express();

// Global middleware
app.use(createExpressMiddleware(sessionService, {
  cookieName: "session_token",
  csrfHeaderName: "x-csrf-token",
}));

// Protected route
app.get("/protected", requireSession(), (req, res) => {
  res.json({ session: req.session });
});
```

### Fastify

Peer dependencies: `fastify`

```typescript
import { fastifySessionPlugin, fastifyRequireSession } from "@restingowlorg/owl-session-guard/fastify";
import fastify from "fastify";

const app = fastify();

app.register(fastifySessionPlugin, {
  sessionService,
  cookieName: "session_token",
  csrfHeaderName: "x-csrf-token",
});

app.get("/protected", { preHandler: [fastifyRequireSession()] }, async (request, reply) => {
  return { session: request.session };
});
```

### NestJS

Peer dependencies: `@nestjs/common`, `@nestjs/core`, `rxjs`

```typescript
import { SessionGuard, RequireRoles } from "@restingowlorg/owl-session-guard/nestjs";
import { Controller, Get, UseGuards } from "@nestjs/common";

@Controller("protected")
@UseGuards(SessionGuard)
export class ProtectedController {
  @Get()
  @RequireRoles("admin")
  getProtectedData() {
    return { message: "Hello Admin" };
  }
}
```

## Role-Limit Semantics

- **Exact Matching**: Session limits evaluate exactly matched roles.
- **Multiple Roles**: If a user is assigned multiple roles, limits are verified against each distinct role configuration.
- **Global Caps**: A global `maxSessionsPerUser` cap operates as a fallback or ceiling limit regardless of role specifics.
- **Privilege-Change Rotation**: Sessions must be rotated explicitly whenever user privileges (roles or scopes) change to re-evaluate limits and security policies.

## CSRF Protection

When CSRF protection is enabled, the library uses a **Signed-Token** architecture. The CSRF token is cryptographically bound to the session ID via HMAC and validated.
**Method Normalization**: Safe HTTP methods (`GET`, `HEAD`, `OPTIONS`) bypass CSRF checks, while mutating methods (`POST`, `PUT`, `DELETE`, `PATCH`) are normalized and strictly require the correct CSRF token to pass the validation gate.

## OWASP Alignment

Here's exactly what owl-session-guard does, and where each decision comes from. Every control is traced back to the [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

| Control | What the library does | OWASP reference |
| ------- | --------------------- | --------------- |
| CSPRNG Tokens | 256-bit base64url encoded tokens from Node's crypto RNG. | [Session ID Entropy](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy) |
| Hash-only Storage | Only token hashes are stored in the database. Raw tokens are never persisted. | [Protect Session IDs](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#protect-session-ids) |
| Automatic Reuse Detection | If a rotated session token is reused, the entire session tree is instantly revoked. | [Detect Session Hijacking](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#detect-session-hijacking) |
| Token Rotation | Transparent rotation APIs for privilege boundary crossing. | [Rotate Session ID](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change) |
| CSRF Token Binding | HMAC signed tokens bound to the specific session ID. | [CSRF Synchronizer Token](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern) |

## Security Notes

The table above covers what this library actually does. It's **not** an OWASP certification, and it won't make your app ASVS-compliant on its own. You still need to handle:

- TLS and secure transport (cookies must be Secure and HttpOnly)
- Proper user authentication before session creation
- Cross-Site Scripting (XSS) defenses
- Route-level authorization and role enforcement

## Known Caller Responsibilities

The `SessionService` handles session state, concurrency, and validation, but the calling application MUST provide:

1. **TLS**: Ensure all traffic is sent over HTTPS.
2. **Authentication**: Verify user credentials before calling `createSession`.
3. **Authorization**: Implement route-level and resource-level access control beyond basic session active status.
4. **Rate Limiting**: Protect endpoints from brute-force or DoS attacks.
5. **Deployment Hardening**: Secure cookies (`HttpOnly`, `Secure`, `SameSite`) and properly sanitize inputs.
6. **Monitoring**: Ingest emitted telemetry events (`observability.emitEvents`) to detect anomalies.

## Community

[![Website](https://img.shields.io/badge/restingowl.com-111827?style=flat-square&logo=googlechrome&logoColor=white)](https://restingowl.com/) [![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/showcase/restingowl/) [![GitHub](https://img.shields.io/badge/Source-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/restingowlorg/OwlSessionGuard) [![Issues](https://img.shields.io/badge/Issues-GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/restingowlorg/OwlSessionGuard/issues) [![Security Policy](https://img.shields.io/badge/Security_Policy-B91C1C?style=flat-square&logo=owasp&logoColor=white)](SECURITY.md) [![Contributing](https://img.shields.io/badge/Contributing-15803D?style=flat-square&logo=git&logoColor=white)](CONTRIBUTING.md)

## License

[MIT License](LICENSE)
