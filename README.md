
---

# 🛡️ MVP Session

**MVP Session** is a **framework-agnostic**, **database-agnostic** Node.js **session management library**, designed to comply with **OWASP ASVS v7 Session Management** requirements.

It **does not perform authentication**.
It **only manages sessions** after a user has been authenticated.

---

## What This Library Does

✅ Secure session creation
✅ Token validation with idle expiration
✅ Optional token rotation (consumer-controlled)
✅ Session revocation (logout / security events)
✅ Max concurrent sessions per user
✅ Database-backed, revocable sessions
✅ Strong typing with structured results
✅ Framework-agnostic (Express, NestJS, Fastify, etc.)

---

## ❌ What This Library Does NOT Do

🚫 No login / signup
🚫 No password handling
🚫 No cookies automatically set
🚫 No forced token rotation
🚫 No HTTP framework assumptions

> **Authentication and sessions are intentionally decoupled.**

---

## Installation

```bash
npm install @restingowlorg/mvp-session
```

---

## Database Support

* PostgreSQL
* MongoDB

### Environment Variables

```env
POSTGRES_URI=postgres://user:pass@localhost:5432/app
MONGO_URI=mongodb://localhost:27017/app
```

---

## Initialization

### PostgreSQL

```ts
import { SessionManager } from "@restingowlorg/mvp-session";

const sessionManager = await SessionManager.init({
  dbType: "postgres",
  postgresUrl: process.env.POSTGRES_URI!,
  sessionTtlSeconds: 60 * 60 * 24 * 7, // 7 days
  idleTtlSeconds: 60 * 15,             // 15 minutes
  maxSessionsPerUser: 3,
});
```

### MongoDB

```ts
const sessionManager = await SessionManager.init({
  dbType: "mongo",
  mongoUri: process.env.MONGO_URI!,
  sessionTtlSeconds: 60 * 60 * 24 * 7,
  idleTtlSeconds: 60 * 15,
  maxSessionsPerUser: 3,
});
```

---

## Core API

### `create(userId)`

Creates a new session for an already-authenticated user.

```ts
const result = await sessionManager.create(userId);

if (result.success) {
  console.log(result.data.sessionToken);
}
```

✔ Enforces max concurrent sessions
✔ Returns a **raw session token** (store securely)

---

### `validate(token)`

Validates a session token and updates `lastUsedAt`.

```ts
const result = await sessionManager.validate(token);

if (!result.success) {
  // session expired / revoked / invalid
}
```

✔ Enforces idle expiration
✔ Does NOT rotate token automatically

---

### `rotate(token)`

Explicitly rotate a session token.

```ts
const rotated = await sessionManager.rotate(token);

res.cookie("SESSION", rotated.data.sessionToken, {
  httpOnly: true,
  secure: true,
});
```

✔ Old token is revoked
✔ New token returned
✔ Consumer controls **when** rotation happens

---

### `revoke(token)`

Explicitly revoke a session (logout, password change, security event).

```ts
await sessionManager.revoke(token);
```

✔ Immediate invalidation
✔ Required for logout flows

---

## Express Example

```ts
app.post("/login", async (req, res) => {
  const session = await sessionManager.create(user.id);

  res.cookie("SESSION", session.data.sessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  });

  res.json({ success: true });
});
```

---

## Session Validation Middleware (Express)

```ts
async function requireSession(req, res, next) {
  const token = req.cookies?.SESSION;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  const result = await sessionManager.validate(token);
  if (!result.success) return res.status(401).json(result);

  req.session = result.data;
  next();
}
```

---

## OWASP ASVS v7 Compliance

✔ Unique session identifiers
✔ Server-side session state
✔ Idle timeout enforcement
✔ Absolute expiration support
✔ Explicit logout invalidation
✔ Session revocation on reuse
✔ Concurrent session limits
✔ Token rotation supported (not forced)

> Token rotation is **consumer-controlled** to avoid unnecessary DB writes.

---

## Recommended Rotation Strategy

| Event                | Rotate?         |
| -------------------- | --------------- |
| Login                | ❌ (new session) |
| Every request        | ❌               |
| Privilege escalation | ✅               |
| Password change      | ✅               |
| Sensitive action     | ✅               |
| Suspected compromise | ✅               |

---

## Security Best Practices

* Always use **HTTPS**
* Store tokens in **HTTP-only cookies**
* Rotate tokens on **high-risk actions**
* Revoke all sessions on password reset
* Keep idle TTL short (10–30 mins)
* Limit concurrent sessions

---

## Session Result Type

```ts
export interface SessionResult<T = any> {
  success: boolean;
  data: T | null;
  httpCode: number;
  message: string;
}
```

> Tokens and identifiers are never logged or leaked.

---
