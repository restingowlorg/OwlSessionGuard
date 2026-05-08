# Owl Session Management Library

A framework-agnostic and database-agnostic session management library for Node.js applications. It provides robust session handling, security binding, and token rotation features.

## Features

- Framework Agnostic: Works with Express, Fastify, NestJS, or any other Node.js framework.
- Database Agnostic: Pluggable storage adapters (Memory, Redis, MongoDB, etc.).
- Secure Token Sessions: Uses CSPRNG-generated tokens (256-bit entropy).
- Token Rotation: Automatic or manual token rotation to prevent session hijacking.
- Security Binding: Optional IP address and fingerprint binding.
- Lifecycle Management: Built-in state machine for active, rotated, revoked, and expired states.
- Idle Expiration: Support for sliding (rolling) and absolute session timeouts.
- Concurrent Session Limits: Enforce maximum active sessions per user.

## Installation

```bash
npm install @restingowlorg/owl-session
```

## Core Components

### SessionService

The `SessionService` is the primary entry point for managing sessions. It handles creation, validation, rotation, and revocation.

### SessionStoreAdapter

The library uses a pluggable storage system. You can use the built-in `MemoryStoreAdapter` or implement your own by following the `SessionStoreAdapter` interface.

## Usage

### Initialization

```typescript
import { SessionService } from "@restingowlorg/owl-session";
import { MemoryStoreAdapter } from "@restingowlorg/owl-session/storage";

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
  },
  limits: {
    maxSessionsPerUser: 5,
  },
  // ... other configuration
};

const sessionService = new SessionService(store, config);
```

### Creating a Session

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
  // Send token to client (e.g., via Set-Cookie)
}
```

### Validating a Session

```typescript
const result = await sessionService.validateSession({
  token: requestToken,
  context: {
    ipAddress: requestIp,
  },
});

if (result.success) {
  const session = result.data;
  console.log(`User ID: ${session.userId}`);
}
```

### Rotating a Session

```typescript
const result = await sessionService.rotateSession({
  token: oldToken,
  context: {
    ipAddress: requestIp,
  },
});

if (result.success) {
  const { newToken, record } = result.data;
  // Update client with the new token
}
```

## Security Best Practices

1. Use HTTPS: Always serve your application over TLS.
2. Secure Cookies: Use `HttpOnly`, `Secure`, and `SameSite` flags for cookies.
3. IP Binding: Enable `hard` IP binding if your application requires strict security.
4. Token Rotation: Rotate tokens frequently, especially after privilege changes.
5. Absolute Timeout: Always set an absolute timeout to limit the maximum life of a session.

## Testing

Run the unit tests using:

```bash
npm test
```

## License

MIT
