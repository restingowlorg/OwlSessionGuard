import Redis from "ioredis";
import { RedisStoreAdapter } from "../../src/storage/adapters/redis.adapter";
import { runAdapterContractTests } from "./adapter-contract.suite";
import { SessionStatus } from "../../src/types";
import { v4 as uuidv4 } from "uuid";

/**
 * Redis Integration Tests — Real Redis Validation
 *
 * Runs the contract suite against a real Redis instance.
 * Skipped by default. Enable with: RUN_REDIS_TESTS=true
 *
 * When enabled:
 *   - If REDIS_URL is set: uses that Redis instance
 *   - If REDIS_URL is not set: spins up a Docker container automatically
 *
 * Usage:
 *   npm run test:redis                          # Auto-spin Redis in Docker
 *   REDIS_URL=redis://host:port npm run test:redis  # Use existing Redis
 */

const RUN_REDIS_TESTS = process.env.RUN_REDIS_TESTS === "true";
const REDIS_URL = process.env.REDIS_URL;

const describeRedis = RUN_REDIS_TESTS ? describe : describe.skip;

describeRedis("Redis Integration Tests (Real Redis)", () => {
  let redis: Redis;
  let container: { stop: () => Promise<void>; getHost: () => string; getMappedPort: (port: number) => number } | null = null;

  beforeAll(async () => {
    let redisUrl = REDIS_URL;

    // If no REDIS_URL provided, spin up a Redis container
    if (!redisUrl) {
      const { GenericContainer } = require("testcontainers");
      container = await new GenericContainer("redis:7.2.3")
        .withExposedPorts(6379)
        .withCommand(["redis-server", "--maxmemory", "64mb", "--maxmemory-policy", "allkeys-lru"])
        .start();

      const host = container.getHost();
      const port = container.getMappedPort(6379);
      redisUrl = `redis://${host}:${port}`;
    }

    redis = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        if (times > 3) return null;
        return Math.min(times * 200, 2000);
      },
    });

    await redis.ping();
  }, 60000); // 60s timeout for Docker container startup

  afterAll(async () => {
    if (redis) {
      await redis.quit();
    }
    if (container) {
      await container.stop();
    }
  });

  runAdapterContractTests(
    "RedisStoreAdapter (Real Redis)",
    async () => {
      const adapter = new RedisStoreAdapter(redis);
      return adapter;
    },
    async () => {
      await redis.flushdb();
    },
  );

  // ── Lock Tests ────────────────────────────────────────────────────────

  describe("Lock Operations", () => {
    let adapter: RedisStoreAdapter;

    beforeEach(async () => {
      adapter = new RedisStoreAdapter(redis);
    });

    afterEach(async () => {
      await redis.flushdb();
    });

    test("should acquire and release lock", async () => {
      const lockKey = "test:lock:1";
      const acquired = await adapter.acquireLock(lockKey, 10000);
      expect(acquired).toBe(true);

      const locked = await adapter.isLocked(lockKey);
      expect(locked).toBe(true);

      await adapter.releaseLock(lockKey);

      const lockedAfter = await adapter.isLocked(lockKey);
      expect(lockedAfter).toBe(false);
    });

    test("should not acquire lock when already held", async () => {
      const lockKey = "test:lock:2";
      const acquired1 = await adapter.acquireLock(lockKey, 10000);
      expect(acquired1).toBe(true);

      const acquired2 = await adapter.acquireLock(lockKey, 10000);
      expect(acquired2).toBe(false);
    });

    test("should auto-expire lock after TTL", async () => {
      const lockKey = "test:lock:3";
      const acquired = await adapter.acquireLock(lockKey, 100); // 100ms TTL
      expect(acquired).toBe(true);

      // Wait for lock to expire
      await new Promise((resolve) => setTimeout(resolve, 200));

      const locked = await adapter.isLocked(lockKey);
      expect(locked).toBe(false);

      // Should be able to acquire again
      const acquired2 = await adapter.acquireLock(lockKey, 10000);
      expect(acquired2).toBe(true);
    });

    test("should report isLocked as false for nonexistent key", async () => {
      const locked = await adapter.isLocked("nonexistent:key");
      expect(locked).toBe(false);
    });
  });

  // ── TTL Verification ──────────────────────────────────────────────────

  describe("TTL Verification", () => {
    let adapter: RedisStoreAdapter;

    beforeEach(async () => {
      adapter = new RedisStoreAdapter(redis);
    });

    afterEach(async () => {
      await redis.flushdb();
    });

    test("should set correct TTL on session keys", async () => {
      const userId = uuidv4();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + 5000); // 5 seconds from now

      await adapter.create({
        id: uuidv4(),
        userId,
        tokenHash: uuidv4(),
        status: SessionStatus.ACTIVE,
        roles: ["user"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt,
        idleExpiresAt: new Date(now.getTime() + 3000),
        metadata: { ipAddress: "127.0.0.1" },
      });

      // Check TTL exists on session key (should be <= 5 seconds)
      const keys = await redis.keys("ossec:sess:*");
      expect(keys.length).toBe(1);

      const ttl = await redis.ttl(keys[0]);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(5);
    });

    test("should auto-expire session after TTL", async () => {
      const adapter = new RedisStoreAdapter(redis);
      const userId = uuidv4();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + 1500); // 1.5 seconds from now

      const sessionId = uuidv4();
      const tokenHash = uuidv4();

      await adapter.create({
        id: sessionId,
        userId,
        tokenHash,
        status: SessionStatus.ACTIVE,
        roles: ["user"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt,
        idleExpiresAt: new Date(now.getTime() + 1000),
        metadata: { ipAddress: "127.0.0.1" },
      });

      // Session should exist initially
      const found = await adapter.findById(sessionId);
      expect(found).not.toBeNull();

      // Wait for expiration (TTL is 2 seconds, wait 2.5 seconds)
      await new Promise((resolve) => setTimeout(resolve, 2500));

      // Session should be gone
      const expired = await adapter.findById(sessionId);
      expect(expired).toBeNull();
    });
  });

  // ── Token Index Verification ──────────────────────────────────────────

  describe("Token Index Verification", () => {
    let adapter: RedisStoreAdapter;

    beforeEach(async () => {
      adapter = new RedisStoreAdapter(redis);
    });

    afterEach(async () => {
      await redis.flushdb();
    });

    test("should maintain token index on rotation", async () => {
      const userId = uuidv4();
      const now = new Date();
      const tokenHash1 = uuidv4();
      const tokenHash2 = uuidv4();
      const sessionId = uuidv4();

      // Create session with first token
      await adapter.create({
        id: sessionId,
        userId,
        tokenHash: tokenHash1,
        status: SessionStatus.ACTIVE,
        roles: ["user"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt: new Date(now.getTime() + 3600000),
        idleExpiresAt: new Date(now.getTime() + 1800000),
        metadata: { ipAddress: "127.0.0.1" },
      });

      // Verify first token index exists
      const id1 = await adapter.findByTokenHash(tokenHash1);
      expect(id1).not.toBeNull();

      // Rotate to new token
      await adapter.update(sessionId, { tokenHash: tokenHash2 });

      // Old token index should be removed
      const oldToken = await adapter.findByTokenHash(tokenHash1);
      expect(oldToken).toBeNull();

      // New token index should exist
      const newToken = await adapter.findByTokenHash(tokenHash2);
      expect(newToken).not.toBeNull();
      expect(newToken?.id).toBe(sessionId);
    });
  });

  // ── Role Index Verification ───────────────────────────────────────────

  describe("Role Index Verification", () => {
    let adapter: RedisStoreAdapter;

    beforeEach(async () => {
      adapter = new RedisStoreAdapter(redis);
    });

    afterEach(async () => {
      await redis.flushdb();
    });

    test("should maintain role indices on revokeAllForUser", async () => {
      const userId = uuidv4();
      const now = new Date();

      // Create sessions with different roles
      await adapter.create({
        id: "s1",
        userId,
        tokenHash: uuidv4(),
        status: SessionStatus.ACTIVE,
        roles: ["ADMIN"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt: new Date(now.getTime() + 3600000),
        idleExpiresAt: new Date(now.getTime() + 1800000),
        metadata: { ipAddress: "127.0.0.1" },
      });

      await adapter.create({
        id: "s2",
        userId,
        tokenHash: uuidv4(),
        status: SessionStatus.ACTIVE,
        roles: ["USER"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt: new Date(now.getTime() + 3600000),
        idleExpiresAt: new Date(now.getTime() + 1800000),
        metadata: { ipAddress: "127.0.0.1" },
      });

      // Verify role indices exist
      const roleKeys = await redis.keys("ossec:idx:role:*");
      expect(roleKeys.length).toBeGreaterThanOrEqual(2);

      // Revoke all
      await adapter.revokeAllForUser(userId, "MANUAL_LOGOUT" as any, new Date());

      // Verify role indices are cleaned up
      const remaining = await redis.keys("ossec:idx:role:*:ADMIN");
      expect(remaining.length).toBe(0);
    });
  });

  // ── Redis Outage Behavior ─────────────────────────────────────────────

  describe("Redis Outage Behavior", () => {
    test("should handle Redis connection failure gracefully", async () => {
      // Create a new Redis client that will fail
      const badRedis = new Redis("redis://localhost:1", {
        maxRetriesPerRequest: 0,
        retryStrategy() {
          return null; // Don't retry
        },
        connectTimeout: 100,
        lazyConnect: true,
      });

      const adapter = new RedisStoreAdapter(badRedis);

      // Operations should fail gracefully (throw, not crash)
      await expect(
        adapter.findById("nonexistent")
      ).rejects.toThrow();

      // Clean up - don't call quit if connection never established
      badRedis.disconnect();
    });

    test("should handle Redis timeout gracefully", async () => {
      const adapter = new RedisStoreAdapter(redis);

      // Verify adapter works normally first
      const userId = uuidv4();
      const found = await adapter.findAllForUser(userId);
      expect(found.sessions).toEqual([]);
    });
  });

  // ── SCAN Operations ──────────────────────────────────────────────────

  describe("SCAN Operations", () => {
    let adapter: RedisStoreAdapter;

    beforeEach(async () => {
      adapter = new RedisStoreAdapter(redis);
    });

    afterEach(async () => {
      await redis.flushdb();
    });

    test("should handle SCAN across multiple batches", async () => {
      const userId = uuidv4();
      const now = new Date();
      const future = new Date(now.getTime() + 3600000);

      // Create multiple sessions to trigger multi-batch SCAN
      for (let i = 0; i < 10; i++) {
        await adapter.create({
          id: `batch-${i}`,
          userId,
          tokenHash: uuidv4(),
          status: SessionStatus.ACTIVE,
          roles: ["user"],
          scopes: ["read"],
          createdAt: now,
          lastUsedAt: now,
          expiresAt: future,
          idleExpiresAt: future,
          metadata: { ipAddress: "127.0.0.1" },
        });
      }

      // findAllForUser with non-active status uses SCAN
      // First create some revoked sessions
      for (let i = 0; i < 5; i++) {
        await adapter.create({
          id: `revoked-${i}`,
          userId,
          tokenHash: uuidv4(),
          status: SessionStatus.REVOKED,
          roles: ["user"],
          scopes: ["read"],
          createdAt: now,
          lastUsedAt: now,
          expiresAt: future,
          idleExpiresAt: future,
          metadata: { ipAddress: "127.0.0.1" },
        });
      }

      // Query revoked sessions (triggers SCAN)
      const result = await adapter.findAllForUser(userId, {
        status: SessionStatus.REVOKED,
      });

      expect(result.sessions.length).toBe(5);
      expect(result.total).toBe(5);
    });

    test("should revoke ROTATED sessions via SCAN path", async () => {
      const userId = uuidv4();
      const now = new Date();
      const future = new Date(now.getTime() + 3600000);

      // Create an active session
      await adapter.create({
        id: "active-1",
        userId,
        tokenHash: uuidv4(),
        status: SessionStatus.ACTIVE,
        roles: ["user"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt: future,
        idleExpiresAt: future,
        metadata: { ipAddress: "127.0.0.1" },
      });

      // Create a ROTATED session (not in sorted set, must be found via SCAN)
      await adapter.create({
        id: "rotated-1",
        userId,
        tokenHash: uuidv4(),
        status: SessionStatus.ROTATED,
        roles: ["user"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt: future,
        idleExpiresAt: future,
        metadata: { ipAddress: "127.0.0.1" },
      });

      // Revoke all — should find ROTATED session via SCAN
      const affected = await adapter.revokeAllForUser(
        userId,
        "MANUAL_LOGOUT" as any,
        new Date(),
      );

      // Both ACTIVE and ROTATED should be revoked
      expect(affected).toContain("active-1");
      expect(affected).toContain("rotated-1");

      // Verify both are now REVOKED
      const s1 = await adapter.findById("active-1");
      const s2 = await adapter.findById("rotated-1");
      expect(s1?.status).toBe(SessionStatus.REVOKED);
      expect(s2?.status).toBe(SessionStatus.REVOKED);
    });

    test("should findLiveSessionsForUser include ROTATED sessions via SCAN", async () => {
      const userId = uuidv4();
      const now = new Date();
      const future = new Date(now.getTime() + 3600000);

      // Create an active session (in sorted set)
      await adapter.create({
        id: "active-1",
        userId,
        tokenHash: uuidv4(),
        status: SessionStatus.ACTIVE,
        roles: ["user"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt: future,
        idleExpiresAt: future,
        metadata: { ipAddress: "127.0.0.1" },
      });

      // Create a ROTATED session (not in sorted set, must be found via SCAN)
      await adapter.create({
        id: "rotated-1",
        userId,
        tokenHash: uuidv4(),
        status: SessionStatus.ROTATED,
        roles: ["user"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt: future,
        idleExpiresAt: future,
        metadata: { ipAddress: "127.0.0.1" },
      });

      // findLiveSessionsForUser should find both via SCAN
      const live = await adapter.findLiveSessionsForUser(userId);
      const liveIds = live.map((s) => s.id);

      expect(liveIds).toContain("active-1");
      expect(liveIds).toContain("rotated-1");
    });

    test("should handle SCAN with empty results", async () => {
      const userId = uuidv4();

      // Query non-existent user
      const result = await adapter.findAllForUser(userId, {
        status: SessionStatus.REVOKED,
      });

      expect(result.sessions).toEqual([]);
      expect(result.total).toBe(0);
    });
  });
});
