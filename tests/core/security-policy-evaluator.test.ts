import { SecurityPolicyEvaluator } from "../../src/core/security-policy-evaluator";
import { SessionService } from "../../src/core/session.service";
import { MemoryStoreAdapter } from "../../src/storage/adapters/memory.adapter";
import {
  SessionRecord,
  SessionStatus,
  SessionReasonCode,
  SessionLibraryConfig,
} from "../../src/types";

describe("SecurityPolicyEvaluator & Concurrency Sync", () => {
  let evaluator: SecurityPolicyEvaluator;
  let service: SessionService;
  let store: MemoryStoreAdapter;

  const baseConfig: SessionLibraryConfig = {
    env: "test",
    transport: { mode: "header", header: { name: "Authorization" } },
    expiration: {
      idleTimeoutSeconds: 3600,
      absoluteTimeoutSeconds: 86400,
      rolling: true,
    },
    rotation: {
      rotateOnLogin: true,
      rotateOnPrivilegeChange: true,
      gracePeriodSeconds: 300,
    },
    security: {
      enforceTlsInProduction: false,
      ipBinding: "hard",
      fingerprinting: "hard",
      csrf: { enabled: false, mode: "double-submit" },
    },
    limits: { maxSessionsPerUser: 3 },
    store: { provider: "memory" },
    observability: { debug: false, emitEvents: true, metrics: false },
  };

  beforeEach(() => {
    evaluator = new SecurityPolicyEvaluator(baseConfig);
    store = new MemoryStoreAdapter();
    service = new SessionService(store, baseConfig);
  });

  describe("SecurityPolicyEvaluator Pipeline Rules", () => {
    it("should allow active valid sessions", () => {
      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.ACTIVE,
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 100000),
        idleExpiresAt: new Date(Date.now() + 100000),
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(true);
      expect(result.actionRequired).toBe("none");
    });

    it("should reject revoked sessions with correct reason", () => {
      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.REVOKED,
        revocationReason: SessionReasonCode.MANUAL_LOGOUT,
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 100000),
        idleExpiresAt: new Date(Date.now() + 100000),
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.reason).toBe(SessionReasonCode.MANUAL_LOGOUT);
    });

    it("should reject expired sessions", () => {
      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.EXPIRED,
        revocationReason: SessionReasonCode.ABSOLUTE_TIMEOUT,
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 100000),
        idleExpiresAt: new Date(Date.now() + 100000),
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.reason).toBe(SessionReasonCode.ABSOLUTE_TIMEOUT);
    });

    it("should fail validation for absolute timeout", () => {
      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.ACTIVE,
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() - 1000), // Expired absolute
        idleExpiresAt: new Date(Date.now() + 100000),
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.actionRequired).toBe("revoke");
      expect(result.reason).toBe(SessionReasonCode.ABSOLUTE_TIMEOUT);
    });

    it("should fail validation for idle timeout", () => {
      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.ACTIVE,
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 100000),
        idleExpiresAt: new Date(Date.now() - 1000), // Expired idle
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.actionRequired).toBe("revoke");
      expect(result.reason).toBe(SessionReasonCode.IDLE_TIMEOUT);
    });
  });

  describe("HTTP Idempotency and Rotated Session Grace Validation", () => {
    it("should instantly reject state-changing mutations on rotated sessions", () => {
      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.ROTATED,
        revokedAt: new Date(), // Just rotated
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 100000),
        idleExpiresAt: new Date(Date.now() + 100000),
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "POST", // UNSAFE Mutation!
      });

      expect(result.isValid).toBe(false);
      expect(result.actionRequired).toBe("revoke_tree"); // Triggers ARD
      expect(result.reason).toBe(SessionReasonCode.SECURITY_BREACH);
    });

    it("should allow read-only GET requests on rotated sessions within 50ms window", () => {
      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.ROTATED,
        revokedAt: new Date(Date.now() - 20), // 20ms ago (within 50ms)
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 100000),
        idleExpiresAt: new Date(Date.now() + 100000),
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(true);
      expect(result.isWithinGracePeriod).toBe(true);
    });

    it("should reject GET requests on rotated sessions outside the 50ms window", () => {
      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.ROTATED,
        revokedAt: new Date(Date.now() - 100), // 100ms ago (outside 50ms cap)
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 100000),
        idleExpiresAt: new Date(Date.now() + 100000),
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.actionRequired).toBe("revoke_tree"); // Triggers ARD
      expect(result.reason).toBe(SessionReasonCode.SECURITY_BREACH);
    });
  });

  describe("IP and User-Agent Context Binding Options", () => {
    it("should reject IP Mismatch when ipBinding level is 'hard'", () => {
      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.ACTIVE,
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 100000),
        idleExpiresAt: new Date(Date.now() + 100000),
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = evaluator.evaluate(record, {
        ipAddress: "99.99.99.99", // Changed!
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.actionRequired).toBe("revoke");
      expect(result.reason).toBe(SessionReasonCode.IP_MISMATCH);
    });

    it("should allow IP Mismatch with soft warning when ipBinding level is 'soft'", () => {
      const softIpConfig = {
        ...baseConfig,
        security: { ...baseConfig.security, ipBinding: "soft" as const },
      };
      const softEvaluator = new SecurityPolicyEvaluator(softIpConfig);

      const record: SessionRecord = {
        id: "sess-1",
        userId: "user-1",
        tokenHash: "hash-1",
        status: SessionStatus.ACTIVE,
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 100000),
        idleExpiresAt: new Date(Date.now() + 100000),
        roles: [],
        scopes: [],
        metadata: { ipAddress: "192.168.1.1", userAgent: "Mozilla" },
      };

      const result = softEvaluator.evaluate(record, {
        ipAddress: "99.99.99.99", // Mismatch
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(true);
      expect(result.reason).toBe(SessionReasonCode.IP_MISMATCH); // Returns soft reason code for logging
    });
  });

  describe("In-Flight Lock Concurrency Synchronization (Integration)", () => {
    it("should hold concurrent GET requests while rotation lock is active and succeed once released", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });

      expect(createResult.success).toBe(true);
      if (!createResult.success) return;

      const token = createResult.data.token;
      const oldRecordId = createResult.data.record.id;
      const lockKey = `lock:rotate:${oldRecordId}`;

      // Simulate step 1: Rotate starts, acquires store lock
      if (store.acquireLock) {
        await store.acquireLock(lockKey, 500);
      }

      // Transition the parent session record status to ROTATED
      const now = new Date();
      await store.update(oldRecordId, {
        status: SessionStatus.ROTATED,
        revokedAt: now,
        childSessionId: "new-sess-id",
      });

      // Start the concurrent GET validation in the background (should block)
      const validationPromise = service.validateSession({
        token,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla", method: "GET" },
      });

      // Assert validation is currently held (lock is active)
      let resolved = false;
      validationPromise.then(() => {
        resolved = true;
      });

      await new Promise((resolve) => setTimeout(resolve, 15));
      expect(resolved).toBe(false); // Still waiting

      // Release lock (simulate database write completion)
      if (store.releaseLock) {
        await store.releaseLock(lockKey);
      }

      // Wait for execution queue to process suspended promise
      const validationResult = await validationPromise;

      expect(validationResult.success).toBe(true);
      if (validationResult.success) {
        expect(validationResult.data.status).toBe(SessionStatus.ROTATED);
      }
    });

    it("should time out suspended request and return 401 if lock persists >50ms", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });

      if (!createResult.success) return;
      const oldRecordId = createResult.data.record.id;
      const lockKey = `lock:rotate:${oldRecordId}`;

      // Lock session permanently
      if (store.acquireLock) {
        await store.acquireLock(lockKey, 500);
      }

      await store.update(oldRecordId, {
        status: SessionStatus.ROTATED,
        revokedAt: new Date(),
      });

      const validationResult = await service.validateSession({
        token: createResult.data.token,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla", method: "GET" },
      });

      expect(validationResult.success).toBe(false);
      if (!validationResult.success) {
        expect(validationResult.error.message).toContain("Concurrent request timeout");
      }

      if (store.releaseLock) {
        await store.releaseLock(lockKey);
      }
    });
  });

  describe("Automatic Reuse Detection (ARD) Cascading Revocation", () => {
    it("should trigger cascading revocation of descendants on rotated token reuse outside window", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      if (!createResult.success) return;

      // Rotate session: Session A (old) -> Session B (new)
      const rotateResult = await service.rotateSession({
        token: createResult.data.token,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      expect(rotateResult.success).toBe(true);
      if (!rotateResult.success) return;

      const oldRecord = createResult.data.record;
      const activeRecord = rotateResult.data.record;

      // Ensure active record B is currently valid
      const validateActive = await service.validateSession({
        token: rotateResult.data.newToken,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      expect(validateActive.success).toBe(true);

      // Artificially age the revokedAt timestamp of A beyond 50ms limit (e.g. 1 second ago)
      await store.update(oldRecord.id, {
        revokedAt: new Date(Date.now() - 1000),
      });

      // Attacker attempts to reuse old token A
      const reuseResult = await service.validateSession({
        token: createResult.data.token,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla", method: "GET" },
      });

      expect(reuseResult.success).toBe(false);
      if (!reuseResult.success) {
        expect(reuseResult.error.reason).toBe(SessionReasonCode.SECURITY_BREACH);
      }

      // ARD check: Ensure BOTH parent A and child B are now completely revoked in database
      const finalA = await store.findById(oldRecord.id);
      const finalB = await store.findById(activeRecord.id);

      expect(finalA?.status).toBe(SessionStatus.REVOKED);
      expect(finalA?.revocationReason).toBe(SessionReasonCode.SECURITY_BREACH);

      expect(finalB?.status).toBe(SessionStatus.REVOKED);
      expect(finalB?.revocationReason).toBe(SessionReasonCode.SECURITY_BREACH);
    });
  });
});
