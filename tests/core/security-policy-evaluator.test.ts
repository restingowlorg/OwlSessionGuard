import { SecurityPolicyEvaluator } from "../../src/core/security-policy-evaluator";
import { SessionService } from "../../src/core/session.service";
import { MemoryStoreAdapter } from "../../src/storage/adapters/memory.adapter";
import {
  SessionRecord,
  SessionStatus,
  SessionReasonCode,
  SessionLibraryConfig,
  DeviceOS,
  DeviceBrowser,
  DeviceType,
} from "../../src/types";

/**
 * WHY: SessionRecord.metadata requires ResolvedDeviceContext (non-partial) because
 * every real record produced by SessionService will always have deviceFingerprint and
 * deviceContext set. Tests that do not exercise fingerprinting should use this factory
 * to satisfy the type contract without cluttering the test body with irrelevant fields.
 */
const createBaseRecord = (
  overrides: Partial<Omit<SessionRecord, "metadata">> & {
    metadata?: Partial<SessionRecord["metadata"]>;
  } = {},
): SessionRecord => {
  const { metadata: metadataOverride = {}, ...recordOverrides } = overrides;
  return {
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
    metadata: {
      ipAddress: "192.168.1.1",
      userAgent: "Mozilla",
      // WHY: Default to a fallback_ prefixed fingerprint so that fingerprint-unaware
      // tests automatically bypass Step 6B enforcement (which only runs on persistent FPs).
      // Tests that specifically exercise fingerprint enforcement must override this with
      // a persistent FP (e.g. "persistent_fp_abc") via the metadata override.
      deviceFingerprint: "fallback_test-sentinel",
      deviceContext: { os: DeviceOS.UNKNOWN, browser: DeviceBrowser.UNKNOWN, type: DeviceType.DESKTOP },
      ...metadataOverride,
    },
    ...recordOverrides,
  };
};


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
      csrf: { enabled: false },
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
      const record: SessionRecord = createBaseRecord();

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(true);
      expect(result.actionRequired).toBe("none");
    });

    it("should reject revoked sessions with correct reason", () => {
      const record: SessionRecord = createBaseRecord({
        status: SessionStatus.REVOKED,
        revocationReason: SessionReasonCode.MANUAL_LOGOUT,
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.reason).toBe(SessionReasonCode.MANUAL_LOGOUT);
    });

    it("should reject expired sessions", () => {
      const record: SessionRecord = createBaseRecord({
        status: SessionStatus.EXPIRED,
        revocationReason: SessionReasonCode.ABSOLUTE_TIMEOUT,
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.reason).toBe(SessionReasonCode.ABSOLUTE_TIMEOUT);
    });

    it("should fail validation for absolute timeout", () => {
      const record: SessionRecord = createBaseRecord({
        expiresAt: new Date(Date.now() - 1000), // Expired absolute
      });

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
      const record: SessionRecord = createBaseRecord({
        idleExpiresAt: new Date(Date.now() - 1000), // Expired idle
      });

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
      const record: SessionRecord = createBaseRecord({
        status: SessionStatus.ROTATED,
        revokedAt: new Date(1000), // Just rotated
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "POST", // UNSAFE Mutation!
      }, new Date(1005)); // 5ms after revokedAt

      expect(result.isValid).toBe(false);
      expect(result.actionRequired).toBe("revoke_tree"); // Triggers ARD
      expect(result.reason).toBe(SessionReasonCode.SECURITY_BREACH);
    });

    it("should allow read-only GET requests on rotated sessions within 50ms window", () => {
      const frozenNow = new Date(1000);
      const record: SessionRecord = createBaseRecord({
        status: SessionStatus.ROTATED,
        revokedAt: new Date(980), // 20ms before frozenNow (within 50ms)
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      }, frozenNow);

      expect(result.isValid).toBe(true);
      expect(result.isWithinGracePeriod).toBe(true);
    });

    it("should reject GET requests on rotated sessions outside the 50ms window", () => {
      const frozenNow = new Date(1000);
      const record: SessionRecord = createBaseRecord({
        status: SessionStatus.ROTATED,
        revokedAt: new Date(800), // 200ms before frozenNow (outside 50ms cap)
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        method: "GET",
      }, frozenNow);

      expect(result.isValid).toBe(false);
      expect(result.actionRequired).toBe("revoke_tree"); // Triggers ARD
      expect(result.reason).toBe(SessionReasonCode.SECURITY_BREACH);
    });
  });

  describe("IP and User-Agent Context Binding Options", () => {
    it("should reject IP Mismatch when ipBinding level is 'hard'", () => {
      const record: SessionRecord = createBaseRecord();

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

      const record: SessionRecord = createBaseRecord();

      const result = softEvaluator.evaluate(record, {
        ipAddress: "99.99.99.99", // Mismatch
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(true);
      expect(result.softWarning).toBe(true);
      expect(result.reason).toBeUndefined();
      expect(result.message).toBeUndefined();
    });

    it("should reject Device Fingerprint Mismatch when fingerprinting level is 'hard'", () => {
      const record: SessionRecord = createBaseRecord({
        metadata: { deviceFingerprint: "persistent_fp_abc" },
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        deviceFingerprint: "hacker_fp_xyz", // Mismatch!
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.actionRequired).toBe("revoke");
      expect(result.reason).toBe(SessionReasonCode.DEVICE_MISMATCH);
    });

    it("should allow Device Fingerprint Mismatch with soft warning when fingerprinting level is 'soft'", () => {
      const softFpConfig = {
        ...baseConfig,
        security: { ...baseConfig.security, fingerprinting: "soft" as const },
      };
      const softEvaluator = new SecurityPolicyEvaluator(softFpConfig);

      const record: SessionRecord = createBaseRecord({
        metadata: { deviceFingerprint: "persistent_fp_abc" },
      });

      const result = softEvaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        deviceFingerprint: "hacker_fp_xyz", // Mismatch
        method: "GET",
      });

      expect(result.isValid).toBe(true);
      expect(result.softWarning).toBe(true);
      expect(result.reason).toBeUndefined();
      expect(result.message).toBeUndefined();
    });

    it("should ignore Device Fingerprint check if the stored fingerprint starts with 'fallback_'", () => {
      const record: SessionRecord = createBaseRecord({
        metadata: { deviceFingerprint: "fallback_uuid123" },
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        deviceFingerprint: "hacker_fp_xyz", // Mismatch, but bypassed due to fallback prefix
        method: "GET",
      });

      expect(result.isValid).toBe(true);
    });
  });

  describe("CSRF Validation Enforcement", () => {
    it("should allow state-changing request if CSRF token matches", () => {
      const csrfConfig = {
        ...baseConfig,
        // WHY: fingerprinting: "off" isolates CSRF validation. Tests that call evaluate()
        // without a deviceFingerprint context would be blocked by Step 6B before reaching CSRF.
        security: { ...baseConfig.security, fingerprinting: "off" as const, csrf: { enabled: true } },
      };
      const csrfEvaluator = new SecurityPolicyEvaluator(csrfConfig);

      const record: SessionRecord = createBaseRecord({ csrfToken: "super-secret-csrf-token" });

      const result = csrfEvaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        method: "POST",
        csrfToken: "super-secret-csrf-token", // Matches!
      });

      expect(result.isValid).toBe(true);
    });

    it("should reject state-changing request if CSRF token is missing", () => {
      const csrfConfig = {
        ...baseConfig,
        security: { ...baseConfig.security, fingerprinting: "off" as const, csrf: { enabled: true } },
      };
      const csrfEvaluator = new SecurityPolicyEvaluator(csrfConfig);

      const record: SessionRecord = createBaseRecord({ csrfToken: "super-secret-csrf-token" });

      const result = csrfEvaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        method: "DELETE",
        // No csrfToken provided
      });

      expect(result.isValid).toBe(false);
      expect(result.reason).toBe(SessionReasonCode.CSRF_VIOLATION);
    });

    it("should reject state-changing request if CSRF token mismatches", () => {
      const csrfConfig = {
        ...baseConfig,
        security: { ...baseConfig.security, fingerprinting: "off" as const, csrf: { enabled: true } },
      };
      const csrfEvaluator = new SecurityPolicyEvaluator(csrfConfig);

      const record: SessionRecord = createBaseRecord({ csrfToken: "super-secret-csrf-token" });

      const result = csrfEvaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        method: "PUT",
        csrfToken: "hacker-token", // Mismatch
      });

      expect(result.isValid).toBe(false);
      expect(result.reason).toBe(SessionReasonCode.CSRF_VIOLATION);
    });

    it("should ignore CSRF for non-state-changing GET requests even if token is missing", () => {
      const csrfConfig = {
        ...baseConfig,
        security: { ...baseConfig.security, fingerprinting: "off" as const, csrf: { enabled: true } },
      };
      const csrfEvaluator = new SecurityPolicyEvaluator(csrfConfig);

      const record: SessionRecord = createBaseRecord({ csrfToken: "super-secret-csrf-token" });

      const result = csrfEvaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        method: "GET", // Safe method
      });

      expect(result.isValid).toBe(true);
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

      expect(createResult.success).toBe(true);
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

    it("should allow concurrent read-only GET requests on a rotated session within overlapping grace periods", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      expect(createResult.success).toBe(true);
      if (!createResult.success) return;

      const rotateResult = await service.rotateSession({
        token: createResult.data.token,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      expect(rotateResult.success).toBe(true);
      if (!rotateResult.success) return;

      // The old token is now ROTATED but within the 50ms grace period.
      // Launch 5 concurrent read requests with the OLD token
      const promises = Array.from({ length: 5 }).map(() =>
        service.validateSession({
          token: createResult.data.token,
          context: { ipAddress: "127.0.0.1", userAgent: "Mozilla", method: "GET" },
        }),
      );

      const results = await Promise.all(promises);

      // All of them should succeed and return the old session record seamlessly due to overlapping grace
      for (const result of results) {
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.status).toBe(SessionStatus.ROTATED);
        }
      }
    });
  });

  describe("Automatic Reuse Detection (ARD) Cascading Revocation", () => {
    it("should trigger cascading revocation of descendants on rotated token reuse outside window", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      expect(createResult.success).toBe(true);
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

    it("should trigger ARD tree revocation with deeply nested session hierarchies", async () => {
      // Create Session A
      const createA = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      expect(createA.success).toBe(true);
      if (!createA.success) return;

      // Rotate A -> B
      const rotateB = await service.rotateSession({
        token: createA.data.token,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      expect(rotateB.success).toBe(true);
      if (!rotateB.success) return;

      // Rotate B -> C
      const rotateC = await service.rotateSession({
        token: rotateB.data.newToken,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      expect(rotateC.success).toBe(true);
      if (!rotateC.success) return;

      // Rotate C -> D
      const rotateD = await service.rotateSession({
        token: rotateC.data.newToken,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla" },
      });
      expect(rotateD.success).toBe(true);
      if (!rotateD.success) return;

      // Artificially age the revokedAt timestamp of A beyond 50ms limit (e.g. 1 second ago)
      await store.update(createA.data.record.id, {
        revokedAt: new Date(Date.now() - 1000),
      });

      // Attacker attempts to reuse old token A
      const reuseResult = await service.validateSession({
        token: createA.data.token,
        context: { ipAddress: "127.0.0.1", userAgent: "Mozilla", method: "GET" },
      });

      expect(reuseResult.success).toBe(false);

      // Verify all sessions in the hierarchy are recursively revoked
      const finalA = await store.findById(createA.data.record.id);
      const finalB = await store.findById(rotateB.data.record.id);
      const finalC = await store.findById(rotateC.data.record.id);
      const finalD = await store.findById(rotateD.data.record.id);

      expect(finalA?.status).toBe(SessionStatus.REVOKED);
      expect(finalB?.status).toBe(SessionStatus.REVOKED);
      expect(finalC?.status).toBe(SessionStatus.REVOKED);
      expect(finalD?.status).toBe(SessionStatus.REVOKED);
      
      expect(finalD?.revocationReason).toBe(SessionReasonCode.SECURITY_BREACH);
    });
  });

  describe("Sensitive Data Redaction in Messages", () => {
    it("should hash fingerprint in hard-mode fingerprint mismatch message", () => {
      const record: SessionRecord = createBaseRecord({
        metadata: { deviceFingerprint: "secret_raw_fingerprint_abc123" },
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        deviceFingerprint: "different_fingerprint_xyz789",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.message).toBeDefined();
      // Message must NOT contain the raw fingerprint
      expect(result.message).not.toContain("secret_raw_fingerprint_abc123");
      expect(result.message).not.toContain("different_fingerprint_xyz789");
      // Message should contain truncated hashes (16 chars hex)
      expect(result.message).toMatch(/Expected: [a-f0-9]{16}/);
      expect(result.message).toMatch(/Actual: [a-f0-9]{16}/);
    });

    it("should mask IP in hard-mode IP mismatch message", () => {
      const record: SessionRecord = createBaseRecord();

      const result = evaluator.evaluate(record, {
        ipAddress: "10.20.30.40",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.message).toBeDefined();
      // Message must NOT contain the raw actual IP
      expect(result.message).not.toContain("10.20.30.40");
      // Message should contain masked IPs (last octet replaced with x)
      expect(result.message).toContain("192.168.1.x");
      expect(result.message).toContain("10.20.30.x");
    });

    it("should NOT expose raw values in soft-mode IP mismatch result", () => {
      const softIpConfig = {
        ...baseConfig,
        security: { ...baseConfig.security, ipBinding: "soft" as const },
      };
      const softEvaluator = new SecurityPolicyEvaluator(softIpConfig);

      const record: SessionRecord = createBaseRecord();

      const result = softEvaluator.evaluate(record, {
        ipAddress: "10.20.30.40",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(true);
      expect(result.softWarning).toBe(true);
      expect(result.reason).toBeUndefined();
      expect(result.message).toBeUndefined();
    });

    it("should NOT expose raw values in soft-mode fingerprint mismatch result", () => {
      const softFpConfig = {
        ...baseConfig,
        security: { ...baseConfig.security, fingerprinting: "soft" as const },
      };
      const softEvaluator = new SecurityPolicyEvaluator(softFpConfig);

      const record: SessionRecord = createBaseRecord({
        metadata: { deviceFingerprint: "secret_stored_fp" },
      });

      const result = softEvaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        deviceFingerprint: "attacker_fp",
        method: "GET",
      });

      expect(result.isValid).toBe(true);
      expect(result.softWarning).toBe(true);
      expect(result.reason).toBeUndefined();
      expect(result.message).toBeUndefined();
    });
  });

  describe("Adversarial Edge Cases — Redaction Helpers", () => {
    it("should handle empty fingerprint string in hashFingerprint", () => {
      const record: SessionRecord = createBaseRecord({
        metadata: { deviceFingerprint: "" }, // empty
      });

      // Should not throw — empty string is falsy, bypasses fingerprint check
      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        deviceFingerprint: "any_value",
        method: "GET",
      });

      expect(result.isValid).toBe(true);
    });

    it("should handle IPv6-style IP in maskIp (no masking, returned as-is)", () => {
      const record: SessionRecord = createBaseRecord({
        metadata: { ipAddress: "::1" },
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "10.0.0.1",
        userAgent: "Mozilla",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      // IPv6 should pass through maskIp unchanged (not 4 octets)
      expect(result.message).toContain("::1");
    });

    it("should handle very long fingerprint without performance degradation", () => {
      const longFp = "a".repeat(1024);
      const record: SessionRecord = createBaseRecord({
        metadata: { deviceFingerprint: longFp },
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        deviceFingerprint: "b".repeat(1024),
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      // Hash should be exactly 16 chars regardless of input length
      expect(result.message).toMatch(/Expected: [a-f0-9]{16}/);
      expect(result.message).toMatch(/Actual: [a-f0-9]{16}/);
    });

    it("should not leak fingerprint in hard-mode message even when context has undefined fingerprint", () => {
      const record: SessionRecord = createBaseRecord({
        metadata: { deviceFingerprint: "persistent_real_fp" },
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla",
        // deviceFingerprint intentionally omitted (undefined)
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      expect(result.message).not.toContain("persistent_real_fp");
      expect(result.message).toMatch(/Actual: [a-f0-9]{16}/);
    });

    it("should handle very long User-Agent in hard mode without performance degradation", () => {
      const longUA = "Mozilla/5.0 ".repeat(100); // ~1200 chars
      const record: SessionRecord = createBaseRecord({
        metadata: { userAgent: longUA },
      });

      const result = evaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "Different-UA",
        method: "GET",
      });

      expect(result.isValid).toBe(false);
      // UA is public data — kept as-is in message, not hashed
      expect(result.message).toContain(longUA);
    });

    it("should handle empty User-Agent in soft mode without throwing", () => {
      const softFpConfig = {
        ...baseConfig,
        security: { ...baseConfig.security, fingerprinting: "soft" as const },
      };
      const softEvaluator = new SecurityPolicyEvaluator(softFpConfig);

      const record: SessionRecord = createBaseRecord({
        metadata: { userAgent: "Mozilla" },
      });

      const result = softEvaluator.evaluate(record, {
        ipAddress: "192.168.1.1",
        userAgent: "", // empty UA
        method: "GET",
      });

      expect(result.isValid).toBe(true);
      expect(result.softWarning).toBe(true);
    });
  });
});
