import { SelectiveRevocationEngine } from "../src/core/selective-revocation-engine";
import { MemoryStoreAdapter } from "../src/storage/adapters/memory.adapter";
import {
  SessionRecord,
  SessionStatus,
  SessionReasonCode,
  SessionStoreAdapter,
} from "../src/types";
import { v4 as uuidv4 } from "uuid";

describe("SelectiveRevocationEngine", () => {
  let engine: SelectiveRevocationEngine;
  let store: MemoryStoreAdapter;
  let events: Array<{ event: string; payload: Record<string, unknown> }>;

  const createMockRecord = (
    overrides: Partial<SessionRecord> = {},
  ): SessionRecord => {
    const now = new Date();
    return {
      id: uuidv4(),
      userId: "user-1",
      tokenHash: uuidv4(),
      status: SessionStatus.ACTIVE,
      roles: ["user"],
      scopes: ["read"],
      createdAt: now,
      lastUsedAt: now,
      expiresAt: new Date(now.getTime() + 3600000),
      idleExpiresAt: new Date(now.getTime() + 1800000),
      metadata: {
        ipAddress: "127.0.0.1",
        deviceFingerprint: "fp-abc",
      },
      ...overrides,
    };
  };

  const emitEvent = (
    event: string,
    payload: Record<string, unknown>,
  ): void => {
    events.push({ event, payload });
  };

  beforeEach(() => {
    store = new MemoryStoreAdapter();
    events = [];
    engine = new SelectiveRevocationEngine(store, emitEvent);
  });

  // ─── revokeAllForUser ──────────────────────────────────────────

  describe("revokeAllForUser", () => {
    it("should soft-revoke all sessions for a user", async () => {
      const r1 = createMockRecord({ id: "s1" });
      const r2 = createMockRecord({ id: "s2" });
      await store.create(r1);
      await store.create(r2);

      const result = await engine.revokeAllForUser(
        "user-1",
        SessionReasonCode.ADMIN_REVOKED,
      );

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(2);
        expect(result.data.revokedSessionIds).toContain("s1");
        expect(result.data.revokedSessionIds).toContain("s2");
        expect(result.data.failedSessionIds).toHaveLength(0);
      }

      const s1 = await store.findById("s1");
      const s2 = await store.findById("s2");
      expect(s1?.status).toBe(SessionStatus.REVOKED);
      expect(s2?.status).toBe(SessionStatus.REVOKED);
      expect(s1?.revocationReason).toBe(SessionReasonCode.ADMIN_REVOKED);
      expect(s1?.revokedAt).toBeInstanceOf(Date);
    });

    it("should return 0 count when no sessions exist", async () => {
      const result = await engine.revokeAllForUser(
        "user-nonexistent",
        SessionReasonCode.ADMIN_REVOKED,
      );

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(0);
        expect(result.data.revokedSessionIds).toEqual([]);
        expect(result.data.failedSessionIds).toEqual([]);
      }
    });

    it("should be idempotent on already-revoked sessions", async () => {
      const r1 = createMockRecord({ id: "s1" });
      await store.create(r1);

      await engine.revokeAllForUser(
        "user-1",
        SessionReasonCode.ADMIN_REVOKED,
      );
      const second = await engine.revokeAllForUser(
        "user-1",
        SessionReasonCode.ADMIN_REVOKED,
      );

      expect(second.success).toBe(true);
      if (second.success) {
        expect(second.data.revokedCount).toBe(0);
      }
    });

    it("should emit batch.revoked and session.revoked events", async () => {
      const r1 = createMockRecord({ id: "s1" });
      await store.create(r1);

      await engine.revokeAllForUser(
        "user-1",
        SessionReasonCode.USER_ALL_SESSIONS_REVOKED,
      );

      const batchEvent = events.find((e) => e.event === "batch.revoked");
      expect(batchEvent).toBeDefined();
      expect(batchEvent?.payload.target).toBe("all");
      expect(batchEvent?.payload.count).toBe(1);

      const sessionEvent = events.find(
        (e) => e.event === "session.revoked",
      );
      expect(sessionEvent).toBeDefined();
      expect(sessionEvent?.payload.sessionId).toBe("s1");
    });

    it("should not affect other users' sessions", async () => {
      const r1 = createMockRecord({ id: "s1", userId: "user-1" });
      const r2 = createMockRecord({ id: "s2", userId: "user-2" });
      await store.create(r1);
      await store.create(r2);

      await engine.revokeAllForUser(
        "user-1",
        SessionReasonCode.ADMIN_REVOKED,
      );

      const s2 = await store.findById("s2");
      expect(s2?.status).toBe(SessionStatus.ACTIVE);
    });

    it("should return error for empty userId", async () => {
      const result = await engine.revokeAllForUser(
        "",
        SessionReasonCode.ADMIN_REVOKED,
      );
      expect(result.success).toBe(false);
    });

    it("should return error for userId exceeding max length", async () => {
      const result = await engine.revokeAllForUser(
        "a".repeat(513),
        SessionReasonCode.ADMIN_REVOKED,
      );
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.message).toContain("512");
      }
    });

    it("should return error for invalid reason code", async () => {
      const result = await engine.revokeAllForUser(
        "user-1",
        "hahaha_lol" as SessionReasonCode,
      );
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.message).toContain("SessionReasonCode");
      }
    });
  });

  // ─── revokeByDevice ────────────────────────────────────────────

  describe("revokeByDevice", () => {
    it("should revoke only sessions matching device fingerprint", async () => {
      const r1 = createMockRecord({
        id: "s1",
        metadata: { ipAddress: "127.0.0.1", deviceFingerprint: "fp-phone" },
      });
      const r2 = createMockRecord({
        id: "s2",
        metadata: { ipAddress: "127.0.0.1", deviceFingerprint: "fp-laptop" },
      });
      await store.create(r1);
      await store.create(r2);

      const result = await engine.revokeByDevice({
        userId: "user-1",
        deviceFingerprint: "fp-phone",
        reason: SessionReasonCode.DEVICE_LOGOUT,
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(1);
        expect(result.data.revokedSessionIds).toContain("s1");
        expect(result.data.revokedSessionIds).not.toContain("s2");
      }

      const s1 = await store.findById("s1");
      const s2 = await store.findById("s2");
      expect(s1?.status).toBe(SessionStatus.REVOKED);
      expect(s2?.status).toBe(SessionStatus.ACTIVE);
    });

    it("should exclude session when excludeSessionId is provided", async () => {
      const r1 = createMockRecord({
        id: "s1",
        metadata: { ipAddress: "127.0.0.1", deviceFingerprint: "fp-phone" },
      });
      await store.create(r1);

      const result = await engine.revokeByDevice({
        userId: "user-1",
        deviceFingerprint: "fp-phone",
        reason: SessionReasonCode.DEVICE_LOGOUT,
        excludeSessionId: "s1",
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(0);
      }

      const s1 = await store.findById("s1");
      expect(s1?.status).toBe(SessionStatus.ACTIVE);
    });

    it("should return 0 count for non-existent fingerprint", async () => {
      const r1 = createMockRecord({
        id: "s1",
        metadata: { ipAddress: "127.0.0.1", deviceFingerprint: "fp-phone" },
      });
      await store.create(r1);

      const result = await engine.revokeByDevice({
        userId: "user-1",
        deviceFingerprint: "fp-nonexistent",
        reason: SessionReasonCode.DEVICE_LOGOUT,
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(0);
      }
    });

    it("should emit batch.revoked with target=device", async () => {
      const r1 = createMockRecord({
        id: "s1",
        metadata: { ipAddress: "127.0.0.1", deviceFingerprint: "fp-phone" },
      });
      await store.create(r1);

      await engine.revokeByDevice({
        userId: "user-1",
        deviceFingerprint: "fp-phone",
        reason: SessionReasonCode.DEVICE_LOGOUT,
      });

      const batchEvent = events.find((e) => e.event === "batch.revoked");
      expect(batchEvent).toBeDefined();
      expect(batchEvent?.payload.target).toBe("device");
      expect(batchEvent?.payload.deviceFingerprint).toBe("fp-phone");
    });

    it("should return error for empty deviceFingerprint", async () => {
      const result = await engine.revokeByDevice({
        userId: "user-1",
        deviceFingerprint: "",
        reason: SessionReasonCode.DEVICE_LOGOUT,
      });
      expect(result.success).toBe(false);
    });
  });

  // ─── revokeBeforeTimestamp ──────────────────────────────────────

  describe("revokeBeforeTimestamp", () => {
    it("should revoke sessions created before the timestamp", async () => {
      const oldDate = new Date("2024-01-01");
      const newDate = new Date("2025-01-01");
      const r1 = createMockRecord({ id: "s1", createdAt: oldDate });
      const r2 = createMockRecord({ id: "s2", createdAt: newDate });
      await store.create(r1);
      await store.create(r2);

      const result = await engine.revokeBeforeTimestamp({
        userId: "user-1",
        issuedBefore: new Date("2024-06-01"),
        reason: SessionReasonCode.TIMESTAMP_PURGE,
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(1);
        expect(result.data.revokedSessionIds).toContain("s1");
      }

      const s1 = await store.findById("s1");
      const s2 = await store.findById("s2");
      expect(s1?.status).toBe(SessionStatus.REVOKED);
      expect(s2?.status).toBe(SessionStatus.ACTIVE);
    });

    it("should keep session when keepSessionId is provided", async () => {
      const oldDate = new Date("2024-01-01");
      const r1 = createMockRecord({ id: "s1", createdAt: oldDate });
      const r2 = createMockRecord({ id: "s2", createdAt: oldDate });
      await store.create(r1);
      await store.create(r2);

      const result = await engine.revokeBeforeTimestamp({
        userId: "user-1",
        issuedBefore: new Date("2025-01-01"),
        reason: SessionReasonCode.TIMESTAMP_PURGE,
        keepSessionId: "s1",
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(1);
        expect(result.data.revokedSessionIds).toContain("s2");
        expect(result.data.revokedSessionIds).not.toContain("s1");
      }
    });

    it("should still revoke all when keepSessionId points to non-existent session", async () => {
      const r1 = createMockRecord({
        id: "s1",
        createdAt: new Date("2024-01-01"),
      });
      await store.create(r1);

      const result = await engine.revokeBeforeTimestamp({
        userId: "user-1",
        issuedBefore: new Date("2025-01-01"),
        reason: SessionReasonCode.TIMESTAMP_PURGE,
        keepSessionId: "nonexistent",
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(1);
      }
    });

    it("should return error for invalid issuedBefore", async () => {
      const result = await engine.revokeBeforeTimestamp({
        userId: "user-1",
        issuedBefore: new Date("invalid"),
        reason: SessionReasonCode.TIMESTAMP_PURGE,
      });
      expect(result.success).toBe(false);
    });

    it("should emit batch.revoked with target=timestamp", async () => {
      const r1 = createMockRecord({
        id: "s1",
        createdAt: new Date("2024-01-01"),
      });
      await store.create(r1);

      await engine.revokeBeforeTimestamp({
        userId: "user-1",
        issuedBefore: new Date("2025-01-01"),
        reason: SessionReasonCode.TIMESTAMP_PURGE,
      });

      const batchEvent = events.find((e) => e.event === "batch.revoked");
      expect(batchEvent).toBeDefined();
      expect(batchEvent?.payload.target).toBe("timestamp");
    });
  });

  // ─── revokeByRole ──────────────────────────────────────────────

  describe("revokeByRole", () => {
    it("should revoke sessions holding a specific role", async () => {
      const r1 = createMockRecord({
        id: "s1",
        roles: ["admin", "user"],
      });
      const r2 = createMockRecord({
        id: "s2",
        roles: ["user"],
      });
      await store.create(r1);
      await store.create(r2);

      const result = await engine.revokeByRole({
        userId: "user-1",
        role: "admin",
        reason: SessionReasonCode.ROLE_DEPRECATED,
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(1);
        expect(result.data.revokedSessionIds).toContain("s1");
        expect(result.data.revokedSessionIds).not.toContain("s2");
      }

      const s1 = await store.findById("s1");
      const s2 = await store.findById("s2");
      expect(s1?.status).toBe(SessionStatus.REVOKED);
      expect(s2?.status).toBe(SessionStatus.ACTIVE);
    });

    it("should exclude session when excludeSessionId is provided", async () => {
      const r1 = createMockRecord({
        id: "s1",
        roles: ["admin"],
      });
      await store.create(r1);

      const result = await engine.revokeByRole({
        userId: "user-1",
        role: "admin",
        reason: SessionReasonCode.ROLE_DEPRECATED,
        excludeSessionId: "s1",
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(0);
      }
    });

    it("should return error for empty role", async () => {
      const result = await engine.revokeByRole({
        userId: "user-1",
        role: "",
        reason: SessionReasonCode.ROLE_DEPRECATED,
      });
      expect(result.success).toBe(false);
    });

    it("should emit batch.revoked with target=role", async () => {
      const r1 = createMockRecord({
        id: "s1",
        roles: ["admin"],
      });
      await store.create(r1);

      await engine.revokeByRole({
        userId: "user-1",
        role: "admin",
        reason: SessionReasonCode.ROLE_DEPRECATED,
      });

      const batchEvent = events.find((e) => e.event === "batch.revoked");
      expect(batchEvent).toBeDefined();
      expect(batchEvent?.payload.target).toBe("role");
      expect(batchEvent?.payload.role).toBe("admin");
    });
  });

  // ─── Adapter Fallback ──────────────────────────────────────────

  describe("adapter fallback", () => {
    it("should work when store.revokeAllForUser is not implemented", async () => {
      const fallbackStore: SessionStoreAdapter = {
        create: jest.fn(),
        rotate: jest.fn(),
        findById: jest.fn(),
        findByTokenHash: jest.fn(),
        update: jest.fn().mockResolvedValue(undefined),
        delete: jest.fn(),
        deleteAllForUser: jest.fn(),
        countActiveForUser: jest.fn(),
        findAllForUser: jest.fn().mockResolvedValue({
          sessions: [
            createMockRecord({ id: "s1" }),
            createMockRecord({ id: "s2" }),
          ],
          total: 2,
          totalIsApproximate: false,
          nextCursor: null,
        }),
      };

      const fallbackEngine = new SelectiveRevocationEngine(
        fallbackStore,
        emitEvent,
      );

      const result = await fallbackEngine.revokeAllForUser(
        "user-1",
        SessionReasonCode.ADMIN_REVOKED,
      );

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(2);
      }
      expect(fallbackStore.update).toHaveBeenCalledTimes(2);
    });

    it("should fall back to findAllForUser when findLiveSessionsForUser is absent", async () => {
      const fallbackStore: SessionStoreAdapter = {
        create: jest.fn(),
        rotate: jest.fn(),
        findById: jest.fn(),
        findByTokenHash: jest.fn(),
        update: jest.fn().mockResolvedValue(undefined),
        delete: jest.fn(),
        deleteAllForUser: jest.fn(),
        countActiveForUser: jest.fn(),
        findAllForUser: jest.fn().mockResolvedValue({
          sessions: [
            createMockRecord({ id: "s1" }),
            createMockRecord({
              id: "s2",
              status: SessionStatus.REVOKED,
              revokedAt: new Date(),
            }),
          ],
          total: 2,
          totalIsApproximate: false,
          nextCursor: null,
        }),
        // No findLiveSessionsForUser
      };

      const fallbackEngine = new SelectiveRevocationEngine(
        fallbackStore,
        emitEvent,
      );

      const result = await fallbackEngine.revokeAllForUser(
        "user-1",
        SessionReasonCode.ADMIN_REVOKED,
      );

      expect(result.success).toBe(true);
      if (result.success) {
        // Should only revoke s1, not the already-revoked s2
        expect(result.data.revokedCount).toBe(1);
        expect(result.data.revokedSessionIds).toContain("s1");
      }
    });
  });

  // ─── Partial Failure ───────────────────────────────────────────

  describe("partial failure", () => {
    it("should report failed session IDs when store.update throws mid-loop", async () => {
      const r1 = createMockRecord({ id: "s1" });
      const r2 = createMockRecord({ id: "s2" });
      const r3 = createMockRecord({ id: "s3" });
      await store.create(r1);
      await store.create(r2);
      await store.create(r3);

      // WHY: Use a custom adapter WITHOUT revokeAllForUser to force the fallback
      // path through revokeSessions loop where partial failure can occur.
      let callCount = 0;
      const customStore: SessionStoreAdapter = {
        create: jest.fn(),
        rotate: jest.fn(),
        findById: jest.fn(),
        findByTokenHash: jest.fn(),
        update: jest.fn().mockImplementation(async () => {
          callCount++;
          if (callCount === 2) throw new Error("REDIS_TIMEOUT");
        }),
        delete: jest.fn(),
        deleteAllForUser: jest.fn(),
        countActiveForUser: jest.fn(),
        findAllForUser: jest.fn().mockResolvedValue({
          sessions: [r1, r2, r3],
          total: 3,
          totalIsApproximate: false,
          nextCursor: null,
        }),
        // No revokeAllForUser — forces fallback through revokeSessions loop
        // No findLiveSessionsForUser — forces fallback through findAllForUser
      };

      const customEngine = new SelectiveRevocationEngine(
        customStore,
        emitEvent,
      );

      const result = await customEngine.revokeAllForUser(
        "user-1",
        SessionReasonCode.ADMIN_REVOKED,
      );

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.revokedCount).toBe(2);
        expect(result.data.revokedSessionIds).toHaveLength(2);
        expect(result.data.failedSessionIds).toHaveLength(1);
        expect(result.data.failedSessionIds).toContain("s2");
      }
    });
  });

  // ─── Error Handling ────────────────────────────────────────────

  describe("error handling", () => {
    it("should handle store errors gracefully", async () => {
      const errorStore: SessionStoreAdapter = {
        create: jest.fn(),
        rotate: jest.fn(),
        findById: jest.fn(),
        findByTokenHash: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
        deleteAllForUser: jest.fn(),
        countActiveForUser: jest.fn(),
        findAllForUser: jest.fn().mockRejectedValue(new Error("REDIS_DOWN")),
      };

      const errorEngine = new SelectiveRevocationEngine(
        errorStore,
        emitEvent,
      );

      const result = await errorEngine.revokeAllForUser(
        "user-1",
        SessionReasonCode.ADMIN_REVOKED,
      );

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe("INTERNAL_ERROR");
        expect(result.httpCode).toBe(500);
      }
    });
  });
});
