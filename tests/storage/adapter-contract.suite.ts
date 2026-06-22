import { SessionStoreAdapter } from "../../src/storage/contracts";
import { SessionRecord, SessionStatus, SessionReasonCode, SessionLimits } from "../../src/types";
import { v4 as uuidv4 } from "uuid";

/**
 * Shared contract test suite for SessionStoreAdapters.
 * Ensures all implementations (Memory, Redis, etc.) behave consistently.
 */
export function runAdapterContractTests(
  adapterName: string,
  createAdapter: () => Promise<SessionStoreAdapter>,
  cleanup?: () => Promise<void>
) {
  describe(`${adapterName} Contract Tests`, () => {
    let adapter: SessionStoreAdapter;

    beforeEach(async () => {
      adapter = await createAdapter();
    });

    afterEach(async () => {
      if (cleanup) await cleanup();
    });

    const createMockRecord = (overrides: Partial<SessionRecord> = {}): SessionRecord => {
      const now = new Date();
      return {
        id: uuidv4(),
        userId: "user-123",
        tokenHash: uuidv4(),
        status: SessionStatus.ACTIVE,
        roles: ["user"],
        scopes: ["read"],
        createdAt: now,
        lastUsedAt: now,
        expiresAt: new Date(now.getTime() + 3600000),
        idleExpiresAt: new Date(now.getTime() + 1800000),
        metadata: { ipAddress: "127.0.0.1" },
        ...overrides,
      };
    };

    const stripDates = (record: SessionRecord | null) => {
        if (!record) return null;
        return {
            ...record,
            createdAt: record.createdAt.getTime(),
            lastUsedAt: record.lastUsedAt.getTime(),
            expiresAt: record.expiresAt.getTime(),
            idleExpiresAt: record.idleExpiresAt.getTime(),
            revokedAt: record.revokedAt?.getTime(),
        };
    };

    test("should create and find session by id", async () => {
      const record = createMockRecord();
      await adapter.create(record);
      const found = await adapter.findById(record.id);
      
      expect(found).not.toBeNull();
      expect(stripDates(found!)).toMatchObject(stripDates(record)!);
    });

    test("should find session by token hash", async () => {
      const record = createMockRecord();
      await adapter.create(record);
      const found = await adapter.findByTokenHash(record.tokenHash);
      
      expect(found).not.toBeNull();
      expect(stripDates(found!)).toMatchObject(stripDates(record)!);
    });

    test("should update session fields atomically", async () => {
      const record = createMockRecord();
      await adapter.create(record);
      
      const updates = { status: SessionStatus.REVOKED, revocationReason: SessionReasonCode.MANUAL_LOGOUT };
      await adapter.update(record.id, updates);
      
      const updated = await adapter.findById(record.id);
      expect(updated?.status).toBe(SessionStatus.REVOKED);
      expect(updated?.revocationReason).toBe(SessionReasonCode.MANUAL_LOGOUT);
      expect(updated?.userId).toBe(record.userId);
    });

    test("should delete session and all indices", async () => {
      const record = createMockRecord();
      await adapter.create(record);
      await adapter.delete(record.id);
      
      expect(await adapter.findById(record.id)).toBeNull();
      expect(await adapter.findByTokenHash(record.tokenHash)).toBeNull();
    });

    test("should delete all sessions for user", async () => {
      const userId = uuidv4();
      await adapter.create(createMockRecord({ id: "s1", userId }));
      await adapter.create(createMockRecord({ id: "s2", userId }));
      
      await adapter.deleteAllForUser(userId);
      
      expect(await adapter.findById("s1")).toBeNull();
      expect(await adapter.findById("s2")).toBeNull();
    });

    test("should count active sessions for user correctly", async () => {
      const userId = uuidv4();
      await adapter.create(createMockRecord({ id: "active", userId }));
      await adapter.create(createMockRecord({ id: "revoked", userId, status: SessionStatus.REVOKED }));
      
      const count = await adapter.countActiveForUser(userId);
      expect(count).toBe(1);
    });

    test("should findAllForUser return active sessions with default pagination", async () => {
      const userId = uuidv4();
      await adapter.create(createMockRecord({ id: "s1", userId }));
      await adapter.create(createMockRecord({ id: "s2", userId }));

      const result = await adapter.findAllForUser(userId);

      expect(result.sessions.length).toBe(2);
      expect(result.total).toBe(2);
      expect(result.totalIsApproximate).toBe(false);
      expect(result.nextCursor).toBeNull();
    });

    test("should findAllForUser filter by status", async () => {
      const userId = uuidv4();
      await adapter.create(createMockRecord({ id: "active", userId, status: SessionStatus.ACTIVE }));
      await adapter.create(createMockRecord({ id: "revoked", userId, status: SessionStatus.REVOKED }));

      const activeResult = await adapter.findAllForUser(userId, { status: SessionStatus.ACTIVE });
      expect(activeResult.sessions.length).toBe(1);
      expect(activeResult.sessions[0].id).toBe("active");

      const revokedResult = await adapter.findAllForUser(userId, { status: SessionStatus.REVOKED });
      expect(revokedResult.sessions.length).toBe(1);
      expect(revokedResult.sessions[0].id).toBe("revoked");
    });

    test("should findAllForUser paginate with limit and cursor", async () => {
      const userId = uuidv4();
      await adapter.create(createMockRecord({ id: "s1", userId }));
      await adapter.create(createMockRecord({ id: "s2", userId }));
      await adapter.create(createMockRecord({ id: "s3", userId }));

      const page1 = await adapter.findAllForUser(userId, { limit: 2 });
      expect(page1.sessions.length).toBe(2);
      expect(page1.total).toBe(3);
      expect(page1.nextCursor).toBeDefined();

      const page2 = await adapter.findAllForUser(userId, { limit: 2, cursor: page1.nextCursor! });
      expect(page2.sessions.length).toBe(1);
      expect(page2.nextCursor).toBeNull();
    });

    test("should findAllForUser return empty for nonexistent user", async () => {
      const result = await adapter.findAllForUser("nonexistent");
      expect(result.sessions).toEqual([]);
      expect(result.total).toBe(0);
      expect(result.nextCursor).toBeNull();
    });

    test("should findAllForUser not return sessions from other users", async () => {
      const userId = uuidv4();
      const otherUserId = uuidv4();
      await adapter.create(createMockRecord({ id: "mine", userId }));
      await adapter.create(createMockRecord({ id: "theirs", userId: otherUserId }));

      const result = await adapter.findAllForUser(userId);
      expect(result.sessions.length).toBe(1);
      expect(result.sessions[0].id).toBe("mine");
    });

    test("should find session by NEW token hash after rotation", async () => {
      const record = createMockRecord();
      await adapter.create(record);

      const newTokenHash = uuidv4();
      await adapter.update(record.id, { tokenHash: newTokenHash });

      const foundOld = await adapter.findByTokenHash(record.tokenHash);
      const foundNew = await adapter.findByTokenHash(newTokenHash);

      expect(foundOld).toBeNull(); // Old index should be unlinked
      expect(foundNew).not.toBeNull();
      expect(foundNew?.id).toBe(record.id);
    });

    test("should findAllForUser not return expired ACTIVE sessions", async () => {
      const userId = uuidv4();
      const now = new Date();
      await adapter.create(
        createMockRecord({
          id: "expired-active",
          userId,
          status: SessionStatus.ACTIVE,
          expiresAt: new Date(now.getTime() - 1000),
        }),
      );
      await adapter.create(
        createMockRecord({
          id: "valid-active",
          userId,
          status: SessionStatus.ACTIVE,
          expiresAt: new Date(now.getTime() + 3600000),
        }),
      );

      const result = await adapter.findAllForUser(userId, {
        status: SessionStatus.ACTIVE,
      });
      expect(result.sessions.length).toBe(1);
      expect(result.sessions[0].id).toBe("valid-active");
    });

    test("should findAllForUser return empty when cursor points to deleted session", async () => {
      const userId = uuidv4();
      await adapter.create(createMockRecord({ id: "s1", userId }));

      const result = await adapter.findAllForUser(userId, {
        limit: 1,
        cursor: "nonexistent-id",
      });
      expect(result.sessions).toEqual([]);
      expect(result.nextCursor).toBeNull();
    });

    test("should revokeAllForUser soft-revoke all sessions and return affected IDs", async () => {
      if (!adapter.revokeAllForUser) return; // Skip if adapter doesn't implement

      const userId = uuidv4();
      await adapter.create(createMockRecord({ id: "s1", userId }));
      await adapter.create(createMockRecord({ id: "s2", userId }));
      await adapter.create(createMockRecord({ id: "s3", userId: "other" }));

      const revokedAt = new Date();
      const affected = await adapter.revokeAllForUser(
        userId,
        SessionReasonCode.ADMIN_REVOKED,
        revokedAt,
      );

      expect(affected).toHaveLength(2);
      expect(affected).toContain("s1");
      expect(affected).toContain("s2");

      const s1 = await adapter.findById("s1");
      const s2 = await adapter.findById("s2");
      const s3 = await adapter.findById("s3");
      expect(s1?.status).toBe(SessionStatus.REVOKED);
      expect(s1?.revocationReason).toBe(SessionReasonCode.ADMIN_REVOKED);
      expect(s2?.status).toBe(SessionStatus.REVOKED);
      expect(s3?.status).toBe(SessionStatus.ACTIVE); // Other user untouched
    });

    test("should revokeAllForUser return empty array when already revoked", async () => {
      if (!adapter.revokeAllForUser) return;

      const userId = uuidv4();
      await adapter.create(
        createMockRecord({
          id: "s1",
          userId,
          status: SessionStatus.REVOKED,
          revokedAt: new Date(),
          revocationReason: SessionReasonCode.MANUAL_LOGOUT,
        }),
      );

      const affected = await adapter.revokeAllForUser(
        userId,
        SessionReasonCode.ADMIN_REVOKED,
        new Date(),
      );
      expect(affected).toHaveLength(0);
    });

    test("should revokeAllForUser return empty array for nonexistent user", async () => {
      if (!adapter.revokeAllForUser) return;

      const affected = await adapter.revokeAllForUser(
        "nonexistent",
        SessionReasonCode.ADMIN_REVOKED,
        new Date(),
      );
      expect(affected).toHaveLength(0);
    });

    test("should findLiveSessionsForUser return only ACTIVE and ROTATED sessions", async () => {
      if (!adapter.findLiveSessionsForUser) return;

      const userId = uuidv4();
      const now = new Date();
      await adapter.create(
        createMockRecord({ id: "active-1", userId, status: SessionStatus.ACTIVE }),
      );
      await adapter.create(
        createMockRecord({ id: "rotated-1", userId, status: SessionStatus.ROTATED }),
      );
      await adapter.create(
        createMockRecord({
          id: "revoked-1",
          userId,
          status: SessionStatus.REVOKED,
          revokedAt: now,
          revocationReason: SessionReasonCode.MANUAL_LOGOUT,
        }),
      );
      await adapter.create(
        createMockRecord({
          id: "expired-1",
          userId,
          status: SessionStatus.EXPIRED,
        }),
      );

      const live = await adapter.findLiveSessionsForUser(userId);
      const liveIds = live.map((s) => s.id);

      expect(liveIds).toContain("active-1");
      expect(liveIds).toContain("rotated-1");
      expect(liveIds).not.toContain("revoked-1");
      expect(liveIds).not.toContain("expired-1");
    });

    test("should findLiveSessionsForUser return empty for nonexistent user", async () => {
      if (!adapter.findLiveSessionsForUser) return;

      const live = await adapter.findLiveSessionsForUser("nonexistent");
      expect(live).toHaveLength(0);
    });

    test("should findLiveSessionsForUser not return sessions from other users", async () => {
      if (!adapter.findLiveSessionsForUser) return;

      const userId = uuidv4();
      const otherUserId = uuidv4();
      await adapter.create(createMockRecord({ id: "mine", userId }));
      await adapter.create(createMockRecord({ id: "theirs", userId: otherUserId }));

      const live = await adapter.findLiveSessionsForUser(userId);
      expect(live).toHaveLength(1);
      expect(live[0].id).toBe("mine");
    });

    test("should findLiveSessionsForUser exclude expired ROTATED sessions", async () => {
      if (!adapter.findLiveSessionsForUser) return;

      const userId = uuidv4();
      const now = new Date();
      // Active session — not expired
      await adapter.create(
        createMockRecord({ id: "active-1", userId, status: SessionStatus.ACTIVE }),
      );
      // Rotated session — not expired (expiresAt in future)
      await adapter.create(
        createMockRecord({
          id: "rotated-live",
          userId,
          status: SessionStatus.ROTATED,
          expiresAt: new Date(now.getTime() + 3600000),
        }),
      );
      // Rotated session — expired (expiresAt in past)
      await adapter.create(
        createMockRecord({
          id: "rotated-expired",
          userId,
          status: SessionStatus.ROTATED,
          expiresAt: new Date(now.getTime() - 1000),
        }),
      );

      const live = await adapter.findLiveSessionsForUser(userId);
      const liveIds = live.map((s) => s.id);

      expect(liveIds).toContain("active-1");
      expect(liveIds).toContain("rotated-live");
      expect(liveIds).not.toContain("rotated-expired");
    });

    test("should revokeAllForUser include ROTATED sessions", async () => {
      if (!adapter.revokeAllForUser) return;

      const userId = uuidv4();
      const now = new Date();
      await adapter.create(
        createMockRecord({ id: "active-1", userId, status: SessionStatus.ACTIVE }),
      );
      await adapter.create(
        createMockRecord({
          id: "rotated-1",
          userId,
          status: SessionStatus.ROTATED,
          expiresAt: new Date(now.getTime() + 3600000),
        }),
      );

      const affected = await adapter.revokeAllForUser(
        userId,
        SessionReasonCode.ADMIN_REVOKED,
        new Date(),
      );

      expect(affected).toContain("active-1");
      expect(affected).toContain("rotated-1");

      const rotated = await adapter.findById("rotated-1");
      expect(rotated?.status).toBe(SessionStatus.REVOKED);
    });

    // ── Role-Based Session Limit Tests ──────────────────────────────────

    test("should enforce dual limits: global + role independently", async () => {
      const userId = uuidv4();
      const limits: SessionLimits = {
        maxSessionsPerUser: 5,
        maxSessionsPerRole: { ADMIN: 2 },
      };

      // Create 2 ADMIN sessions — hits ADMIN limit
      await adapter.create(createMockRecord({ id: "a1", userId, roles: ["ADMIN"] }), limits);
      await adapter.create(createMockRecord({ id: "a2", userId, roles: ["ADMIN"] }), limits);
      await expect(
        adapter.create(createMockRecord({ id: "a3", userId, roles: ["ADMIN"] }), limits)
      ).rejects.toThrow("SESSION_LIMIT_REACHED");

      // Global cap still allows more (5 total, only 2 used)
      await adapter.create(createMockRecord({ id: "u1", userId, roles: ["USER"] }), limits);
    });

    test("should enforce global cap even when role limit is higher", async () => {
      const userId = uuidv4();
      const limits: SessionLimits = {
        maxSessionsPerUser: 3,
        maxSessionsPerRole: { ADMIN: 10 },
      };

      await adapter.create(createMockRecord({ id: "a1", userId, roles: ["ADMIN"] }), limits);
      await adapter.create(createMockRecord({ id: "a2", userId, roles: ["ADMIN"] }), limits);
      await adapter.create(createMockRecord({ id: "a3", userId, roles: ["ADMIN"] }), limits);

      // Global cap (3) reached, even though ADMIN limit (10) not reached
      await expect(
        adapter.create(createMockRecord({ id: "a4", userId, roles: ["ADMIN"] }), limits)
      ).rejects.toThrow("SESSION_LIMIT_REACHED");
    });

    test("should not count ordinary sessions against role limits", async () => {
      const userId = uuidv4();
      const limits: SessionLimits = {
        maxSessionsPerUser: 10,
        maxSessionsPerRole: { ADMIN: 1 },
      };

      // Create 1 ADMIN session — hits ADMIN limit
      await adapter.create(createMockRecord({ id: "a1", userId, roles: ["ADMIN"] }), limits);
      await expect(
        adapter.create(createMockRecord({ id: "a2", userId, roles: ["ADMIN"] }), limits)
      ).rejects.toThrow("SESSION_LIMIT_REACHED");

      // Ordinary sessions (roles: []) don't count against ADMIN limit
      await adapter.create(createMockRecord({ id: "o1", userId, roles: [] }), limits);
      await adapter.create(createMockRecord({ id: "o2", userId, roles: [] }), limits);
    });

    test("should enforce role limits during rotation with role change", async () => {
      const userId = uuidv4();
      const limits: SessionLimits = {
        maxSessionsPerUser: 5,
        maxSessionsPerRole: { SUPER_ADMIN: 1 },
      };

      // Create 2 ordinary sessions
      await adapter.create(createMockRecord({ id: "s1", userId, roles: [] }), limits);
      await adapter.create(createMockRecord({ id: "s2", userId, roles: [] }), limits);

      // Rotate s1 to SUPER_ADMIN — succeeds (no existing SUPER_ADMIN sessions)
      const newRecord1 = createMockRecord({ id: "new1", userId, roles: ["SUPER_ADMIN"] });
      await adapter.rotate("s1", newRecord1, { status: SessionStatus.ROTATED }, limits, []);

      // Rotate s2 to SUPER_ADMIN — blocked (SUPER_ADMIN limit = 1, already have 1)
      const newRecord2 = createMockRecord({ id: "new2", userId, roles: ["SUPER_ADMIN"] });
      await expect(
        adapter.rotate("s2", newRecord2, { status: SessionStatus.ROTATED }, limits, [])
      ).rejects.toThrow("SESSION_LIMIT_REACHED");
    });

    test("should allow rotation with same roles (1-to-1 replacement)", async () => {
      const userId = uuidv4();
      const limits: SessionLimits = {
        maxSessionsPerUser: 2,
        maxSessionsPerRole: { ADMIN: 2 },
      };

      // Create 2 ADMIN sessions — at both limits
      await adapter.create(createMockRecord({ id: "a1", userId, roles: ["ADMIN"] }), limits);
      await adapter.create(createMockRecord({ id: "a2", userId, roles: ["ADMIN"] }), limits);

      // Rotate a1 with same roles — should succeed (1-to-1 replacement, count stays 2)
      const newRecord = createMockRecord({ id: "new1", userId, roles: ["ADMIN"] });
      await adapter.rotate("a1", newRecord, { status: SessionStatus.ROTATED }, limits, ["ADMIN"]);

      // Verify old is rotated, new is active
      const old = await adapter.findById("a1");
      expect(old?.status).toBe(SessionStatus.ROTATED);
      const fresh = await adapter.findById("new1");
      expect(fresh?.status).toBe(SessionStatus.ACTIVE);
    });
  });
}
