import { SessionStoreAdapter } from "../../src/storage/contracts";
import { SessionRecord, SessionStatus, SessionReasonCode } from "../../src/types";
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
  });
}
