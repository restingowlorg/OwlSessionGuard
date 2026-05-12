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
  });
}
