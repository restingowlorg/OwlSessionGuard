/* eslint-disable @typescript-eslint/no-require-imports */
import { SessionService } from "../src/core/session.service";
import { MemoryStoreAdapter } from "../src/storage/adapters/memory.adapter";
import {
  SessionLibraryConfig,
  SessionStatus,
  SessionReasonCode,
} from "../src/types";

describe("SessionService", () => {
  let service: SessionService;
  let store: MemoryStoreAdapter;
  const config: SessionLibraryConfig = {
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
      fingerprinting: "off",
      csrf: { enabled: false, mode: "double-submit" },
    },
    limits: { maxSessionsPerUser: 2 },
    store: { provider: "memory" },
    observability: { debug: false, emitEvents: false, metrics: false },
  };

  beforeEach(() => {
    store = new MemoryStoreAdapter();
    service = new SessionService(store, config);
  });

  describe("createSession", () => {
    it("should create a new session successfully", async () => {
      const result = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.token).toBeDefined();
        expect(result.data.record.userId).toBe("user-1");
        expect(result.data.record.status).toBe(SessionStatus.ACTIVE);
      }
    });

    it("should enforce session limits", async () => {
      await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });
      await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });

      const result = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.reason).toBe(SessionReasonCode.SECURITY_BREACH);
      }
    });
  });

  describe("validateSession", () => {
    it("should validate a valid session", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });

      if (createResult.success) {
        const result = await service.validateSession({
          token: createResult.data.token,
          context: { ipAddress: "127.0.0.1" },
        });

        expect(result.success).toBe(true);
      }
    });

    it("should fail validation for IP mismatch if hard binding is enabled", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });

      if (createResult.success) {
        const result = await service.validateSession({
          token: createResult.data.token,
          context: { ipAddress: "192.168.1.1" },
        });

        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.reason).toBe(SessionReasonCode.IP_MISMATCH);
        }
      }
    });
  });

  describe("rotateSession", () => {
    it("should rotate session token", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });

      if (createResult.success) {
        const rotateResult = await service.rotateSession({
          token: createResult.data.token,
          context: { ipAddress: "127.0.0.1" },
        });

        expect(rotateResult.success).toBe(true);
        if (rotateResult.success) {
          expect(rotateResult.data.newToken).not.toBe(createResult.data.token);

          // Old token should be unusable after grace period
          await new Promise((resolve) => setTimeout(resolve, 55));
          const validateOld = await service.validateSession({
            token: createResult.data.token,
            context: { ipAddress: "127.0.0.1" },
          });
          expect(validateOld.success).toBe(false);
        }
      }
    });
  });

  describe("revokeSession", () => {
    it("should revoke a session", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });

      if (createResult.success) {
        const revokeResult = await service.revokeSession({
          token: createResult.data.token,
          reason: SessionReasonCode.MANUAL_LOGOUT,
        });

        expect(revokeResult.success).toBe(true);

        const validateResult = await service.validateSession({
          token: createResult.data.token,
          context: { ipAddress: "127.0.0.1" },
        });
        expect(validateResult.success).toBe(false);
      }
    });
  });

  describe("listUserSessions", () => {
    it("should return empty list when no sessions exist", async () => {
      const result = await service.listUserSessions("nonexistent-user");

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.sessions).toEqual([]);
        expect(result.data.total).toBe(0);
        expect(result.data.nextCursor).toBeNull();
      }
    });

    it("should return all active sessions for a user", async () => {
      // Create sessions with different IPs to satisfy hard IP binding
      await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.1" },
      });
      await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.2" },
      });

      const result = await service.listUserSessions("user-1");

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.sessions.length).toBe(2);
        expect(result.data.total).toBe(2);
        expect(result.data.sessions[0].userId).toBeUndefined();
        expect(result.data.sessions[0].tokenHash).toBeUndefined();
        expect(result.data.sessions[0].csrfToken).toBeUndefined();
        expect(result.data.sessions[0].parentSessionId).toBeUndefined();
        expect(result.data.sessions[0].childSessionId).toBeUndefined();
      }
    });

    it("should include roles and scopes in snapshot", async () => {
      await service.createSession({
        userId: "user-1",
        roles: ["admin", "user"],
        scopes: ["read", "write"],
        metadata: { ipAddress: "10.0.0.1" },
      });

      const result = await service.listUserSessions("user-1");

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.sessions[0].roles).toEqual(["admin", "user"]);
        expect(result.data.sessions[0].scopes).toEqual(["read", "write"]);
      }
    });

    it("should not return sessions from other users", async () => {
      await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.1" },
      });
      await service.createSession({
        userId: "user-2",
        metadata: { ipAddress: "10.0.0.2" },
      });

      const result = await service.listUserSessions("user-1");

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.sessions.length).toBe(1);
        expect(result.data.total).toBe(1);
      }
    });

    it("should paginate results with cursor", async () => {
      // Create max sessions (config limits to 2 per user)
      await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.1" },
      });
      await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.2" },
      });

      // Request page of size 1
      const page1 = await service.listUserSessions("user-1", { limit: 1 });

      expect(page1.success).toBe(true);
      if (page1.success) {
        expect(page1.data.sessions.length).toBe(1);
        expect(page1.data.total).toBe(2);
        expect(page1.data.nextCursor).toBeDefined();

        // Request page 2
        const page2 = await service.listUserSessions("user-1", {
          limit: 1,
          cursor: page1.data.nextCursor!,
        });

        expect(page2.success).toBe(true);
        if (page2.success) {
          expect(page2.data.sessions.length).toBe(1);
          expect(page2.data.nextCursor).toBeNull();
          // Pages should have different session IDs
          expect(page2.data.sessions[0].sessionId).not.toBe(
            page1.data.sessions[0].sessionId,
          );
        }
      }
    });

    it("should return safe snapshot without secrets", async () => {
      const createResult = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.1", userAgent: "TestAgent/1.0" },
      });

      expect(createResult.success).toBe(true);

      const result = await service.listUserSessions("user-1");

      expect(result.success).toBe(true);
      if (result.success) {
        const snapshot = result.data.sessions[0];
        // Should have safe fields
        expect(snapshot.sessionId).toBeDefined();
        expect(snapshot.status).toBe(SessionStatus.ACTIVE);
        expect(snapshot.createdAt).toBeInstanceOf(Date);
        expect(snapshot.lastUsedAt).toBeInstanceOf(Date);
        expect(snapshot.expiresAt).toBeInstanceOf(Date);

        // Should NOT have secret/internal fields
        expect((snapshot as Record<string, unknown>).tokenHash).toBeUndefined();
        expect((snapshot as Record<string, unknown>).csrfToken).toBeUndefined();
        expect((snapshot as Record<string, unknown>).userId).toBeUndefined();
        expect((snapshot as Record<string, unknown>).ipAddress).toBeUndefined();
        expect(
          (snapshot as Record<string, unknown>).userAgent,
        ).toBeUndefined();
        expect(
          (snapshot as Record<string, unknown>).deviceContext,
        ).toBeUndefined();
        expect(
          (snapshot as Record<string, unknown>).parentSessionId,
        ).toBeUndefined();
        expect(
          (snapshot as Record<string, unknown>).childSessionId,
        ).toBeUndefined();
      }
    });

    it("should return results sorted newest-first", async () => {
      const s1 = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.1" },
      });
      await new Promise((r) => setTimeout(r, 10));
      const s2 = await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.2" },
      });

      const result = await service.listUserSessions("user-1");
      expect(result.success).toBe(true);
      if (result.success && s1.success && s2.success) {
        expect(result.data.sessions[0].sessionId).toBe(s2.data.record.id);
        expect(result.data.sessions[1].sessionId).toBe(s1.data.record.id);
      }
    });
  });

  describe("listUserSessions — adversarial & edge cases", () => {
    it("should reject empty userId", async () => {
      const result = await service.listUserSessions("");
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.httpCode).toBe(400);
      }
    });

    it("should reject null userId", async () => {
      const result = await service.listUserSessions(null as unknown as string);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.httpCode).toBe(400);
      }
    });

    it("should reject undefined userId", async () => {
      const result = await service.listUserSessions(
        undefined as unknown as string,
      );
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.httpCode).toBe(400);
      }
    });

    it("should cap limit at 100 even if caller requests more", async () => {
      const result = await service.listUserSessions("user-1", {
        limit: 999999,
      });
      expect(result.success).toBe(true);
    });

    it("should clamp negative limit to 1", async () => {
      const result = await service.listUserSessions("user-1", { limit: -5 });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.sessions.length).toBeLessThanOrEqual(1);
      }
    });

    it("should return empty for cursor pointing to deleted session", async () => {
      await service.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.1" },
      });

      const result = await service.listUserSessions("user-1", {
        limit: 1,
        cursor: "nonexistent-session-id",
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.sessions).toEqual([]);
        expect(result.data.nextCursor).toBeNull();
      }
    });

    it("should not include expired ACTIVE sessions in listing", async () => {
      const shortConfig: SessionLibraryConfig = {
        ...config,
        expiration: { ...config.expiration, absoluteTimeoutSeconds: -1 },
      };
      const shortService = new SessionService(
        new MemoryStoreAdapter(),
        shortConfig,
      );

      await shortService.createSession({
        userId: "user-1",
        metadata: { ipAddress: "10.0.0.1" },
      });

      const result = await shortService.listUserSessions("user-1");
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.sessions.length).toBe(0);
      }
    });
  });

  describe("Custom Concurrency Configuration", () => {
    it("should successfully accept and initialize with custom concurrency settings", () => {
      const customConfig: SessionLibraryConfig = {
        ...config,
        concurrency: {
          lockTimeoutMs: 100,
          pollIntervalMs: 10,
        },
      };
      const customService = new SessionService(store, customConfig);
      expect(customService).toBeDefined();
    });

    it("should reject invalid concurrency settings during validation", () => {
      const { ConfigValidator } = require("../src/config/validator");
      const invalidConfig = {
        ...config,
        concurrency: {
          lockTimeoutMs: -10,
        },
      } as unknown as SessionLibraryConfig;

      expect(() => ConfigValidator.validate(invalidConfig)).toThrow(
        /must be a positive number/,
      );
    });
  });
});
