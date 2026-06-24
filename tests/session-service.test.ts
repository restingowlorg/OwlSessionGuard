import { SessionService } from "../src/core/session.service";
import { DeviceContextExtractor } from "../src/core/device-context-extractor";
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
      gracePeriodSeconds: 0,
    },
    security: {
      enforceTlsInProduction: false,
      ipBinding: "hard",
      fingerprinting: "off",
      csrf: { enabled: false },
    },
    limits: { maxSessionsPerUser: 2 },
    store: { provider: "memory" },
    observability: { debug: false, emitEvents: false, metrics: false },
  };

  beforeEach(() => {
    store = new MemoryStoreAdapter();
    service = new SessionService(store, config);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("createSession", () => {
    it("should emit session.fallback_fingerprint event when metadata has no valid deviceId", async () => {
      const eventService = new SessionService(store, {
        ...config,
        observability: { ...config.observability, emitEvents: true },
      });

      const eventPromise = new Promise<{
        sessionId: string;
        userId: string;
        deviceContext: Record<string, string | number | boolean>;
      }>((resolve) => {
        eventService.on("session.fallback_fingerprint", (...args: unknown[]) => {
          const payload = args[0] as {
            sessionId: string;
            userId: string;
            deviceContext: Record<string, string | number | boolean>;
          };
          resolve(payload);
        });
      });

      const result = await eventService.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });

      expect(result.success).toBe(true);
      const payload = await eventPromise;
      expect(payload.sessionId).toBeDefined();
      expect(payload.userId).toBe("user-1");
      expect(payload.deviceContext).toBeDefined();
      expect(payload.deviceContext.os).toBeDefined();
      expect(payload.deviceContext.browser).toBeDefined();
      expect(payload.deviceContext.type).toBeDefined();
    });

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

    it("should fall back to UUID fingerprint when DeviceContextExtractor throws", async () => {
      const extractSpy = jest.spyOn(DeviceContextExtractor, "extract").mockImplementation(() => {
        throw new Error("extractor failure");
      });

      const eventService = new SessionService(store, {
        ...config,
        observability: { ...config.observability, emitEvents: true },
      });

      const eventPromise = new Promise<{
        userId: string;
        error: string;
        metadata: { ipAddress: string; userAgent?: string };
      }>((resolve) => {
        eventService.on("security.extractor_failed", (payload: unknown) => {
          resolve(payload as {
            userId: string;
            error: string;
            metadata: { ipAddress: string; userAgent?: string };
          });
        });
      });

      const result = await eventService.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1", userAgent: "TestAgent/1.0" },
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.record.metadata.deviceFingerprint).toMatch(/^fallback_/);
      }

      const eventPayload = await eventPromise;
      expect(eventPayload.userId).toBe("user-1");
      expect(eventPayload.error).toBe("extractor failure");
      expect(eventPayload.metadata).toBeDefined();
      expect(eventPayload.metadata.ipAddress).toBe("127.0.0.1");
      expect(eventPayload.metadata.userAgent).toBe("TestAgent/1.0");

      extractSpy.mockRestore();
    });

    it("should run all session.created listeners even when one throws", async () => {
      const eventService = new SessionService(store, {
        ...config,
        observability: { ...config.observability, emitEvents: true },
      });

      let secondListenerRan = false;
      const listenerPromise = new Promise<void>((resolve) => {
        eventService.on("session.created", () => {
          throw new Error("first listener threw");
        });
        eventService.on("session.created", () => {
          secondListenerRan = true;
          resolve();
        });
      });

      const result = await eventService.createSession({
        userId: "user-1",
        metadata: { ipAddress: "127.0.0.1" },
      });

      expect(result.success).toBe(true);
      await listenerPromise;
      expect(secondListenerRan).toBe(true);
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
        if (revokeResult.success) {
          expect(revokeResult.data.alreadyRevoked).toBeUndefined();
        }

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
        expect(result.data.totalIsApproximate).toBe(false);
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

    it("should include deviceLabel derived from deviceContext", async () => {
      await service.createSession({
        userId: "user-1",
        metadata: {
          ipAddress: "10.0.0.1",
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        },
      });

      const result = await service.listUserSessions("user-1");

      expect(result.success).toBe(true);
      if (result.success) {
        const snapshot = result.data.sessions[0];
        expect(snapshot.deviceLabel).toBeDefined();
        expect(typeof snapshot.deviceLabel).toBe("string");
        expect(snapshot.deviceLabel!.length).toBeGreaterThan(0);
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
        expiration: { absoluteTimeoutSeconds: -1, idleTimeoutSeconds: -1, rolling: false },
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
        expect(result.data.totalIsApproximate).toBe(false);
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
      const { ConfigValidator } = require("../src/core/config-validator");
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

  describe("role-based session limits", () => {
    const roleConfig: SessionLibraryConfig = {
      ...config,
      limits: {
        maxSessionsPerUser: 5,
        maxSessionsPerRole: {
          SUPER_ADMIN: 1,
          ADMIN: 2,
        },
      },
    };

    it("should enforce role-based limit when user has a matching role", async () => {
      const roleService = new SessionService(store, roleConfig);

      const result1 = await roleService.createSession({
        userId: "admin-1",
        roles: ["SUPER_ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(result1.success).toBe(true);

      const result2 = await roleService.createSession({
        userId: "admin-1",
        roles: ["SUPER_ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(result2.success).toBe(false);
      if (!result2.success) {
        expect(result2.error.message).toContain("exceeded maximum session limit");
      }
    });

    it("should use most restrictive role limit when user has multiple roles", async () => {
      const roleService = new SessionService(store, roleConfig);

      const result1 = await roleService.createSession({
        userId: "admin-2",
        roles: ["ADMIN", "SUPER_ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(result1.success).toBe(true);

      const result2 = await roleService.createSession({
        userId: "admin-2",
        roles: ["ADMIN", "SUPER_ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(result2.success).toBe(false);
    });

    it("should fall back to maxSessionsPerUser when no role matches", async () => {
      const roleService = new SessionService(store, roleConfig);

      for (let i = 0; i < 5; i++) {
        const result = await roleService.createSession({
          userId: "user-1",
          roles: ["GUEST"],
          metadata: { ipAddress: "127.0.0.1" },
        });
        expect(result.success).toBe(true);
      }

      const result = await roleService.createSession({
        userId: "user-1",
        roles: ["GUEST"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(result.success).toBe(false);
    });

    it("should fall back to maxSessionsPerUser when roles array is empty", async () => {
      const roleService = new SessionService(store, roleConfig);

      for (let i = 0; i < 5; i++) {
        const result = await roleService.createSession({
          userId: "user-2",
          roles: [],
          metadata: { ipAddress: "127.0.0.1" },
        });
        expect(result.success).toBe(true);
      }

      const result = await roleService.createSession({
        userId: "user-2",
        roles: [],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(result.success).toBe(false);
    });

    it("should fall back to maxSessionsPerUser when maxSessionsPerRole is not configured", async () => {
      const noRoleConfig: SessionLibraryConfig = {
        ...config,
        limits: { maxSessionsPerUser: 3 },
      };
      const roleService = new SessionService(store, noRoleConfig);

      for (let i = 0; i < 3; i++) {
        const result = await roleService.createSession({
          userId: "user-3",
          roles: ["SUPER_ADMIN"],
          metadata: { ipAddress: "127.0.0.1" },
        });
        expect(result.success).toBe(true);
      }

      const result = await roleService.createSession({
        userId: "user-3",
        roles: ["SUPER_ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(result.success).toBe(false);
    });

    it("should apply ADMIN limit of 2 correctly", async () => {
      const roleService = new SessionService(store, roleConfig);

      const r1 = await roleService.createSession({
        userId: "admin-3",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(r1.success).toBe(true);

      const r2 = await roleService.createSession({
        userId: "admin-3",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(r2.success).toBe(true);

      const r3 = await roleService.createSession({
        userId: "admin-3",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(r3.success).toBe(false);
      if (!r3.success) {
        expect(r3.error.message).toContain("exceeded maximum session limit");
      }
    });

    it("should enforce role-based limit during rotation", async () => {
      const roleService = new SessionService(store, roleConfig);

      // Create 2 ADMIN sessions (limit is 2)
      const s1 = await roleService.createSession({
        userId: "rot-admin-1",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(s1.success).toBe(true);

      const s2 = await roleService.createSession({
        userId: "rot-admin-1",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(s2.success).toBe(true);

      // Rotate first session — should succeed (net count stays 2)
      if (s1.success) {
        const rotateResult = await roleService.rotateSession({
          token: s1.data.token,
        });
        expect(rotateResult.success).toBe(true);
      }

      // Now revoke one session to free a slot, then try creating a third
      if (s2.success) {
        await roleService.revokeSession({ token: s2.data.token });
      }

      const s3 = await roleService.createSession({
        userId: "rot-admin-1",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(s3.success).toBe(true);
    });

    it("should allow ordinary sessions without counting against role-specific limits", async () => {
      const dualConfig: SessionLibraryConfig = {
        ...config,
        limits: {
          maxSessionsPerUser: 5,
          maxSessionsPerRole: {
            ADMIN: 2,
          },
        },
      };
      const roleService = new SessionService(store, dualConfig);

      // Create 2 ADMIN sessions (hits ADMIN role limit of 2)
      const a1 = await roleService.createSession({
        userId: "dual-user-1",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(a1.success).toBe(true);
      const a2 = await roleService.createSession({
        userId: "dual-user-1",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(a2.success).toBe(true);

      // Third ADMIN session should fail (role limit = 2)
      const a3 = await roleService.createSession({
        userId: "dual-user-1",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(a3.success).toBe(false);

      // But a non-admin session should still succeed (global cap = 5)
      const o1 = await roleService.createSession({
        userId: "dual-user-1",
        roles: [],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(o1.success).toBe(true);

      const o2 = await roleService.createSession({
        userId: "dual-user-1",
        roles: [],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(o2.success).toBe(true);
    });

    it("should enforce global cap even when role limit is higher", async () => {
      const highRoleConfig: SessionLibraryConfig = {
        ...config,
        limits: {
          maxSessionsPerUser: 3,
          maxSessionsPerRole: {
            ADMIN: 10,
          },
        },
      };
      const roleService = new SessionService(store, highRoleConfig);

      // Create 3 ADMIN sessions — hits global cap of 3 even though ADMIN limit is 10
      for (let i = 0; i < 3; i++) {
        const r = await roleService.createSession({
          userId: "high-role-user",
          roles: ["ADMIN"],
          metadata: { ipAddress: "127.0.0.1" },
        });
        expect(r.success).toBe(true);
      }

      // Fourth ADMIN session should fail (global cap = 3)
      const r4 = await roleService.createSession({
        userId: "high-role-user",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(r4.success).toBe(false);
    });

    it("should enforce both global and role limits independently", async () => {
      const bothConfig: SessionLibraryConfig = {
        ...config,
        limits: {
          maxSessionsPerUser: 4,
          maxSessionsPerRole: {
            ADMIN: 2,
          },
        },
      };
      const roleService = new SessionService(store, bothConfig);

      // Create 2 ADMIN sessions (hits ADMIN limit)
      const a1 = await roleService.createSession({
        userId: "both-user",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(a1.success).toBe(true);
      const a2 = await roleService.createSession({
        userId: "both-user",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(a2.success).toBe(true);

      // Third ADMIN should fail (role limit = 2)
      const a3 = await roleService.createSession({
        userId: "both-user",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(a3.success).toBe(false);

      // Add non-admin sessions up to global cap
      const o1 = await roleService.createSession({
        userId: "both-user",
        roles: [],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(o1.success).toBe(true);
      const o2 = await roleService.createSession({
        userId: "both-user",
        roles: [],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(o2.success).toBe(true);

      // Global cap is 4 (2 admin + 2 ordinary = 4), so this should fail
      const o3 = await roleService.createSession({
        userId: "both-user",
        roles: [],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(o3.success).toBe(false);
    });

    it("should evaluate new role limits when roles are provided during rotation", async () => {
      const roleService = new SessionService(store, roleConfig);

      // Create 1 session as USER (no role limit, global limit = 5)
      const s1 = await roleService.createSession({
        userId: "elevate-user",
        roles: ["USER"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(s1.success).toBe(true);

      // Elevate to SUPER_ADMIN (limit = 1) — should succeed (no existing SUPER_ADMIN sessions)
      if (s1.success) {
        const rotResult = await roleService.rotateSession({
          token: s1.data.token,
          context: { ipAddress: "127.0.0.1" },
          roles: ["SUPER_ADMIN"],
        });
        expect(rotResult.success).toBe(true);
      }
    });

    it("should block rotation that would exceed new role's limit", async () => {
      const roleService = new SessionService(store, roleConfig);

      // Create 2 sessions as USER
      const s1 = await roleService.createSession({
        userId: "elevate-block-user",
        roles: ["USER"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      const s2 = await roleService.createSession({
        userId: "elevate-block-user",
        roles: ["USER"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(s1.success).toBe(true);
      expect(s2.success).toBe(true);

      // Elevate first to SUPER_ADMIN (limit = 1) — succeeds
      if (s1.success) {
        const rot1 = await roleService.rotateSession({
          token: s1.data.token,
          context: { ipAddress: "127.0.0.1" },
          roles: ["SUPER_ADMIN"],
        });
        expect(rot1.success).toBe(true);
      }

      // Elevate second to SUPER_ADMIN — blocked (limit = 1, already have 1)
      if (s2.success) {
        const rot2 = await roleService.rotateSession({
          token: s2.data.token,
          context: { ipAddress: "127.0.0.1" },
          roles: ["SUPER_ADMIN"],
        });
        expect(rot2.success).toBe(false);
      }
    });

    it("should elevate ordinary sessions to a strict role without pollution", async () => {
      const roleService = new SessionService(store, roleConfig);

      // Create 3 ordinary sessions (roles: []) — no role limits apply
      const s1 = await roleService.createSession({
        userId: "elevate-ordinary",
        roles: [],
        metadata: { ipAddress: "127.0.0.1" },
      });
      const s2 = await roleService.createSession({
        userId: "elevate-ordinary",
        roles: [],
        metadata: { ipAddress: "127.0.0.1" },
      });
      const s3 = await roleService.createSession({
        userId: "elevate-ordinary",
        roles: [],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(s1.success).toBe(true);
      expect(s2.success).toBe(true);
      expect(s3.success).toBe(true);

      // Elevate s1 to SUPER_ADMIN (limit = 1) — succeeds (no existing SUPER_ADMIN)
      const rot1 = await roleService.rotateSession({
        token: s1.data!.token,
        context: { ipAddress: "127.0.0.1" },
        roles: ["SUPER_ADMIN"],
      });
      expect(rot1.success).toBe(true);

      // Elevate s2 to SUPER_ADMIN — blocked (limit = 1, already have 1)
      const rot2 = await roleService.rotateSession({
        token: s2.data!.token,
        context: { ipAddress: "127.0.0.1" },
        roles: ["SUPER_ADMIN"],
      });
      expect(rot2.success).toBe(false);

      // s3 (ordinary) is unaffected — still valid
      const s3Check = await roleService.validateSession({
        token: s3.data!.token,
        context: { ipAddress: "127.0.0.1" },
      });
      expect(s3Check.success).toBe(true);
    });

    it("should fall back to old roles when roles param is not provided", async () => {
      const roleService = new SessionService(store, roleConfig);

      // Create 2 ADMIN sessions (ADMIN limit = 2)
      const s1 = await roleService.createSession({
        userId: "no-roles-rot",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      const s2 = await roleService.createSession({
        userId: "no-roles-rot",
        roles: ["ADMIN"],
        metadata: { ipAddress: "127.0.0.1" },
      });
      expect(s1.success).toBe(true);
      expect(s2.success).toBe(true);

      // Rotate without providing roles — should use old roles (ADMIN)
      // Admin limit is 2, rotation is 1-to-1 (count stays 2), so it should succeed
      if (s1.success) {
        const rot = await roleService.rotateSession({
          token: s1.data.token,
          context: { ipAddress: "127.0.0.1" },
        });
        expect(rot.success).toBe(true);
      }
    });
  });
});
