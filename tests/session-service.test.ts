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
      rotateOnLogin: true,
      rotateOnPrivilegeChange: true,
      gracePeriodSeconds: 300,
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
});
