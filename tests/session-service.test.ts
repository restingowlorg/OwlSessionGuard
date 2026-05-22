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
