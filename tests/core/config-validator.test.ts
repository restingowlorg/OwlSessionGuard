import { ConfigValidator, FatalSecurityError } from "../../src/core/config-validator";
import { SessionLibraryConfig } from "../../src/types";

describe("ConfigValidator", () => {
  const getBaseConfig = (): SessionLibraryConfig => ({
    env: "production",
    transport: {
      mode: "cookie",
      cookie: {
        name: "session_id",
        httpOnly: true,
        secure: true,
        sameSite: "lax",
      },
    },
    expiration: { idleTimeoutSeconds: 3600, absoluteTimeoutSeconds: 86400, rolling: true },
    rotation: { gracePeriodSeconds: 10 },
    security: {
      enforceTlsInProduction: true,
      ipBinding: "hard",
      fingerprinting: "hard",
      csrf: { enabled: true },
    },
    limits: { maxSessionsPerUser: 3 },
    store: { provider: "memory" },
    observability: { debug: false, emitEvents: false, metrics: false },
  });

  describe("env validation", () => {
    it("should throw FatalSecurityError for invalid env value", () => {
      const config = getBaseConfig();
      (config as { env: string }).env = "staging";

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/Invalid environment/);
    });

    it("should accept valid env values", () => {
      for (const env of ["development", "test", "production"]) {
        const config = getBaseConfig();
        config.env = env as SessionLibraryConfig["env"];
        if (env !== "production" && config.transport.cookie) {
          config.transport.cookie.secure = false;
        }
        expect(() => ConfigValidator.validate(config)).not.toThrow();
      }
    });
  });

  describe("expiration validation", () => {
    it("should throw FatalSecurityError if idleTimeout > absoluteTimeout", () => {
      const config = getBaseConfig();
      config.expiration = { idleTimeoutSeconds: 90000, absoluteTimeoutSeconds: 3600, rolling: true };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/idleTimeoutSeconds/);
    });

    it("should not throw if idleTimeout equals absoluteTimeout", () => {
      const config = getBaseConfig();
      config.expiration = { idleTimeoutSeconds: 3600, absoluteTimeoutSeconds: 3600, rolling: true };

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });

    it("should not throw if idleTimeout < absoluteTimeout", () => {
      const config = getBaseConfig();
      config.expiration = { idleTimeoutSeconds: 1800, absoluteTimeoutSeconds: 3600, rolling: true };

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });
  });

  describe("store validation", () => {
    it("should throw FatalSecurityError if redis provider without url", () => {
      const config = getBaseConfig();
      config.store = { provider: "redis" };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/Redis/);
    });

    it("should throw FatalSecurityError if mongo provider without uri", () => {
      const config = getBaseConfig();
      config.store = { provider: "mongo" };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/MongoDB/);
    });

    it("should throw FatalSecurityError if postgres provider without url", () => {
      const config = getBaseConfig();
      config.store = { provider: "postgres" };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/PostgreSQL/);
    });

    it("should not throw if redis provider has url", () => {
      const config = getBaseConfig();
      config.store = { provider: "redis", redis: { url: "redis://localhost:6379" } };

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });
  });

  describe("concurrency validation", () => {
    it("should throw FatalSecurityError if lockTimeoutMs is not positive", () => {
      const config = getBaseConfig();
      config.concurrency = { lockTimeoutMs: 0 };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/lockTimeoutMs/);
    });

    it("should throw FatalSecurityError if pollIntervalMs is negative", () => {
      const config = getBaseConfig();
      config.concurrency = { pollIntervalMs: -10 };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/pollIntervalMs/);
    });

    it("should not throw if concurrency values are valid", () => {
      const config = getBaseConfig();
      config.concurrency = { lockTimeoutMs: 50, pollIntervalMs: 5 };

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });
  });

  describe("production cookie security", () => {
    it("should not throw if environment is not production", () => {
      const config = getBaseConfig();
      config.env = "development";
      if (config.transport.cookie) {
        config.transport.cookie.secure = false; // Insecure but allowed in dev
      }

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });

    it("should throw FatalSecurityError if production and cookie secure is false", () => {
      const config = getBaseConfig();
      if (config.transport.cookie) {
        config.transport.cookie.secure = false;
      }

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/transport\.cookie\.secure/);
    });

    it("should throw FatalSecurityError if production and sameSite is none but secure is false", () => {
      const config = getBaseConfig();
      if (config.transport.cookie) {
        config.transport.cookie.sameSite = "none";
        config.transport.cookie.secure = false;
      }

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/sameSite: none/);
    });

    it("should throw FatalSecurityError if production and httpOnly is false", () => {
      const config = getBaseConfig();
      if (config.transport.cookie) {
        config.transport.cookie.httpOnly = false;
      }

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/httpOnly/);
    });

    it("should throw FatalSecurityError if cookie mode but no cookie config", () => {
      const config = getBaseConfig();
      config.transport = { mode: "cookie" };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/cookie configuration/);
    });

    it("should not throw if production and secure is true", () => {
      const config = getBaseConfig();
      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });
  });

  describe("limits validation", () => {
    it("should throw FatalSecurityError if maxSessionsPerUser is zero", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 0 };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerUser/);
    });

    it("should throw FatalSecurityError if maxSessionsPerUser is negative", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: -1 };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerUser/);
    });

    it("should throw FatalSecurityError if maxSessionsPerUser is not an integer", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 2.5 };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerUser/);
    });

    it("should throw FatalSecurityError if role limit is zero", () => {
      const config = getBaseConfig();
      config.limits = {
        maxSessionsPerUser: 5,
        maxSessionsPerRole: { ADMIN: 0 },
      };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should throw FatalSecurityError if role limit is negative", () => {
      const config = getBaseConfig();
      config.limits = {
        maxSessionsPerUser: 5,
        maxSessionsPerRole: { ADMIN: -1 },
      };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should throw FatalSecurityError if role limit is not an integer", () => {
      const config = getBaseConfig();
      config.limits = {
        maxSessionsPerUser: 5,
        maxSessionsPerRole: { ADMIN: 1.5 },
      };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should not throw if role limits are valid positive integers", () => {
      const config = getBaseConfig();
      config.limits = {
        maxSessionsPerUser: 5,
        maxSessionsPerRole: { SUPER_ADMIN: 1, ADMIN: 2 },
      };

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });

    it("should not throw if maxSessionsPerRole is not provided", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 5 };

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });

    it("should reject null maxSessionsPerRole (fail closed)", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 5, maxSessionsPerRole: null as unknown as Record<string, number> };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should reject array maxSessionsPerRole (fail closed)", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 5, maxSessionsPerRole: [] as unknown as Record<string, number> };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should reject empty string role keys", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 5, maxSessionsPerRole: { "": 1 } };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should reject whitespace-only role keys", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 5, maxSessionsPerRole: { " ": 2 } };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should reject string maxSessionsPerRole (runtime garbage)", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 5, maxSessionsPerRole: "hello" as unknown as Record<string, number> };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should reject number maxSessionsPerRole (runtime garbage)", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 5, maxSessionsPerRole: 42 as unknown as Record<string, number> };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should reject boolean maxSessionsPerRole (runtime garbage)", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 5, maxSessionsPerRole: true as unknown as Record<string, number> };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });

    it("should reject non-numeric role limit values (runtime garbage)", () => {
      const config = getBaseConfig();
      config.limits = { maxSessionsPerUser: 5, maxSessionsPerRole: { ADMIN: "two" as unknown as number } };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/maxSessionsPerRole/);
    });
  });

  describe("Rotation Configuration", () => {
    it("should accept valid gracePeriodSeconds", () => {
      const config = getBaseConfig();
      config.rotation = { gracePeriodSeconds: 5 };

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });

    it("should accept zero gracePeriodSeconds", () => {
      const config = getBaseConfig();
      config.rotation = { gracePeriodSeconds: 0 };

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });

    it("should accept undefined gracePeriodSeconds (backward compat)", () => {
      const config = getBaseConfig();
      config.rotation = {};

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });

    it("should reject non-numeric gracePeriodSeconds", () => {
      const config = getBaseConfig();
      config.rotation = { gracePeriodSeconds: "30" as unknown as number };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/gracePeriodSeconds/);
    });

    it("should reject NaN gracePeriodSeconds", () => {
      const config = getBaseConfig();
      config.rotation = { gracePeriodSeconds: NaN };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/gracePeriodSeconds/);
    });

    it("should reject Infinity gracePeriodSeconds", () => {
      const config = getBaseConfig();
      config.rotation = { gracePeriodSeconds: Infinity };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/gracePeriodSeconds/);
    });

    it("should reject negative gracePeriodSeconds", () => {
      const config = getBaseConfig();
      config.rotation = { gracePeriodSeconds: -1 };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/gracePeriodSeconds/);
    });

    it("should reject gracePeriodSeconds exceeding safe maximum (30s)", () => {
      const config = getBaseConfig();
      config.rotation = { gracePeriodSeconds: 31 };

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/gracePeriodSeconds/);
    });

    it("should accept fractional gracePeriodSeconds (e.g., 0.5s)", () => {
      const config = getBaseConfig();
      config.rotation = { gracePeriodSeconds: 0.5 };

      expect(() => ConfigValidator.validate(config)).not.toThrow();
    });

    it("should reject rotation as a string (runtime garbage)", () => {
      const config = getBaseConfig();
      (config as any).rotation = "invalid";

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/rotation/);
    });

    it("should reject rotation as an array (runtime garbage)", () => {
      const config = getBaseConfig();
      (config as any).rotation = [30];

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/rotation/);
    });

    it("should reject rotation as a number (runtime garbage)", () => {
      const config = getBaseConfig();
      (config as any).rotation = 30;

      expect(() => ConfigValidator.validate(config)).toThrow(FatalSecurityError);
      expect(() => ConfigValidator.validate(config)).toThrow(/rotation/);
    });
  });
});
