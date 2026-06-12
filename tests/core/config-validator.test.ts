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
    rotation: { rotateOnLogin: true, rotateOnPrivilegeChange: true, gracePeriodSeconds: 300 },
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
});
