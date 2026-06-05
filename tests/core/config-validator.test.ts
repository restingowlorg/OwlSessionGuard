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

  it("should not throw if production and secure is true", () => {
    const config = getBaseConfig();
    expect(() => ConfigValidator.validate(config)).not.toThrow();
  });
});
