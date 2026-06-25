import { SessionLibraryConfig } from "../types";

export class FatalSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FatalSecurityError";
  }
}

/**
 * ConfigValidator ensures that the session library is instantiated with valid and secure
 * configurations. It enforces structural correctness (env, expiration, store, concurrency)
 * and strict security constraints in production environments.
 */
export class ConfigValidator {
  public static validate(config: SessionLibraryConfig): void {
    this.validateEnv(config);
    this.validateExpiration(config);
    this.validateLimits(config);
    this.validateStore(config);
    this.validateConcurrency(config);
    this.validateRotation(config);
    this.validateDeviceConfig(config);

    if (config.env === "production") {
      this.validateProductionConstraints(config);
    }
  }

  private static validateEnv(config: SessionLibraryConfig): void {
    const validEnvs = ["development", "test", "production"];
    if (!validEnvs.includes(config.env)) {
      throw new FatalSecurityError(
        `Invalid environment: '${config.env}'. ` +
          `Must be one of: ${validEnvs.join(", ")}.` +
          "\n[REMEDIATION]: Set 'config.env' to a valid value.",
      );
    }
  }

  private static validateExpiration(config: SessionLibraryConfig): void {
    const { idleTimeoutSeconds, absoluteTimeoutSeconds } = config.expiration;

    if (idleTimeoutSeconds > absoluteTimeoutSeconds) {
      throw new FatalSecurityError(
        "CONFIGURATION ERROR: 'idleTimeoutSeconds' cannot be greater than 'absoluteTimeoutSeconds'.\n" +
          `Received: idleTimeout=${idleTimeoutSeconds}s, absoluteTimeout=${absoluteTimeoutSeconds}s.\n` +
          "[REMEDIATION]: Set 'idleTimeoutSeconds' to a value less than or equal to 'absoluteTimeoutSeconds'.",
      );
    }
  }

  private static validateLimits(config: SessionLibraryConfig): void {
    const { maxSessionsPerUser, maxSessionsPerRole } = config.limits;

    if (maxSessionsPerUser <= 0 || !Number.isInteger(maxSessionsPerUser)) {
      throw new FatalSecurityError(
        "CONFIGURATION ERROR: 'limits.maxSessionsPerUser' must be a positive integer.\n" +
          `[REMEDIATION]: Set 'config.limits.maxSessionsPerUser' to an integer >= 1 (received: ${maxSessionsPerUser}).`,
      );
    }

    if (maxSessionsPerRole !== undefined) {
      if (
        maxSessionsPerRole === null ||
        typeof maxSessionsPerRole !== "object" ||
        Array.isArray(maxSessionsPerRole)
      ) {
        throw new FatalSecurityError(
          "CONFIGURATION ERROR: 'limits.maxSessionsPerRole' must be a plain object (Record<string, number>).\n" +
            `[REMEDIATION]: Set 'config.limits.maxSessionsPerRole' to an object like { "ADMIN": 2 } (received: ${maxSessionsPerRole === null ? "null" : typeof maxSessionsPerRole}).`,
        );
      }

      for (const [role, limit] of Object.entries(maxSessionsPerRole)) {
        if (!role || role.trim() === "") {
          throw new FatalSecurityError(
            "CONFIGURATION ERROR: 'limits.maxSessionsPerRole' contains an empty or whitespace-only role key.\n" +
              "[REMEDIATION]: Remove empty role keys or set them to valid non-empty strings.",
          );
        }

        if (limit <= 0 || !Number.isInteger(limit)) {
          throw new FatalSecurityError(
            `CONFIGURATION ERROR: 'limits.maxSessionsPerRole["${role}"]' must be a positive integer.\n` +
              `[REMEDIATION]: Set 'config.limits.maxSessionsPerRole["${role}"]' to an integer >= 1 (received: ${limit}).`,
          );
        }
      }
    }
  }

  private static validateStore(config: SessionLibraryConfig): void {
    const { provider } = config.store;

    if (provider === "redis" && !config.store.redis?.url) {
      throw new FatalSecurityError(
        "CONFIGURATION ERROR: Redis store provider requires a URL.\n" +
          "[REMEDIATION]: Set 'config.store.redis.url' to your Redis connection string.",
      );
    }

    if (provider === "mongo" && !config.store.mongo?.uri) {
      throw new FatalSecurityError(
        "CONFIGURATION ERROR: MongoDB store provider requires a URI.\n" +
          "[REMEDIATION]: Set 'config.store.mongo.uri' to your MongoDB connection string.",
      );
    }

    if (provider === "postgres" && !config.store.postgres?.url) {
      throw new FatalSecurityError(
        "CONFIGURATION ERROR: PostgreSQL store provider requires a URL.\n" +
          "[REMEDIATION]: Set 'config.store.postgres.url' to your PostgreSQL connection string.",
      );
    }
  }

  private static validateConcurrency(config: SessionLibraryConfig): void {
    const { concurrency } = config;
    if (!concurrency) return;

    if (
      concurrency.lockTimeoutMs !== undefined &&
      (typeof concurrency.lockTimeoutMs !== "number" ||
        concurrency.lockTimeoutMs <= 0)
    ) {
      throw new FatalSecurityError(
        "CONFIGURATION ERROR: 'concurrency.lockTimeoutMs' must be a positive number.\n" +
          `[REMEDIATION]: Set 'config.concurrency.lockTimeoutMs' to a value greater than 0 (received: ${concurrency.lockTimeoutMs}).`,
      );
    }

    if (
      concurrency.pollIntervalMs !== undefined &&
      (typeof concurrency.pollIntervalMs !== "number" ||
        concurrency.pollIntervalMs <= 0)
    ) {
      throw new FatalSecurityError(
        "CONFIGURATION ERROR: 'concurrency.pollIntervalMs' must be a positive number.\n" +
          `[REMEDIATION]: Set 'config.concurrency.pollIntervalMs' to a value greater than 0 (received: ${concurrency.pollIntervalMs}).`,
      );
    }
  }

  // WHY: 30-second safe maximum. OWASP recommends immediate invalidation on rotation,
  // but industry implementations (Okta: 0-60s default 30s, Auth0: reuse interval)
  // use a short grace window to handle legitimate concurrency (network retries,
  // in-flight requests). 30s is the conservative upper bound — beyond this, the
  // replay attack surface outweighs the usability benefit.
  private static readonly SAFE_GRACE_PERIOD_SECONDS = 30;

  private static validateRotation(config: SessionLibraryConfig): void {
    const { rotation } = config;
    if (rotation === undefined) return;

    if (
      rotation === null ||
      typeof rotation !== "object" ||
      Array.isArray(rotation)
    ) {
      throw new FatalSecurityError(
        "CONFIGURATION ERROR: 'rotation' must be a plain object.\n" +
          `[REMEDIATION]: Set 'config.rotation' to an object like { "gracePeriodSeconds": 5 } (received: ${rotation === null ? "null" : typeof rotation}).`,
      );
    }

    const { gracePeriodSeconds } = rotation;

    if (gracePeriodSeconds !== undefined) {
      if (typeof gracePeriodSeconds !== "number") {
        throw new FatalSecurityError(
          "CONFIGURATION ERROR: 'rotation.gracePeriodSeconds' must be a number.\n" +
            `[REMEDIATION]: Set 'config.rotation.gracePeriodSeconds' to a number in seconds (received: ${typeof gracePeriodSeconds}).`,
        );
      }

      if (!Number.isFinite(gracePeriodSeconds)) {
        throw new FatalSecurityError(
          "CONFIGURATION ERROR: 'rotation.gracePeriodSeconds' must be a finite number.\n" +
            `[REMEDIATION]: Set 'config.rotation.gracePeriodSeconds' to a finite number (received: ${gracePeriodSeconds}).`,
        );
      }

      if (gracePeriodSeconds < 0) {
        throw new FatalSecurityError(
          "CONFIGURATION ERROR: 'rotation.gracePeriodSeconds' cannot be negative.\n" +
            `[REMEDIATION]: Set 'config.rotation.gracePeriodSeconds' to a value >= 0 (received: ${gracePeriodSeconds}).`,
        );
      }

      if (gracePeriodSeconds > this.SAFE_GRACE_PERIOD_SECONDS) {
        throw new FatalSecurityError(
          `CONFIGURATION ERROR: 'rotation.gracePeriodSeconds' exceeds safe maximum of ${this.SAFE_GRACE_PERIOD_SECONDS}s.\n` +
            `[REMEDIATION]: Set 'config.rotation.gracePeriodSeconds' to a value <= ${this.SAFE_GRACE_PERIOD_SECONDS} (received: ${gracePeriodSeconds}).`,
        );
      }
    }
  }

  private static validateDeviceConfig(config: SessionLibraryConfig): void {
    const { device } = config;
    if (!device || !device.enabled) return;

    // WHY: When device identification is enabled, a cookie name must be
    // explicitly provided to avoid silent collision with other cookies.
    if (device.cookie?.name !== undefined && device.cookie.name.trim() === "") {
      throw new FatalSecurityError(
        "CONFIGURATION ERROR: 'device.cookie.name' must be a non-empty string when device identification is enabled.\n" +
          "[REMEDIATION]: Set 'config.device.cookie.name' to a valid cookie name (e.g. 'device_id').",
      );
    }

    // WHY: Enforce SameSite=None requires Secure=true for device cookie,
    // same constraint as session cookie in production. Prevents silent
    // browser rejection of the device cookie.
    if (device.cookie?.sameSite === "none" && device.cookie?.secure !== true) {
      throw new FatalSecurityError(
        "INSECURE CONFIGURATION DETECTED: \n" +
          "Device cookie has 'sameSite: none' but 'secure' is not set to true.\n" +
          "Modern browsers will reject this cookie entirely.\n" +
          "[REMEDIATION]: Set 'device.cookie.secure' to true when using 'device.cookie.sameSite: none'.",
      );
    }
  }

  private static validateProductionConstraints(
    config: SessionLibraryConfig,
  ): void {
    const transportMode = config.transport.mode;

    if (transportMode === "cookie" || transportMode === "hybrid") {
      const cookieConfig = config.transport.cookie;
      if (!cookieConfig) {
        throw new FatalSecurityError(
          "CONFIGURATION ERROR: Cookie transport mode is enabled but no cookie configuration is provided.\n" +
            "[REMEDIATION]: Add 'config.transport.cookie' with at least 'name', 'httpOnly', 'secure', and 'sameSite' properties.",
        );
      }

      if (cookieConfig.sameSite === "none" && cookieConfig.secure !== true) {
        throw new FatalSecurityError(
          "INSECURE CONFIGURATION DETECTED: \n" +
            "You are running in 'production' environment with 'sameSite: none' but 'secure' is false.\n" +
            "Modern browsers will reject this cookie entirely.\n" +
            "[REMEDIATION]: Set 'transport.cookie.secure' to true when using 'sameSite: none'.",
        );
      }

      if (cookieConfig.secure !== true) {
        throw new FatalSecurityError(
          "INSECURE CONFIGURATION DETECTED: \n" +
            "You are running in 'production' environment but 'transport.cookie.secure' is not set to true.\n" +
            "This means session cookies could be transmitted over unencrypted HTTP connections, exposing them to interception.\n" +
            "[REMEDIATION]: Ensure your application is served over HTTPS and update 'config.transport.cookie.secure' to true.",
        );
      }

      if (cookieConfig.httpOnly !== true) {
        throw new FatalSecurityError(
          "INSECURE CONFIGURATION DETECTED: \n" +
            "You are running in 'production' environment but 'transport.cookie.httpOnly' is not set to true.\n" +
            "This allows client-side JavaScript to read the session cookie, exposing it to Cross-Site Scripting (XSS) attacks.\n" +
            "[REMEDIATION]: Update 'config.transport.cookie.httpOnly' to true.",
        );
      }
    }
  }
}
