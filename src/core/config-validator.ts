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
    this.validateStore(config);
    this.validateConcurrency(config);

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
