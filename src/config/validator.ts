import { SessionLibraryConfig } from "../types";

/**
 * ConfigValidator — Ensures the session library configuration is secure and valid.
 */
export class ConfigValidator {
  /**
   * Validates the configuration and throws error or logs warnings if insecure.
   */
  public static validate(config: SessionLibraryConfig): void {
    const errors: string[] = [];
    const warnings: string[] = [];

    // 1. Environment Validation
    if (!["development", "test", "production"].includes(config.env)) {
      errors.push(
        `Invalid environment: ${config.env}. Must be 'development', 'test', or 'production'.`,
      );
    }

    // 2. Production Security Hardening
    if (config.env === "production") {
      // TLS Enforcement
      if (
        config.security.enforceTlsInProduction &&
        config.transport.mode === "cookie"
      ) {
        if (config.transport.cookie && !config.transport.cookie.secure) {
          errors.push(
            "Production Error: Cookies must be 'secure=true' when 'enforceTlsInProduction' is enabled.",
          );
        }
      }

      // HttpOnly Enforcement
      if (config.transport.cookie && !config.transport.cookie.httpOnly) {
        warnings.push(
          "Security Warning: 'httpOnly' is disabled in production. This increases risk of XSS-based session theft.",
        );
      }

      // SameSite Check
      if (
        config.transport.cookie &&
        config.transport.cookie.sameSite === "none" &&
        !config.transport.cookie.secure
      ) {
        errors.push(
          "Production Error: 'SameSite=None' requires 'Secure=true'.",
        );
      }
    }

    // 3. Expiration Logic
    if (
      config.expiration.idleTimeoutSeconds >
      config.expiration.absoluteTimeoutSeconds
    ) {
      errors.push(
        "Config Error: 'idleTimeoutSeconds' cannot be greater than 'absoluteTimeoutSeconds'.",
      );
    }

    // 4. Store Validation
    if (config.store.provider === "redis" && !config.store.redis?.url) {
      errors.push(
        "Config Error: Redis URL is required when store provider is 'redis'.",
      );
    }

    if (config.store.provider === "mongo" && !config.store.mongo?.uri) {
      errors.push(
        "Config Error: MongoDB URI is required when store provider is 'mongo'.",
      );
    }

    if (config.store.provider === "postgres" && !config.store.postgres?.url) {
      errors.push(
        "Config Error: PostgreSQL URL is required when store provider is 'postgres'.",
      );
    }

    // Report results
    if (warnings.length > 0) {
      warnings.forEach((w) => console.warn(`[@ossec/auth] ${w}`));
    }

    if (errors.length > 0) {
      throw new Error(
        `[@ossec/auth] Configuration validation failed:\n- ${errors.join("\n- ")}`,
      );
    }
  }

  /**
   * Deep merges user config with defaults.
   */
  public static merge(
    defaults: Record<string, unknown>,
    userConfig: Record<string, unknown>,
  ): SessionLibraryConfig {
    const merged: Record<string, unknown> = { ...defaults, ...userConfig };

    // Deep merge nested objects
    Object.keys(defaults).forEach((key) => {
      const defaultValue = defaults[key];
      const userValue = userConfig[key];

      if (
        defaultValue &&
        typeof defaultValue === "object" &&
        !Array.isArray(defaultValue)
      ) {
        merged[key] = {
          ...(defaultValue as Record<string, unknown>),
          ...((userValue as Record<string, unknown>) || {}),
        };
      }
    });

    return merged as unknown as SessionLibraryConfig;
  }
}
