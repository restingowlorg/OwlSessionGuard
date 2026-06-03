import { SessionLibraryConfig } from "../types";

export class FatalSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FatalSecurityError";
  }
}

/**
 * ConfigValidator ensures that the session library is instantiated with secure configurations,
 * particularly enforcing strict constraints in production environments.
 */
export class ConfigValidator {
  public static validate(config: SessionLibraryConfig): void {
    if (config.env === "production") {
      this.validateProductionConstraints(config);
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
          "Cookie transport mode is enabled but no cookie configuration is provided.",
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
