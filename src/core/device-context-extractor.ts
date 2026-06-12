import { v4 as uuidv4 } from "uuid";
import {
  DeviceOS,
  DeviceBrowser,
  DeviceType,
  SessionMetadata,
  ResolvedDeviceContext,
  FALLBACK_FP_PREFIX,
} from "../types";

export class DeviceContextExtractor {
  /**
   * Extracts device context safely with runtime type checking.
   *
   * @param metadata The incoming session metadata
   * @returns The resolved device fingerprint and extracted context
   */
  public static extract(
    metadata: SessionMetadata | undefined | null,
  ): ResolvedDeviceContext {
    // 1. Defend the runtime boundary. If metadata is missing, return safe defaults.
    if (!metadata || typeof metadata !== "object") {
      return {
        deviceFingerprint: `${FALLBACK_FP_PREFIX}${uuidv4()}`,
        deviceContext: {
          os: DeviceOS.UNKNOWN,
          browser: DeviceBrowser.UNKNOWN,
          type: DeviceType.UNKNOWN,
        },
      };
    }

    // 2. Resolve Device Fingerprint (OWASP Gold Standard)
    // WHY: Inline the condition in the ternary (not via an intermediate boolean variable)
    // because TypeScript doesn't narrow through const booleans — isDeviceIdValid would be
    // typed as `boolean`, not as a type guard, so metadata.deviceId stays `string | undefined`
    // in the true branch and triggers TS2322.
    const fingerprint =
      typeof metadata.deviceId === "string" &&
      metadata.deviceId.length > 0 &&
      metadata.deviceId.length <= 512
        ? metadata.deviceId
        : `${FALLBACK_FP_PREFIX}${uuidv4()}`;

    // 3. Orchestrate parsing and sanitization
    const parsedContext = DeviceContextExtractor.parseUserAgent(
      metadata.userAgent,
    );
    const sanitizedInjected = DeviceContextExtractor.sanitizeInjectedContext(
      metadata.deviceContext,
    );

    // WHY: Spread order is intentional — parsedContext (os/browser/type from User-Agent)
    // is spread LAST so it always overwrites any consumer-injected os/browser/type values.
    // If a consumer passes { deviceContext: { os: "Linux" } } but their User-Agent says
    // Windows, the library's parsed value wins. This prevents device context spoofing
    // via consumer-injected metadata and ensures the record reflects the actual HTTP client.
    return {
      deviceFingerprint: fingerprint,
      deviceContext: {
        ...sanitizedInjected,
        ...parsedContext,
      },
    };
  }

  /**
   * Safe User-Agent parser to isolate complex string/regex parsing.
   */
  private static parseUserAgent(userAgent: unknown): {
    os: DeviceOS;
    browser: DeviceBrowser;
    type: DeviceType;
  } {
    const context = {
      os: DeviceOS.UNKNOWN,
      browser: DeviceBrowser.UNKNOWN,
      type: DeviceType.DESKTOP,
    };

    if (typeof userAgent !== "string") {
      return context;
    }

    // WHY: Truncate User-Agent to 500 bytes before regex matching to prevent ReDoS.
    // 500 is chosen as a safe upper bound — RFC 9110 §10.1.5 recommends that
    // servers should handle at least 200 bytes, and no real browser sends >500.
    // This also aligns with common CDN limits (Cloudflare: 800, Akamai: 512).
    const ua = userAgent.substring(0, 500);

    // OS parsing logic
    if (/windows/i.test(ua)) context.os = DeviceOS.WINDOWS;
    else if (/mac os/i.test(ua) && !/like mac os/i.test(ua))
      context.os = DeviceOS.MAC_OS;
    else if (/android/i.test(ua)) context.os = DeviceOS.ANDROID;
    else if (/ipad|iphone|ipod/i.test(ua)) context.os = DeviceOS.IOS;
    else if (/linux/i.test(ua)) context.os = DeviceOS.LINUX;

    // Browser parsing logic (Specific checks like Opera/Edge must precede generic Chrome/Safari checks)
    if (/opera|opr/i.test(ua)) context.browser = DeviceBrowser.OPERA;
    else if (/edg/i.test(ua)) context.browser = DeviceBrowser.EDGE;
    else if (/chrome|crios/i.test(ua)) context.browser = DeviceBrowser.CHROME;
    else if (/firefox|fxios/i.test(ua)) context.browser = DeviceBrowser.FIREFOX;
    else if (/safari/i.test(ua)) context.browser = DeviceBrowser.SAFARI;

    // Type parsing logic
    if (/tablet|ipad/i.test(ua)) context.type = DeviceType.TABLET;
    else if (/mobile|android|iphone|ipod/i.test(ua))
      context.type = DeviceType.MOBILE;

    return context;
  }

  /**
   * Sanitizer for consumer-injected arbitrary context keys.
   */
  private static sanitizeInjectedContext(
    injected: unknown,
  ): Record<string, string | number | boolean> {
    const sanitized: Record<string, string | number | boolean> = {};

    if (!injected || typeof injected !== "object" || Array.isArray(injected)) {
      return sanitized;
    }

    // WHY: Cap at 64 keys to prevent CPU DoS from maliciously large deviceContext.
    // A consumer could pass { "key0": "v", ... up to 1M entries }.
    //
    // NOTE: Object.entries() + early break is insufficient because entries()
    // internally allocates ALL [key,value] tuples before the first iteration,
    // meaning 1M keys still blow memory/time before the break fires. We use
    // Object.keys() (cheaper — keys only) and cap iteration manually.
    //
    // NOTE: We DO NOT use Object.entries() at all because it has no internal
    // try-catch — a single throwing getter on any key causes the entire call
    // to propagate the error. We access each value individually with a try-catch
    // so one bad getter doesn't crash the whole sanitization pass.
    const MAX_SANITIZED_KEYS = 64;
    const keys = Object.keys(injected as Record<string, unknown>);
    const maxIndex = Math.min(keys.length, MAX_SANITIZED_KEYS);

    for (let i = 0; i < maxIndex; i++) {
      const key = keys[i];
      try {
        const value = (injected as Record<string, unknown>)[key];
        if (
          typeof value === "string" ||
          typeof value === "number" ||
          typeof value === "boolean"
        ) {
          sanitized[key] = value;
        }
      } catch {
        // Silently skip keys with throwing accessors — one bad getter
        // must not prevent other keys from being sanitized.
      }
    }

    return sanitized;
  }
}
