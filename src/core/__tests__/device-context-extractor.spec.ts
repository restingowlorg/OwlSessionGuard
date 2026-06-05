import { DeviceContextExtractor } from "../device-context-extractor";
import {
  SessionMetadata,
  DeviceOS,
  DeviceBrowser,
  DeviceType,
} from "../../types";

/**
 * Typed Mock Factory for SessionMetadata to avoid inline object casts.
 */
const createMockMetadata = (
  overrides: Partial<SessionMetadata> = {},
): SessionMetadata => ({
  ipAddress: "127.0.0.1",
  ...overrides,
});

// Mock uuid to have deterministic fallback fingerprints.
// WHY: Plain function, not jest.fn() — the jest config has resetMocks: true,
// which clears jest.fn() implementations after each test, causing uuidv4() to
// return undefined on subsequent tests. A plain function is immune to this.
jest.mock("uuid", () => ({
  v4: (): string => "mock-uuid-1234",
}));

describe("DeviceContextExtractor — Unit Tests", () => {
  beforeEach(() => {
    // Law 5: beforeEach Resets, Never Shares
    jest.clearAllMocks();
  });

  // Law 1 & 2: Living Specifications, One Behavior
  it("should return the explicit deviceId as the fingerprint when provided in the metadata", () => {
    const metadata = createMockMetadata({
      deviceId: "persistent_cookie_uuid_123",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
    });

    const result = DeviceContextExtractor.extract(metadata);

    expect(result.deviceFingerprint).toBe("persistent_cookie_uuid_123");
  });

  it("should generate a fallback UUID fingerprint to prevent collision when deviceId is missing", () => {
    // Law 6: Test Every Fallback
    const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0";
    const metadata = createMockMetadata({ userAgent });

    const result = DeviceContextExtractor.extract(metadata);

    expect(result.deviceFingerprint).toBe("fallback_mock-uuid-1234");
  });

  it("should safely handle null or undefined metadata without throwing", () => {
    const result = DeviceContextExtractor.extract(null);
    expect(result.deviceFingerprint).toBe("fallback_mock-uuid-1234");
    expect(result.deviceContext.os).toBe(DeviceOS.UNKNOWN);
  });

  // Explicit Fallbacks / Defaults (Law 6)
  it("should fall back to an 'Unknown' OS when the User-Agent does not match known patterns", () => {
    const metadata = createMockMetadata({
      userAgent: "SomeObscureBrowser/1.0",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.os).toBe(DeviceOS.UNKNOWN);
  });

  it("should fall back to an 'Unknown' browser when the User-Agent does not match known patterns", () => {
    const metadata = createMockMetadata({
      userAgent: "SomeObscureBrowser/1.0",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.browser).toBe(DeviceBrowser.UNKNOWN);
  });

  it("should fall back to a 'Desktop' device type when the User-Agent does not match mobile patterns", () => {
    const metadata = createMockMetadata({
      userAgent: "SomeObscureBrowser/1.0",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.type).toBe(DeviceType.DESKTOP);
  });

  // OS Detection mapping tests
  it("should correctly identify Mac OS from a Macintosh Apple WebKit User-Agent", () => {
    const metadata = createMockMetadata({
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.os).toBe(DeviceOS.MAC_OS);
  });

  it("should correctly identify iOS from an iPhone User-Agent", () => {
    const metadata = createMockMetadata({
      userAgent:
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.os).toBe(DeviceOS.IOS);
  });

  it("should correctly identify Tablet type from an iPad User-Agent that contains the word Mobile", () => {
    const metadata = createMockMetadata({
      userAgent:
        "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.type).toBe(DeviceType.TABLET);
  });

  it("should correctly identify Windows from an NT WebKit User-Agent", () => {
    const metadata = createMockMetadata({
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.os).toBe(DeviceOS.WINDOWS);
  });

  it("should correctly identify Android from a Linux Android User-Agent", () => {
    const metadata = createMockMetadata({
      userAgent:
        "Mozilla/5.0 (Linux; Android 12; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.os).toBe(DeviceOS.ANDROID);
  });

  it("should correctly identify Edge from a Windows Edge User-Agent", () => {
    const metadata = createMockMetadata({
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.browser).toBe(DeviceBrowser.EDGE);
  });

  it("should correctly identify Opera from a Windows Opera User-Agent", () => {
    const metadata = createMockMetadata({
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36 OPR/79.0.4135.88",
    });
    const result = DeviceContextExtractor.extract(metadata);
    expect(result.deviceContext.browser).toBe(DeviceBrowser.OPERA);
  });

  it("should safely merge extracted context with any existing deviceContext injected by the consumer", () => {
    const metadata = createMockMetadata({
      userAgent: "Chrome",
      deviceContext: { appVersion: "1.0.0" },
    });

    const result = DeviceContextExtractor.extract(metadata);

    expect(result.deviceContext).toEqual({
      os: DeviceOS.UNKNOWN,
      browser: DeviceBrowser.CHROME,
      type: DeviceType.DESKTOP,
      appVersion: "1.0.0",
    });
  });

  describe("Additional Adversarial and Input Edge Cases", () => {
    it("should handle an empty deviceContext object without error", () => {
      const metadata = createMockMetadata({ deviceContext: {} });
      const result = DeviceContextExtractor.extract(metadata);
      expect(result.deviceContext).toEqual({
        os: DeviceOS.UNKNOWN,
        browser: DeviceBrowser.UNKNOWN,
        type: DeviceType.DESKTOP,
      });
    });

    it("should silently drop functions and symbols from deviceContext", () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const metadata: any = createMockMetadata({
        deviceContext: { valid: "ok" },
      });
      metadata.deviceContext.fn = (): void => {};
      metadata.deviceContext.sym = Symbol("a");
      const result = DeviceContextExtractor.extract(metadata);
      expect(result.deviceContext.valid).toBe("ok");
      // Functions and symbols should be dropped by the sanitizer
      expect(Object.keys(result.deviceContext)).not.toContain("fn");
      expect(Object.keys(result.deviceContext)).not.toContain("sym");
    });

    it("should handle frozen metadata without throwing", () => {
      const metadata = Object.freeze(
        createMockMetadata({ deviceId: "persistent", userAgent: "Chrome" }),
      );
      expect(() => DeviceContextExtractor.extract(metadata)).not.toThrow();
      const result = DeviceContextExtractor.extract(metadata);
      expect(result.deviceFingerprint).toBe("persistent");
    });

    it("should treat an oversized deviceId (>512 bytes) as missing and fall back to UUID", () => {
      const metadata = createMockMetadata({
        deviceId: "x".repeat(600),
      });
      const result = DeviceContextExtractor.extract(metadata);
      expect(result.deviceFingerprint).toBe("fallback_mock-uuid-1234");
    });

    it("should accept deviceId of exactly 512 characters (boundary edge)", () => {
      const metadata = createMockMetadata({
        deviceId: "a".repeat(512),
      });
      const result = DeviceContextExtractor.extract(metadata);
      expect(result.deviceFingerprint).toBe("a".repeat(512));
    });

    it("should accept deviceId of 1 character (minimum valid)", () => {
      const metadata = createMockMetadata({
        deviceId: "x",
      });
      const result = DeviceContextExtractor.extract(metadata);
      expect(result.deviceFingerprint).toBe("x");
    });

    it("should treat non-string deviceId as missing and fall back to UUID", () => {
      const metadata = createMockMetadata({
        deviceId: 12345 as unknown as string,
      });
      const result = DeviceContextExtractor.extract(metadata);
      expect(result.deviceFingerprint).toBe("fallback_mock-uuid-1234");
    });

    it("should treat boolean deviceId as missing and fall back to UUID", () => {
      const metadata = createMockMetadata({
        deviceId: true as unknown as string,
      });
      const result = DeviceContextExtractor.extract(metadata);
      expect(result.deviceFingerprint).toBe("fallback_mock-uuid-1234");
    });
  });

  describe("Adversarial Tests — Stage 5 Matrix", () => {
    it("should safely ignore a deviceContext that is maliciously passed as an Array", () => {
      const metadata = createMockMetadata({
        deviceContext: ["hacked"] as unknown as Record<string, string>,
      });

      const result = DeviceContextExtractor.extract(metadata);

      // The array should be completely ignored, retaining only default keys
      expect(result.deviceContext).toEqual({
        os: DeviceOS.UNKNOWN,
        browser: DeviceBrowser.UNKNOWN,
        type: DeviceType.DESKTOP,
      });
    });

    it("should silently drop nested objects within deviceContext to prevent structure corruption", () => {
      const metadata = createMockMetadata({
        deviceContext: {
          validString: "safe",
          nestedObject: { major: 1 } as unknown as string, // Malicious nested object
        },
      });

      const result = DeviceContextExtractor.extract(metadata);

      // It should keep the safe string, but drop the nested object
      expect(result.deviceContext).toEqual({
        os: DeviceOS.UNKNOWN,
        browser: DeviceBrowser.UNKNOWN,
        type: DeviceType.DESKTOP,
        validString: "safe",
      });
    });

    it("should treat an empty string deviceId as falsy and fall back to a UUID to prevent silent collisions", () => {
      const metadata = createMockMetadata({
        deviceId: "", // The attack vector: intentionally sending empty string
      });

      const result = DeviceContextExtractor.extract(metadata);

      expect(result.deviceFingerprint).toBe("fallback_mock-uuid-1234");
    });

    it("should not hang when deviceContext has a lazy getter that blocks the event loop", () => {
      let getterCalled = false;
      const blockingObj: Record<string, string | number | boolean> = {
        validKey: "ok",
      };
      Object.defineProperty(blockingObj, "blockingKey", {
        get() {
          getterCalled = true;
          const start = Date.now();
          while (Date.now() - start < 100) {
            /* busy-wait */
          }
          return "value";
        },
        enumerable: true,
        configurable: true,
      });

      const metadata = createMockMetadata({
        deviceContext: blockingObj,
      });

      const result = DeviceContextExtractor.extract(metadata);
      expect(result.deviceFingerprint).toBe("fallback_mock-uuid-1234");
      expect(getterCalled).toBe(true);
    });

    it("should not mutate shared state when deviceContext getters have side effects", () => {
      let sideEffectCounter = 0;
      const sideEffectObj: Record<string, string | number | boolean> = {};
      Object.defineProperty(sideEffectObj, "validKey", {
        get() {
          sideEffectCounter++;
          return "ok";
        },
        enumerable: true,
        configurable: true,
      });

      const metadata = createMockMetadata({
        deviceContext: sideEffectObj,
      });

      DeviceContextExtractor.extract(metadata);
      // The extractor reads each key at least once during sanitization
      expect(sideEffectCounter).toBeGreaterThan(0);
    });

    it("should not crash when deviceContext has a getter that throws", () => {
      const throwingObj: Record<string, string | number | boolean> = {};
      Object.defineProperty(throwingObj, "boom", {
        get() {
          throw new Error("adversarial getter throw");
        },
        enumerable: true,
        configurable: true,
      });

      const metadata = createMockMetadata({
        deviceContext: throwingObj,
      });

      expect(() => DeviceContextExtractor.extract(metadata)).not.toThrow();
      const result = DeviceContextExtractor.extract(metadata);
      // The throwing key should be silently dropped, only fallback keys remain
      expect(result.deviceFingerprint).toBe("fallback_mock-uuid-1234");
    });

    it("should override consumer-injected os/browser/type with parsed User-Agent values", () => {
      const metadata = createMockMetadata({
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
        deviceContext: {
          os: "Linux" as unknown as DeviceOS,
          browser: "Safari" as unknown as DeviceBrowser,
          type: "Tablet" as unknown as DeviceType,
        },
      });

      const result = DeviceContextExtractor.extract(metadata);

      // Parsed values should win over consumer-injected ones
      expect(result.deviceContext.os).toBe(DeviceOS.WINDOWS);
      expect(result.deviceContext.browser).toBe(DeviceBrowser.CHROME);
      expect(result.deviceContext.type).toBe(DeviceType.DESKTOP);
    });

    it("should cap deviceContext sanitization at 64 keys to prevent CPU DoS", () => {
      const oversizedContext: Record<string, string> = {};
      for (let i = 0; i < 65; i++) {
        oversizedContext[`key${i}`] = `val${i}`;
      }

      const metadata = createMockMetadata({
        deviceContext: oversizedContext as Record<
          string,
          string | number | boolean
        >,
      });

      const result = DeviceContextExtractor.extract(metadata);

      // 64 sanitized keys + 3 parsed keys (os, browser, type) = 67
      expect(Object.keys(result.deviceContext).length).toBe(67);
      expect(result.deviceContext.key0).toBe("val0");
      expect(result.deviceContext.key63).toBe("val63");
      // key64 should be excluded by the cap
      expect(result.deviceContext).not.toHaveProperty("key64");
    });

    it("should retain valid deviceContext properties when another getter throws", () => {
      const mixedObj: Record<string, string | number | boolean> = {
        validKey: "good",
        anotherKey: 42,
      };
      Object.defineProperty(mixedObj, "boom", {
        get() {
          throw new Error("adversarial getter throw");
        },
        enumerable: true,
        configurable: true,
      });

      const metadata = createMockMetadata({
        deviceContext: mixedObj,
      });

      expect(() => DeviceContextExtractor.extract(metadata)).not.toThrow();
      const result = DeviceContextExtractor.extract(metadata);

      expect(result.deviceContext.validKey).toBe("good");
      expect(result.deviceContext.anotherKey).toBe(42);
      expect(result.deviceContext).not.toHaveProperty("boom");
    });
  });
});
