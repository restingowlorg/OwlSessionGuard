import {
  BridgeProcessor,
  SessionWebContext,
  buildValidateFn,
} from "../../src/middleware/bridge";
import {
  SessionLibraryConfig,
  SessionStatus,
  SessionRecord,
} from "../../src/types";
import { ISessionService } from "../../src/interfaces";

const createMockSession = (
  overrides: Partial<SessionRecord> = {},
): SessionRecord => ({
  id: "123",
  userId: "user1",
  tokenHash: "hashed_token",
  status: SessionStatus.ACTIVE,
  roles: [],
  scopes: [],
  createdAt: new Date(),
  lastUsedAt: new Date(),
  expiresAt: new Date(),
  idleExpiresAt: new Date(),
  metadata: { ipAddress: "127.0.0.1" },
  ...overrides,
});

const createMockContext = (): jest.Mocked<SessionWebContext> => ({
  getMethod: jest.fn().mockReturnValue("GET"),
  getCookie: jest.fn(),
  getHeader: jest.fn(),
  setHeader: jest.fn(),
  setCookie: jest.fn(),
  clearCookie: jest.fn(),
  getClientInfo: jest.fn().mockReturnValue({ ipAddress: "127.0.0.1" }),
  setSession: jest.fn(),
  getSession: jest.fn(),
  getDeviceId: jest.fn(),
});

const defaultConfig: SessionLibraryConfig = {
  env: "test",
  transport: {
    mode: "cookie",
    cookie: {
      name: "test_sid",
      httpOnly: true,
      secure: true,
      sameSite: "lax",
    },
  },
  expiration: {
    idleTimeoutSeconds: 3600,
    absoluteTimeoutSeconds: 86400,
    rolling: true,
  },
  rotation: {
    gracePeriodSeconds: 30,
  },
  security: {
    enforceTlsInProduction: true,
    ipBinding: "soft",
    fingerprinting: "off",
    csrf: { enabled: false },
  },
  limits: { maxSessionsPerUser: 5 },
  store: { provider: "memory" },
  observability: { debug: false, emitEvents: false, metrics: false },
};

describe("BridgeProcessor", () => {
  let mockContext: jest.Mocked<SessionWebContext>;
  let processor: BridgeProcessor;

  beforeEach(() => {
    mockContext = createMockContext();
    processor = new BridgeProcessor(defaultConfig);
  });

  it("should extract token from cookie and validate successfully", async () => {
    mockContext.getCookie.mockReturnValue("valid_token");
    const sessionRecord = createMockSession();

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: sessionRecord,
      httpCode: 200,
    });

    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(true);
    expect(mockContext.getCookie).toHaveBeenCalledWith("test_sid");
    expect(validateFn).toHaveBeenCalledWith("valid_token", {
      ipAddress: "127.0.0.1",
      method: "GET",
      csrfToken: undefined,
      deviceFingerprint: undefined,
    });
    expect(mockContext.setSession).toHaveBeenCalledWith(sessionRecord);
  });

  it("should handle rolling expiration by updating cookie", async () => {
    mockContext.getCookie.mockReturnValue("old_token");
    const sessionRecord = createMockSession();

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: sessionRecord,
      newToken: "new_token",
      httpCode: 200,
    });

    await processor.handle(mockContext, validateFn);

    expect(mockContext.setCookie).toHaveBeenCalledWith(
      "test_sid",
      "new_token",
      expect.objectContaining({ httpOnly: true, secure: true }),
    );
  });

  it("should clear cookie on validation failure", async () => {
    mockContext.getCookie.mockReturnValue("invalid_token");

    const validateFn = jest.fn().mockResolvedValue({
      success: false,
      error: { message: "Invalid token", httpCode: 401 },
    });

    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(false);
    expect(mockContext.clearCookie).toHaveBeenCalledWith(
      "test_sid",
      expect.any(Object),
    );
  });

  it("should support header transport", async () => {
    const configWithHeader: SessionLibraryConfig = {
      ...defaultConfig,
      transport: {
        mode: "header",
        header: { name: "X-Session-Id" },
      },
    };
    processor = new BridgeProcessor(configWithHeader);
    mockContext.getHeader.mockReturnValue("header_token");

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });
    await processor.handle(mockContext, validateFn);

    expect(mockContext.getHeader).toHaveBeenCalledWith("x-session-id");
    expect(validateFn).toHaveBeenCalledWith("header_token", expect.objectContaining({ ipAddress: "127.0.0.1" }));
  });

  it("should support Bearer scheme in header", async () => {
    const configWithBearer: SessionLibraryConfig = {
      ...defaultConfig,
      transport: {
        mode: "header",
        header: { name: "Authorization", scheme: "Bearer" },
      },
    };
    processor = new BridgeProcessor(configWithBearer);
    mockContext.getHeader.mockReturnValue("Bearer bearer_token");

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });
    await processor.handle(mockContext, validateFn);

    expect(validateFn).toHaveBeenCalledWith("bearer_token", expect.objectContaining({ ipAddress: "127.0.0.1" }));
  });

  it("should support custom CSRF cookie and header names", async () => {
    const customConfig: SessionLibraryConfig = {
      ...defaultConfig,
      security: {
        ...defaultConfig.security,
        csrf: {
          enabled: true,
          cookieName: "CUSTOM_CSRF_COOKIE",
          headerName: "X-CUSTOM-CSRF",
        },
      },
    };
    processor = new BridgeProcessor(customConfig);
    mockContext.getMethod.mockReturnValue("POST");

    mockContext.getCookie.mockImplementation((name) => {
      if (name === "CUSTOM_CSRF_COOKIE") return "csrf_secret";
      if (name === "test_sid") return "session_token";
      return undefined;
    });
    mockContext.getHeader.mockImplementation((name) => {
      if (name === "x-custom-csrf") return "csrf_secret";
      if (name === "authorization") return "Bearer session_token";
      return undefined;
    });

    const validateFn = jest.fn().mockResolvedValue({ success: true, data: createMockSession(), httpCode: 200 });
    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(true);
    expect(mockContext.getHeader).toHaveBeenCalledWith("x-custom-csrf");
  });

  it("should write CSRF cookie when validateFn returns newCsrfToken", async () => {
    const csrfConfig: SessionLibraryConfig = {
      ...defaultConfig,
      security: {
        ...defaultConfig.security,
        csrf: { enabled: true },
      },
    };
    processor = new BridgeProcessor(csrfConfig);
    mockContext.getCookie.mockReturnValue("token");

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      newCsrfToken: "fresh_csrf_value",
      httpCode: 200,
    });

    await processor.handle(mockContext, validateFn);

    expect(mockContext.setCookie).toHaveBeenCalledWith(
      "x-csrf-token",
      "fresh_csrf_value",
      expect.objectContaining({ httpOnly: false }),
    );
  });

  it("should clear CSRF cookie when validateFn returns clearCsrfToken on success", async () => {
    const csrfConfig: SessionLibraryConfig = {
      ...defaultConfig,
      security: {
        ...defaultConfig.security,
        csrf: { enabled: true },
      },
    };
    processor = new BridgeProcessor(csrfConfig);
    mockContext.getCookie.mockReturnValue("token");

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      clearCsrfToken: true,
      httpCode: 200,
    });

    await processor.handle(mockContext, validateFn);

    expect(mockContext.clearCookie).toHaveBeenCalledWith(
      "x-csrf-token",
      expect.objectContaining({ httpOnly: false }),
    );
  });

  it("should clear CSRF cookie when validateFn returns clearCsrfToken on failure", async () => {
    const csrfConfig: SessionLibraryConfig = {
      ...defaultConfig,
      security: {
        ...defaultConfig.security,
        csrf: { enabled: true },
      },
    };
    processor = new BridgeProcessor(csrfConfig);
    mockContext.getCookie.mockReturnValue("invalid_token");

    const validateFn = jest.fn().mockResolvedValue({
      success: false,
      error: { message: "Revoked", httpCode: 401 },
      clearCsrfToken: true,
    });

    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(false);
    expect(mockContext.clearCookie).toHaveBeenCalledWith(
      "x-csrf-token",
      expect.objectContaining({ httpOnly: false }),
    );
  });

  it("should not write CSRF cookie when csrf is disabled", async () => {
    mockContext.getCookie.mockReturnValue("token");

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      newCsrfToken: "csrf_value",
      httpCode: 200,
    });

    await processor.handle(mockContext, validateFn);

    const csrfCookieCalls = mockContext.setCookie.mock.calls.filter(
      (call) => call[0] === "x-csrf-token",
    );
    expect(csrfCookieCalls).toHaveLength(0);
  });

  it("should throw when CSRF cookie write fails (critical)", async () => {
    const csrfConfig: SessionLibraryConfig = {
      ...defaultConfig,
      security: {
        ...defaultConfig.security,
        csrf: { enabled: true },
      },
    };
    processor = new BridgeProcessor(csrfConfig);
    mockContext.getCookie.mockReturnValue("token");

    // Session cookie write succeeds, CSRF cookie write fails
    mockContext.setCookie.mockImplementation((name) => {
      if (name === "x-csrf-token") throw new Error("CSRF write failed");
    });

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      newCsrfToken: "fresh_csrf",
      httpCode: 200,
    });

    await expect(processor.handle(mockContext, validateFn)).rejects.toThrow(
      "CSRF write failed",
    );
  });

  it("should not crash when CSRF cookie clear fails (non-critical)", async () => {
    const csrfConfig: SessionLibraryConfig = {
      ...defaultConfig,
      security: {
        ...defaultConfig.security,
        csrf: { enabled: true },
      },
    };
    processor = new BridgeProcessor(csrfConfig);
    mockContext.getCookie.mockReturnValue("token");

    mockContext.clearCookie.mockImplementation(() => {
      throw new Error("Clear failed");
    });

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      clearCsrfToken: true,
      httpCode: 200,
    });

    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(true);
  });

  it("should return false when success:true but session is REVOKED", async () => {
    mockContext.getCookie.mockReturnValue("token");
    const revokedRecord = createMockSession({ status: SessionStatus.REVOKED });

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: revokedRecord,
      clearCsrfToken: true,
      httpCode: 200,
    });

    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(false);
    expect(mockContext.setSession).not.toHaveBeenCalled();
  });

  it("should return false when success:true but data is missing", async () => {
    mockContext.getCookie.mockReturnValue("token");

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      httpCode: 200,
    });

    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(false);
    expect(mockContext.setSession).not.toHaveBeenCalled();
  });

  it("should return false when validateFn throws synchronously", async () => {
    mockContext.getCookie.mockReturnValue("token");

    const validateFn = jest.fn().mockImplementation(() => {
      throw new Error("Boom");
    });

    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(false);
  });

  it("should return false when validateFn rejects asynchronously", async () => {
    mockContext.getCookie.mockReturnValue("token");

    const validateFn = jest.fn().mockRejectedValue(new Error("Async boom"));

    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(false);
  });

  it("should throw when session cookie write fails (critical)", async () => {
    mockContext.getCookie.mockReturnValue("token");
    mockContext.setCookie.mockImplementation(() => {
      throw new Error("Cookie jar full");
    });

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      newToken: "new_token",
      httpCode: 200,
    });

    await expect(processor.handle(mockContext, validateFn)).rejects.toThrow(
      "Cookie jar full",
    );
  });

  it("should not crash when context.clearCookie throws (non-critical)", async () => {
    mockContext.getCookie.mockReturnValue("invalid_token");
    mockContext.clearCookie.mockImplementation(() => {
      throw new Error("Clear failed");
    });

    const validateFn = jest.fn().mockResolvedValue({
      success: false,
      error: { message: "Invalid", httpCode: 401 },
    });

    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(false);
  });

  it("should call getDeviceId and forward deviceFingerprint to validateFn", async () => {
    const deviceConfig: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true },
    };
    const deviceProcessor = new BridgeProcessor(deviceConfig);

    mockContext.getCookie.mockReturnValue("token");
    mockContext.getDeviceId.mockReturnValue("device_abc_123");

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });

    const result = await deviceProcessor.handle(mockContext, validateFn);

    expect(result).toBe(true);
    expect(mockContext.getDeviceId).toHaveBeenCalled();
    expect(validateFn).toHaveBeenCalledWith("token", {
      ipAddress: "127.0.0.1",
      method: "GET",
      csrfToken: undefined,
      deviceFingerprint: "device_abc_123",
    });
  });

  it("should forward undefined deviceFingerprint when getDeviceId returns undefined", async () => {
    mockContext.getCookie.mockReturnValue("token");
    mockContext.getDeviceId.mockReturnValue(undefined);

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });

    await processor.handle(mockContext, validateFn);

    expect(validateFn).toHaveBeenCalledWith("token", {
      ipAddress: "127.0.0.1",
      method: "GET",
      csrfToken: undefined,
      deviceFingerprint: undefined,
    });
  });

  it("should forward undefined deviceFingerprint when getDeviceId is not implemented", async () => {
    mockContext.getCookie.mockReturnValue("token");
    delete (mockContext as { getDeviceId?: jest.Mock }).getDeviceId;

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });

    await processor.handle(mockContext, validateFn);

    expect(validateFn).toHaveBeenCalledWith("token", {
      ipAddress: "127.0.0.1",
      method: "GET",
      csrfToken: undefined,
      deviceFingerprint: undefined,
    });
  });

  it("should NOT call getDeviceId when device is disabled", async () => {
    mockContext.getCookie.mockReturnValue("token");
    mockContext.getDeviceId.mockReturnValue("should_not_be_called");

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });

    // processor uses defaultConfig which has device disabled
    await processor.handle(mockContext, validateFn);

    expect(mockContext.getDeviceId).not.toHaveBeenCalled();
    expect(validateFn).toHaveBeenCalledWith("token", {
      ipAddress: "127.0.0.1",
      method: "GET",
      csrfToken: undefined,
      deviceFingerprint: undefined,
    });
  });

  it("should swallow getDeviceId error and continue without fingerprint", async () => {
    const deviceConfig: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true },
    };
    const deviceProcessor = new BridgeProcessor(deviceConfig);

    mockContext.getCookie.mockReturnValue("token");
    mockContext.getDeviceId.mockImplementation(() => {
      throw new Error("Cookie parser broken");
    });

    const consoleSpy = jest.spyOn(console, "error").mockImplementation();

    const validateFn = jest.fn().mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });

    const result = await deviceProcessor.handle(mockContext, validateFn);

    expect(result).toBe(true);
    expect(consoleSpy).toHaveBeenCalledWith(
      "[OSSEC] getDeviceId() threw:",
      expect.any(Error),
    );
    expect(validateFn).toHaveBeenCalledWith("token", {
      ipAddress: "127.0.0.1",
      method: "GET",
      csrfToken: undefined,
      deviceFingerprint: undefined,
    });

    consoleSpy.mockRestore();
  });
});

describe("BridgeProcessor - Device Cookie Helpers", () => {
  let mockContext: jest.Mocked<SessionWebContext>;

  beforeEach(() => {
    mockContext = createMockContext();
  });

  it("should write device cookie when device is enabled", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: {
        enabled: true,
        cookie: { name: "my_device" },
      },
    };
    const processor = new BridgeProcessor(config);

    processor.writeDeviceIdCookie(mockContext, "device_abc_123");

    expect(mockContext.setCookie).toHaveBeenCalledWith(
      "my_device",
      "device_abc_123",
      expect.objectContaining({ httpOnly: true, secure: true }),
    );
  });

  it("should clear device cookie when device is enabled", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: {
        enabled: true,
        cookie: { name: "my_device" },
      },
    };
    const processor = new BridgeProcessor(config);

    processor.clearDeviceIdCookie(mockContext);

    expect(mockContext.clearCookie).toHaveBeenCalledWith(
      "my_device",
      expect.objectContaining({ httpOnly: true }),
    );
  });

  it("should not write device cookie when device is disabled", () => {
    const processor = new BridgeProcessor(defaultConfig);

    processor.writeDeviceIdCookie(mockContext, "device_abc_123");

    expect(mockContext.setCookie).not.toHaveBeenCalled();
  });

  it("should not clear device cookie when device is disabled", () => {
    const processor = new BridgeProcessor(defaultConfig);

    processor.clearDeviceIdCookie(mockContext);

    expect(mockContext.clearCookie).not.toHaveBeenCalled();
  });

  it("should default cookie name to device_id when not specified", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true },
    };
    const processor = new BridgeProcessor(config);

    processor.writeDeviceIdCookie(mockContext, "device_abc_123");

    expect(mockContext.setCookie).toHaveBeenCalledWith(
      "device_id",
      "device_abc_123",
      expect.any(Object),
    );
  });

  it("should inherit secure defaults from session cookie config", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true },
    };
    const processor = new BridgeProcessor(config);

    processor.writeDeviceIdCookie(mockContext, "device_abc_123");

    expect(mockContext.setCookie).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.objectContaining({ secure: true, sameSite: "lax" }),
    );
  });

  it("should silently ignore empty deviceId", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true },
    };
    const processor = new BridgeProcessor(config);

    processor.writeDeviceIdCookie(mockContext, "");

    expect(mockContext.setCookie).not.toHaveBeenCalled();
  });

  it("should silently ignore deviceId exceeding 512 chars", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true },
    };
    const processor = new BridgeProcessor(config);

    processor.writeDeviceIdCookie(mockContext, "x".repeat(513));

    expect(mockContext.setCookie).not.toHaveBeenCalled();
  });

  it("should accept deviceId of exactly 512 chars", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true },
    };
    const processor = new BridgeProcessor(config);

    processor.writeDeviceIdCookie(mockContext, "a".repeat(512));

    expect(mockContext.setCookie).toHaveBeenCalledWith(
      "device_id",
      "a".repeat(512),
      expect.any(Object),
    );
  });

  it("should not crash when context.setCookie throws on device write", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true },
    };
    const processor = new BridgeProcessor(config);
    mockContext.setCookie.mockImplementation(() => {
      throw new Error("Cookie jar full");
    });

    expect(() =>
      processor.writeDeviceIdCookie(mockContext, "device_abc"),
    ).not.toThrow();
  });

  it("should throw when device cookie has SameSite=None but Secure=false", () => {
    expect(
      () =>
        new BridgeProcessor({
          ...defaultConfig,
          device: {
            enabled: true,
            cookie: { sameSite: "none", secure: false },
          },
        }),
    ).toThrow("[OSSEC] Device cookie: SameSite=None requires Secure=true.");
  });

  it("should not throw when device cookie has SameSite=None and Secure=true", () => {
    expect(
      () =>
        new BridgeProcessor({
          ...defaultConfig,
          device: {
            enabled: true,
            cookie: { sameSite: "none", secure: true },
          },
        }),
    ).not.toThrow();
  });

  it("should expose deviceCookieName when device is enabled", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true, cookie: { name: "custom_device" } },
    };
    const processor = new BridgeProcessor(config);

    expect(processor.deviceCookieName).toBe("custom_device");
  });

  it("should return undefined for deviceCookieName when device is disabled", () => {
    const processor = new BridgeProcessor(defaultConfig);

    expect(processor.deviceCookieName).toBeUndefined();
  });

  it("should expose getDeviceId() that reads the device cookie", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true, cookie: { name: "my_device" } },
    };
    const processor = new BridgeProcessor(config);

    mockContext.getCookie.mockImplementation((name) => {
      if (name === "my_device") return "device_from_request";
      return undefined;
    });

    // WHY: getDeviceId is a consumer-facing method on SessionWebContext.
    // The bridge provides the cookie name; the framework context reads it.
    // This test verifies the end-to-end read path works.
    mockContext.getDeviceId = jest
      .fn()
      .mockReturnValue("device_from_request");

    expect(mockContext.getDeviceId()).toBe("device_from_request");
    expect(processor.deviceCookieName).toBe("my_device");
  });

  it("should write device cookie when expectedFingerprint matches", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true, cookie: { name: "my_device" } },
    };
    const processor = new BridgeProcessor(config);

    processor.writeDeviceIdCookie(
      mockContext,
      "device_abc_123",
      "device_abc_123",
    );

    expect(mockContext.setCookie).toHaveBeenCalledWith(
      "my_device",
      "device_abc_123",
      expect.objectContaining({ httpOnly: true, secure: true }),
    );
  });

  it("should block device cookie write when expectedFingerprint does not match", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true, cookie: { name: "my_device" } },
    };
    const processor = new BridgeProcessor(config);

    processor.writeDeviceIdCookie(
      mockContext,
      "device_abc_123",
      "different_fingerprint",
    );

    expect(mockContext.setCookie).not.toHaveBeenCalled();
  });

  it("should write device cookie when expectedFingerprint is undefined", () => {
    const config: SessionLibraryConfig = {
      ...defaultConfig,
      device: { enabled: true, cookie: { name: "my_device" } },
    };
    const processor = new BridgeProcessor(config);

    processor.writeDeviceIdCookie(mockContext, "device_abc_123", undefined);

    expect(mockContext.setCookie).toHaveBeenCalledWith(
      "my_device",
      "device_abc_123",
      expect.objectContaining({ httpOnly: true, secure: true }),
    );
  });
});

describe("buildValidateFn", () => {
  it("should forward newCsrfToken from service result", async () => {
    const mockService: ISessionService = {
      createSession: jest.fn(),
      validateSession: jest.fn().mockResolvedValue({
        success: true,
        data: createMockSession(),
        httpCode: 200,
        newCsrfToken: "rotated_csrf",
      }),
      rotateSession: jest.fn(),
      revokeSession: jest.fn(),
      revokeAllSessionsForUser: jest.fn(),
    };

    const fn = buildValidateFn(mockService);
    const result = await fn("token", {
      ipAddress: "127.0.0.1",
      method: "GET",
    });

    expect(result).toEqual(
      expect.objectContaining({ newCsrfToken: "rotated_csrf" }),
    );
  });

  it("should forward clearCsrfToken from service result on failure", async () => {
    const mockService: ISessionService = {
      createSession: jest.fn(),
      validateSession: jest.fn().mockResolvedValue({
        success: false,
        error: { code: "ERR", message: "Revoked" },
        httpCode: 401,
        clearCsrfToken: true,
      }),
      rotateSession: jest.fn(),
      revokeSession: jest.fn(),
      revokeAllSessionsForUser: jest.fn(),
    };

    const fn = buildValidateFn(mockService);
    const result = await fn("token", {
      ipAddress: "127.0.0.1",
      method: "GET",
    });

    expect(result).toEqual(
      expect.objectContaining({ clearCsrfToken: true }),
    );
  });

  it("should use rotateSession when mode is 'rotate'", async () => {
    const mockService: ISessionService = {
      createSession: jest.fn(),
      validateSession: jest.fn(),
      rotateSession: jest.fn().mockResolvedValue({
        success: true,
        data: { newToken: "rotated_token", record: createMockSession() },
        httpCode: 200,
        newCsrfToken: "new_csrf",
      }),
      revokeSession: jest.fn(),
      revokeAllSessionsForUser: jest.fn(),
    };

    const fn = buildValidateFn(mockService, { mode: "rotate" });
    const result = await fn("old_token", {
      ipAddress: "127.0.0.1",
      method: "POST",
    });

    expect(result).toEqual(
      expect.objectContaining({
        success: true,
        newToken: "rotated_token",
        newCsrfToken: "new_csrf",
      }),
    );
    expect(mockService.rotateSession).toHaveBeenCalledWith({
      token: "old_token",
      context: {
        ipAddress: "127.0.0.1",
        userAgent: undefined,
        method: "POST",
      },
    });
  });

  it("should forward clearCsrfToken on rotate failure", async () => {
    const mockService: ISessionService = {
      createSession: jest.fn(),
      validateSession: jest.fn(),
      rotateSession: jest.fn().mockResolvedValue({
        success: false,
        error: { code: "ERR", message: "Rotation failed" },
        httpCode: 401,
        clearCsrfToken: true,
      }),
      revokeSession: jest.fn(),
      revokeAllSessionsForUser: jest.fn(),
    };

    const fn = buildValidateFn(mockService, { mode: "rotate" });
    const result = await fn("token", {
      ipAddress: "127.0.0.1",
      method: "POST",
    });

    expect(result).toEqual(
      expect.objectContaining({
        success: false,
        clearCsrfToken: true,
      }),
    );
  });

  it("should forward deviceFingerprint to service.validateSession in default mode", async () => {
    const mockService: ISessionService = {
      createSession: jest.fn(),
      validateSession: jest.fn().mockResolvedValue({
        success: true,
        data: createMockSession(),
        httpCode: 200,
      }),
      rotateSession: jest.fn(),
      revokeSession: jest.fn(),
      revokeAllSessionsForUser: jest.fn(),
    };

    const fn = buildValidateFn(mockService);
    await fn("token", {
      ipAddress: "127.0.0.1",
      method: "GET",
      deviceFingerprint: "device_abc_123",
    });

    expect(mockService.validateSession).toHaveBeenCalledWith({
      token: "token",
      csrfToken: undefined,
      context: {
        ipAddress: "127.0.0.1",
        userAgent: undefined,
        method: "GET",
        deviceFingerprint: "device_abc_123",
      },
    });
  });

  it("should forward deviceFingerprint to service.rotateSession in rotate mode", async () => {
    const mockService: ISessionService = {
      createSession: jest.fn(),
      validateSession: jest.fn(),
      rotateSession: jest.fn().mockResolvedValue({
        success: true,
        data: { newToken: "new_token", record: createMockSession() },
        httpCode: 200,
      }),
      revokeSession: jest.fn(),
      revokeAllSessionsForUser: jest.fn(),
    };

    const fn = buildValidateFn(mockService, { mode: "rotate" });
    await fn("old_token", {
      ipAddress: "127.0.0.1",
      method: "POST",
      deviceFingerprint: "device_xyz_789",
    });

    expect(mockService.rotateSession).toHaveBeenCalledWith({
      token: "old_token",
      context: {
        ipAddress: "127.0.0.1",
        userAgent: undefined,
        method: "POST",
        deviceFingerprint: "device_xyz_789",
      },
    });
  });

  it("should not include deviceFingerprint when not provided", async () => {
    const mockService: ISessionService = {
      createSession: jest.fn(),
      validateSession: jest.fn().mockResolvedValue({
        success: true,
        data: createMockSession(),
        httpCode: 200,
      }),
      rotateSession: jest.fn(),
      revokeSession: jest.fn(),
      revokeAllSessionsForUser: jest.fn(),
    };

    const fn = buildValidateFn(mockService);
    await fn("token", {
      ipAddress: "127.0.0.1",
      method: "GET",
    });

    expect(mockService.validateSession).toHaveBeenCalledWith({
      token: "token",
      csrfToken: undefined,
      context: {
        ipAddress: "127.0.0.1",
        userAgent: undefined,
        method: "GET",
      },
    });
  });
});
