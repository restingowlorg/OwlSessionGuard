import {
  BridgeProcessor,
  SessionWebContext,
} from "../../src/middleware/bridge";
import {
  SessionLibraryConfig,
  SessionStatus,
  SessionRecord,
} from "../../src/types";

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

describe("BridgeProcessor", () => {
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
      rotateOnLogin: true,
      rotateOnPrivilegeChange: true,
      gracePeriodSeconds: 30,
    },
    security: {
      enforceTlsInProduction: true,
      ipBinding: "soft",
      fingerprinting: "off",
      csrf: { enabled: false, mode: "double-submit" },
    },
    limits: { maxSessionsPerUser: 5 },
    store: { provider: "memory" },
    observability: { debug: false, emitEvents: false, metrics: false },
  };

  let mockContext: jest.Mocked<SessionWebContext>;
  let processor: BridgeProcessor;

  beforeEach(() => {
    mockContext = {
      getMethod: jest.fn().mockReturnValue("GET"),
      getCookie: jest.fn(),
      getHeader: jest.fn(),
      setHeader: jest.fn(),
      setCookie: jest.fn(),
      clearCookie: jest.fn(),
      getClientInfo: jest.fn().mockReturnValue({ ipAddress: "127.0.0.1" }),
      setSession: jest.fn(),
      getSession: jest.fn(),
    };
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

    const validateFn = jest
      .fn()
      .mockResolvedValue({
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

    const validateFn = jest
      .fn()
      .mockResolvedValue({
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
          mode: "double-submit",
          cookieName: "CUSTOM_CSRF_COOKIE",
          headerName: "X-CUSTOM-CSRF",
        },
      },
    };
    processor = new BridgeProcessor(customConfig);
    mockContext.getMethod.mockReturnValue("POST");
    mockContext.getCookie.mockReturnValue("token");
    mockContext.getHeader.mockReturnValue("token"); // Correct session token
    
    // CSRF Check
    mockContext.getCookie.mockImplementation((name) => {
      if (name === "CUSTOM_CSRF_COOKIE") return "csrf_secret";
      if (name === "test_sid") return "session_token";
      return undefined;
    });
    mockContext.getHeader.mockImplementation((name) => {
      if (name === "x-custom-csrf") return "csrf_secret"; // Bridge lowercases it
      if (name === "authorization") return "Bearer session_token";
      return undefined;
    });

    const validateFn = jest.fn().mockResolvedValue({ success: true, data: createMockSession(), httpCode: 200 });
    const result = await processor.handle(mockContext, validateFn);

    expect(result).toBe(true);
    expect(mockContext.getHeader).toHaveBeenCalledWith("x-custom-csrf");
  });
});
