import { Request, Response, NextFunction } from "express";
import { createExpressMiddleware } from "../../src/middleware/express";
import { ISessionService } from "../../src/interfaces";
import {
  SessionLibraryConfig,
  SessionStatus,
  SessionRecord,
} from "../../src/types";

const createMockSession = (
  overrides: Partial<SessionRecord> = {},
): SessionRecord => ({
  id: "s1",
  userId: "u1",
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

describe("Express Middleware", () => {
  let mockService: jest.Mocked<ISessionService>;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let next: jest.Mock<NextFunction>;

  const baseConfig: SessionLibraryConfig = {
    env: "test",
    transport: {
      mode: "cookie",
      cookie: {
        name: "sid",
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
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
      csrf: { enabled: false, mode: "double-submit" },
    },
    limits: { maxSessionsPerUser: 5 },
    store: { provider: "memory" },
    observability: { debug: false, emitEvents: false, metrics: false },
  };

  beforeEach(() => {
    mockService = {
      validateSession: jest.fn(),
    } as unknown as jest.Mocked<ISessionService>;

    mockReq = {
      cookies: {},
      signedCookies: {},
      headers: {},
      method: "GET",
      get: jest
        .fn()
        .mockImplementation(
          (name: string) =>
            (mockReq.headers as Record<string, string>)[name.toLowerCase()],
        ),
      socket: { remoteAddress: "127.0.0.1" } as unknown as Request["socket"],
    };

    mockRes = {
      cookie: jest.fn().mockReturnThis(),
      clearCookie: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
    };

    next = jest.fn();
  });

  it("should attach session to request on valid cookie", async () => {
    const middleware = createExpressMiddleware(mockService, baseConfig);
    mockReq.cookies = { sid: "valid_token" };

    const sessionRecord = createMockSession();
    mockService.validateSession.mockResolvedValue({
      success: true,
      data: sessionRecord,
      httpCode: 200,
    });

    await middleware(mockReq as Request, mockRes as Response, next);

    expect(mockReq.session).toEqual(sessionRecord);
    expect(next).toHaveBeenCalled();
  });

  it("should prioritize signed cookies and prevent unsigned bypass", async () => {
    const middleware = createExpressMiddleware(mockService, baseConfig);
    mockReq.cookies = { sid: "attacker_token" };
    mockReq.signedCookies = { sid: "genuine_token" };

    mockService.validateSession.mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });

    await middleware(mockReq as Request, mockRes as Response, next);

    expect(mockService.validateSession).toHaveBeenCalledWith(
      expect.objectContaining({
        token: "genuine_token",
      }),
    );
  });

  it("should enforce CSRF on POST requests", async () => {
    const hardenedConfig: SessionLibraryConfig = {
      ...baseConfig,
      security: {
        ...baseConfig.security,
        csrf: { enabled: true, mode: "double-submit" },
      },
    };
    const middleware = createExpressMiddleware(mockService, hardenedConfig);

    mockReq.method = "POST";
    mockReq.cookies = { sid: "token", "x-csrf-token": "secret" };
    mockReq.headers = { "x-csrf-token": "mismatch" };

    mockService.validateSession.mockResolvedValue({
      success: false,
      error: { message: "CSRF Mismatch", code: "CSRF_ERROR" },
      httpCode: 403,
    });

    await middleware(mockReq as Request, mockRes as Response, next);

    expect(mockReq.session).toBeUndefined();
    expect(mockService.validateSession).toHaveBeenCalledWith(
      expect.objectContaining({
        token: "token",
        csrfToken: "mismatch",
      })
    );
    expect(next).toHaveBeenCalled();
  });
});
