import { ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { SessionGuard } from "../../src/middleware/nestjs";
import { ISessionService } from "../../src/interfaces";
import {
  SessionLibraryConfig,
  SessionStatus,
  SessionRecord,
} from "../../src/types";
import { SessionRequest, SessionResponse } from "../../src/middleware/nestjs";

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

describe("NestJS Binding", () => {
  let mockService: jest.Mocked<ISessionService>;
  let mockReflector: jest.Mocked<Reflector>;
  let mockContext: Partial<ExecutionContext>;
  let config: SessionLibraryConfig;

  beforeEach(() => {
    mockService = {
      validateSession: jest.fn(),
    } as unknown as jest.Mocked<ISessionService>;
    mockReflector = {
      getAllAndOverride: jest.fn(),
    } as unknown as jest.Mocked<Reflector>;

    const mockReq: Partial<SessionRequest> = {
      headers: {},
      cookies: { sid: "token" },
      session: undefined,
      method: "GET",
    };

    mockContext = {
      getType: () => "http",
      switchToHttp: () => ({
        getRequest: () => mockReq as SessionRequest,
        getResponse: () => ({}) as SessionResponse,
      }),
      getHandler: () => function handler() {},
      getClass: () => class Controller {},
    } as unknown as ExecutionContext;

    config = {
      env: "test",
      transport: { mode: "cookie", cookie: { name: "sid" } },
      security: { csrf: { enabled: false } },
    } as unknown as SessionLibraryConfig;
  });

  it("should skip validation if session is already memoized (Symbol protection)", async () => {
    const guard = new SessionGuard(mockService, config, mockReflector);
    
    // 1. First call: Should perform validation
    mockService.validateSession.mockResolvedValueOnce({ 
      success: true, 
      data: createMockSession(), 
      httpCode: 200 
    });
    
    await guard.canActivate(mockContext as ExecutionContext);
    expect(mockService.validateSession).toHaveBeenCalledTimes(1);

    // 2. Second call: Should skip validation (memoized)
    const result = await guard.canActivate(mockContext as ExecutionContext);

    expect(result).toBe(true);
    expect(mockService.validateSession).toHaveBeenCalledTimes(1); // Still 1
  });

  it("should enforce roles using Reflector", async () => {
    const guard = new SessionGuard(mockService, config, mockReflector);

    mockService.validateSession.mockResolvedValue({
      success: true,
      data: createMockSession({ roles: ["user"] }),
      httpCode: 200,
    });

    mockReflector.getAllAndOverride.mockReturnValue(["admin"]);

    await expect(
      guard.canActivate(mockContext as ExecutionContext),
    ).rejects.toThrow("Insufficient roles");
  });

  it("should forward deviceFingerprint from device cookie to service", async () => {
    const deviceConfig: SessionLibraryConfig = {
      ...config,
      device: { enabled: true, cookie: { name: "device_id" } },
    };

    const mockReq: Partial<SessionRequest> = {
      headers: {},
      cookies: { sid: "token", device_id: "device_abc_123" },
      signedCookies: {},
      session: undefined,
      method: "GET",
    };

    mockContext = {
      getType: () => "http",
      switchToHttp: () => ({
        getRequest: () => mockReq as SessionRequest,
        getResponse: () => ({}) as SessionResponse,
      }),
      getHandler: () => function handler() {},
      getClass: () => class Controller {},
    } as unknown as ExecutionContext;

    const guard = new SessionGuard(mockService, deviceConfig, mockReflector);

    mockService.validateSession.mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });

    await guard.canActivate(mockContext as ExecutionContext);

    expect(mockService.validateSession).toHaveBeenCalledWith(
      expect.objectContaining({
        context: expect.objectContaining({
          deviceFingerprint: "device_abc_123",
        }),
      }),
    );
  });
});
