/* eslint-disable @typescript-eslint/no-unsafe-function-type */
import { FastifyRequest, FastifyReply, FastifyInstance } from "fastify";
import { fastifySessionPlugin } from "../../src/middleware/fastify";
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

describe("Fastify Plugin", () => {
  let mockService: jest.Mocked<ISessionService>;
  let mockRequest: Partial<FastifyRequest>;
  let mockReply: Partial<FastifyReply>;
  let config: SessionLibraryConfig;

  beforeEach(() => {
    mockService = {
      validateSession: jest.fn(),
    } as unknown as jest.Mocked<ISessionService>;

    mockRequest = {
      cookies: {},
      headers: {},
      method: "GET",
      ip: "127.0.0.1",
      session: null,
    };

    mockReply = {
      header: jest.fn().mockReturnThis(),
      setCookie: jest.fn().mockReturnThis(),
      clearCookie: jest.fn().mockReturnThis(),
    };

    config = {
      env: "test",
      transport: {
        mode: "hybrid",
        cookie: { name: "sid", httpOnly: true, secure: true, sameSite: "lax" },
        header: { name: "Authorization", scheme: "Bearer" },
      },
      security: { csrf: { enabled: false, mode: "double-submit" } },
    } as unknown as SessionLibraryConfig;
  });

  it("should extract token from Authorization header (Bearer)", async () => {
    let onRequestHook: Function = () => {};
    const fastifyMock = {
      decorateRequest: jest.fn(),
      addHook: jest.fn((hook: string, fn: Function) => {
        if (hook === "onRequest") onRequestHook = fn;
      }),
    } as unknown as FastifyInstance;

    await fastifySessionPlugin(fastifyMock, { service: mockService, config });

    mockRequest.headers = { authorization: "Bearer my_token" };
    mockService.validateSession.mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });

    await onRequestHook(
      mockRequest as FastifyRequest,
      mockReply as FastifyReply,
    );

    expect(mockService.validateSession).toHaveBeenCalledWith(
      expect.objectContaining({
        token: "my_token",
      }),
    );
    expect(mockRequest.session).toBeDefined();
  });

  it("should provide newToken feedback via X-Session-Token header", async () => {
    let onRequestHook: Function = () => {};
    const fastifyMock = {
      decorateRequest: jest.fn(),
      addHook: jest.fn((_: string, fn: Function) => {
        onRequestHook = fn;
      }),
    } as unknown as FastifyInstance;

    await fastifySessionPlugin(fastifyMock, { service: mockService, config });

    mockRequest.headers = { authorization: "Bearer old_token" };
    mockService.validateSession.mockResolvedValue({
      success: true,
      data: createMockSession(),
      newToken: "new_token",
      httpCode: 200,
    });

    await onRequestHook(
      mockRequest as FastifyRequest,
      mockReply as FastifyReply,
    );

    expect(mockReply.header).toHaveBeenCalledWith(
      "X-Session-Token",
      "new_token",
    );
  });

  it("should forward deviceFingerprint from device cookie to service", async () => {
    let onRequestHook: Function = () => {};
    const fastifyMock = {
      decorateRequest: jest.fn(),
      addHook: jest.fn((_: string, fn: Function) => {
        onRequestHook = fn;
      }),
    } as unknown as FastifyInstance;

    const deviceConfig: SessionLibraryConfig = {
      ...config,
      device: { enabled: true, cookie: { name: "device_id" } },
    };

    await fastifySessionPlugin(fastifyMock, {
      service: mockService,
      config: deviceConfig,
    });

    mockRequest.cookies = { device_id: "device_abc_123" };
    mockRequest.headers = { authorization: "Bearer my_token" };
    mockService.validateSession.mockResolvedValue({
      success: true,
      data: createMockSession(),
      httpCode: 200,
    });

    await onRequestHook(
      mockRequest as FastifyRequest,
      mockReply as FastifyReply,
    );

    expect(mockService.validateSession).toHaveBeenCalledWith(
      expect.objectContaining({
        context: expect.objectContaining({
          deviceFingerprint: "device_abc_123",
        }),
      }),
    );
  });
});
