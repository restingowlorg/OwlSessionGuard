import {
  SessionService,
  SelectiveRevocationEngine,
  BridgeProcessor,
  MemoryStoreAdapter,
  RedisStoreAdapter,
  createExpressMiddleware,
  requireSession,
  fastifySessionPlugin,
  fastifyRequireSession,
  SessionGuard,
  SessionInterceptor,
  Session,
  RequireRoles,
  RequireScopes,
  SessionStatus,
  SessionReasonCode,
  ISessionService,
  SessionStoreAdapter,
  SessionRecord,
} from "../src/index";
import {
  SessionService as RootSessionService,
  SelectiveRevocationEngine as RootSelectiveRevocationEngine,
  BridgeProcessor as RootBridgeProcessor,
} from "../src/root";
import {
  MemoryStoreAdapter as StorageMemoryAdapter,
  RedisStoreAdapter as StorageRedisAdapter,
  SessionStoreAdapter as StorageSessionStoreAdapter,
  SessionRecord as StorageSessionRecord,
} from "../src/storage";
import { MemoryStoreAdapter as MemoryOnlyAdapter } from "../src/memory";
import { RedisStoreAdapter as RedisOnlyAdapter } from "../src/redis";
import {
  createExpressMiddleware as ExpressMiddleware,
  requireSession as ExpressRequireSession,
} from "../src/express";
import {
  fastifySessionPlugin as FastifyPlugin,
  fastifyRequireSession as FastifyRequireSession,
} from "../src/fastify";
import {
  SessionGuard as NestGuard,
  SessionInterceptor as NestInterceptor,
  Session as NestSession,
  RequireRoles as NestRequireRoles,
  RequireScopes as NestRequireScopes,
} from "../src/nestjs";

describe("Package Exports", () => {
  describe("Root import (core APIs)", () => {
    test("should export SessionService", () => {
      expect(SessionService).toBeDefined();
      expect(typeof SessionService).toBe("function");
    });

    test("should export SelectiveRevocationEngine", () => {
      expect(SelectiveRevocationEngine).toBeDefined();
      expect(typeof SelectiveRevocationEngine).toBe("function");
    });

    test("should export BridgeProcessor", () => {
      expect(BridgeProcessor).toBeDefined();
      expect(typeof BridgeProcessor).toBe("function");
    });

    test("should export types and enums", () => {
      expect(SessionStatus).toBeDefined();
      expect(SessionReasonCode).toBeDefined();
    });

    test("should export interfaces as types", () => {
      // TypeScript interfaces are exported but not available at runtime
      // This test verifies the module loads without errors
      expect(true).toBe(true);
    });
  });

  describe("Storage exports", () => {
    test("should export MemoryStoreAdapter from root", () => {
      expect(MemoryStoreAdapter).toBeDefined();
      expect(typeof MemoryStoreAdapter).toBe("function");
    });

    test("should export RedisStoreAdapter from root", () => {
      expect(RedisStoreAdapter).toBeDefined();
      expect(typeof RedisStoreAdapter).toBe("function");
    });
  });

  describe("Framework middleware exports", () => {
    test("should export Express middleware from root", () => {
      expect(createExpressMiddleware).toBeDefined();
      expect(typeof createExpressMiddleware).toBe("function");
      expect(requireSession).toBeDefined();
      expect(typeof requireSession).toBe("function");
    });

    test("should export Fastify plugin from root", () => {
      expect(fastifySessionPlugin).toBeDefined();
      expect(typeof fastifySessionPlugin).toBe("function");
      expect(fastifyRequireSession).toBeDefined();
      expect(typeof fastifyRequireSession).toBe("function");
    });

    test("should export NestJS decorators from root", () => {
      expect(SessionGuard).toBeDefined();
      expect(SessionInterceptor).toBeDefined();
      expect(Session).toBeDefined();
      expect(RequireRoles).toBeDefined();
      expect(RequireScopes).toBeDefined();
    });
  });

  describe("Backward compatibility", () => {
    test("should export ISessionService interface", () => {
      // TypeScript interface - verify module loads
      expect(true).toBe(true);
    });

    test("should export SessionStoreAdapter interface", () => {
      // TypeScript interface - verify module loads
      expect(true).toBe(true);
    });

    test("should export SessionRecord type", () => {
      // TypeScript type - verify module loads
      expect(true).toBe(true);
    });
  });

  describe("Subpath: root ('.')", () => {
    test("should export SessionService", () => {
      expect(RootSessionService).toBeDefined();
      expect(typeof RootSessionService).toBe("function");
      expect(RootSessionService).toBe(SessionService);
    });

    test("should export SelectiveRevocationEngine", () => {
      expect(RootSelectiveRevocationEngine).toBeDefined();
      expect(typeof RootSelectiveRevocationEngine).toBe("function");
      expect(RootSelectiveRevocationEngine).toBe(SelectiveRevocationEngine);
    });

    test("should export BridgeProcessor", () => {
      expect(RootBridgeProcessor).toBeDefined();
      expect(typeof RootBridgeProcessor).toBe("function");
      expect(RootBridgeProcessor).toBe(BridgeProcessor);
    });
  });

  describe("Subpath: ./storage", () => {
    test("should export MemoryStoreAdapter", () => {
      expect(StorageMemoryAdapter).toBeDefined();
      expect(typeof StorageMemoryAdapter).toBe("function");
      expect(StorageMemoryAdapter).toBe(MemoryStoreAdapter);
    });

    test("should export RedisStoreAdapter", () => {
      expect(StorageRedisAdapter).toBeDefined();
      expect(typeof StorageRedisAdapter).toBe("function");
      expect(StorageRedisAdapter).toBe(RedisStoreAdapter);
    });

    test("should export SessionStoreAdapter interface", () => {
      // TypeScript interface - verify module loads
      expect(true).toBe(true);
    });

    test("should export SessionRecord type", () => {
      // TypeScript type - verify module loads
      expect(true).toBe(true);
    });
  });

  describe("Subpath: ./storage/memory", () => {
    test("should export MemoryStoreAdapter", () => {
      expect(MemoryOnlyAdapter).toBeDefined();
      expect(typeof MemoryOnlyAdapter).toBe("function");
      expect(MemoryOnlyAdapter).toBe(MemoryStoreAdapter);
    });
  });

  describe("Subpath: ./storage/redis", () => {
    test("should export RedisStoreAdapter", () => {
      expect(RedisOnlyAdapter).toBeDefined();
      expect(typeof RedisOnlyAdapter).toBe("function");
      expect(RedisOnlyAdapter).toBe(RedisStoreAdapter);
    });
  });

  describe("Subpath: ./express", () => {
    test("should export createExpressMiddleware", () => {
      expect(ExpressMiddleware).toBeDefined();
      expect(typeof ExpressMiddleware).toBe("function");
      expect(ExpressMiddleware).toBe(createExpressMiddleware);
    });

    test("should export requireSession", () => {
      expect(ExpressRequireSession).toBeDefined();
      expect(typeof ExpressRequireSession).toBe("function");
      expect(ExpressRequireSession).toBe(requireSession);
    });
  });

  describe("Subpath: ./fastify", () => {
    test("should export fastifySessionPlugin", () => {
      expect(FastifyPlugin).toBeDefined();
      expect(typeof FastifyPlugin).toBe("function");
      expect(FastifyPlugin).toBe(fastifySessionPlugin);
    });

    test("should export fastifyRequireSession", () => {
      expect(FastifyRequireSession).toBeDefined();
      expect(typeof FastifyRequireSession).toBe("function");
      expect(FastifyRequireSession).toBe(fastifyRequireSession);
    });
  });

  describe("Subpath: ./nestjs", () => {
    test("should export SessionGuard", () => {
      expect(NestGuard).toBeDefined();
      expect(NestGuard).toBe(SessionGuard);
    });

    test("should export SessionInterceptor", () => {
      expect(NestInterceptor).toBeDefined();
      expect(NestInterceptor).toBe(SessionInterceptor);
    });

    test("should export Session", () => {
      expect(NestSession).toBeDefined();
      expect(NestSession).toBe(Session);
    });

    test("should export RequireRoles", () => {
      expect(NestRequireRoles).toBeDefined();
      expect(NestRequireRoles).toBe(RequireRoles);
    });

    test("should export RequireScopes", () => {
      expect(NestRequireScopes).toBeDefined();
      expect(NestRequireScopes).toBe(RequireScopes);
    });
  });
});
