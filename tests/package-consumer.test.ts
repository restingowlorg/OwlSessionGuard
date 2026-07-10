import * as fs from "fs";
import * as path from "path";

const DIST = path.resolve(__dirname, "..", "dist");

function loadDist(subpath: string) {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require(path.join(DIST, subpath));
}

function declarationExists(subpath: string) {
  const dtsPath = path.join(DIST, subpath.replace(/\.js$/, ".d.ts"));
  return fs.existsSync(dtsPath);
}

describe("Consumer: CommonJS require() against dist/", () => {
  describe("Root import ('.')", () => {
    let mod: Record<string, unknown>;
    beforeAll(() => {
      mod = loadDist("root.js");
    });

    test("should export SessionService as function", () => {
      expect(typeof mod.SessionService).toBe("function");
    });

    test("should export SelectiveRevocationEngine as function", () => {
      expect(typeof mod.SelectiveRevocationEngine).toBe("function");
    });

    test("should export BridgeProcessor as function", () => {
      expect(typeof mod.BridgeProcessor).toBe("function");
    });

    test("should export SessionStatus enum", () => {
      expect(mod.SessionStatus).toBeDefined();
    });

    test("should export SessionReasonCode enum", () => {
      expect(mod.SessionReasonCode).toBeDefined();
    });
  });

  describe("Subpath: ./storage", () => {
    let mod: Record<string, unknown>;
    beforeAll(() => {
      mod = loadDist("storage.js");
    });

    test("should export MemoryStoreAdapter", () => {
      expect(typeof mod.MemoryStoreAdapter).toBe("function");
    });

    test("should export RedisStoreAdapter", () => {
      expect(typeof mod.RedisStoreAdapter).toBe("function");
    });
  });

  describe("Subpath: ./storage/memory", () => {
    let mod: Record<string, unknown>;
    beforeAll(() => {
      mod = loadDist("memory.js");
    });

    test("should export MemoryStoreAdapter", () => {
      expect(typeof mod.MemoryStoreAdapter).toBe("function");
    });

    test("should not export RedisStoreAdapter", () => {
      expect(mod.RedisStoreAdapter).toBeUndefined();
    });
  });

  describe("Subpath: ./storage/redis", () => {
    let mod: Record<string, unknown>;
    beforeAll(() => {
      mod = loadDist("redis.js");
    });

    test("should export RedisStoreAdapter", () => {
      expect(typeof mod.RedisStoreAdapter).toBe("function");
    });

    test("should not export MemoryStoreAdapter", () => {
      expect(mod.MemoryStoreAdapter).toBeUndefined();
    });
  });

  describe("Subpath: ./express", () => {
    let mod: Record<string, unknown>;
    beforeAll(() => {
      mod = loadDist("express.js");
    });

    test("should export createExpressMiddleware", () => {
      expect(typeof mod.createExpressMiddleware).toBe("function");
    });

    test("should export requireSession", () => {
      expect(typeof mod.requireSession).toBe("function");
    });

    test("should not export core APIs", () => {
      expect(mod.SessionService).toBeUndefined();
    });
  });

  describe("Subpath: ./fastify", () => {
    let mod: Record<string, unknown>;
    beforeAll(() => {
      mod = loadDist("fastify.js");
    });

    test("should export fastifySessionPlugin", () => {
      expect(typeof mod.fastifySessionPlugin).toBe("function");
    });

    test("should export fastifyRequireSession", () => {
      expect(typeof mod.fastifyRequireSession).toBe("function");
    });

    test("should not export core APIs", () => {
      expect(mod.SessionService).toBeUndefined();
    });
  });

  describe("Subpath: ./nestjs", () => {
    let mod: Record<string, unknown>;
    beforeAll(() => {
      mod = loadDist("nestjs.js");
    });

    test("should export SessionGuard", () => {
      expect(mod.SessionGuard).toBeDefined();
    });

    test("should export SessionInterceptor", () => {
      expect(mod.SessionInterceptor).toBeDefined();
    });

    test("should export Session decorator", () => {
      expect(typeof mod.Session).toBe("function");
    });

    test("should export RequireRoles decorator", () => {
      expect(typeof mod.RequireRoles).toBe("function");
    });

    test("should export RequireScopes decorator", () => {
      expect(typeof mod.RequireScopes).toBe("function");
    });

    test("should not export core APIs", () => {
      expect(mod.SessionService).toBeUndefined();
    });
  });
});

describe("Consumer: TypeScript declarations", () => {
  const subpaths = [
    "root.d.ts",
    "index.d.ts",
    "storage.d.ts",
    "memory.d.ts",
    "redis.d.ts",
    "express.d.ts",
    "fastify.d.ts",
    "nestjs.d.ts",
  ];

  test.each(subpaths)("%s should exist", (file) => {
    expect(fs.existsSync(path.join(DIST, file))).toBe(true);
  });

  test("root.d.ts should re-export from core modules", () => {
    const content = fs.readFileSync(path.join(DIST, "root.d.ts"), "utf-8");
    expect(content).toContain("session.service");
    expect(content).toContain("selective-revocation-engine");
    expect(content).toContain("bridge");
  });

  test("storage.d.ts should re-export from adapter modules", () => {
    const content = fs.readFileSync(path.join(DIST, "storage.d.ts"), "utf-8");
    expect(content).toContain("memory.adapter");
    expect(content).toContain("redis.adapter");
    expect(content).toContain("contracts");
  });

  test("express.d.ts should declare createExpressMiddleware", () => {
    const content = fs.readFileSync(path.join(DIST, "express.d.ts"), "utf-8");
    expect(content).toContain("createExpressMiddleware");
  });

  test("fastify.d.ts should declare fastifySessionPlugin", () => {
    const content = fs.readFileSync(path.join(DIST, "fastify.d.ts"), "utf-8");
    expect(content).toContain("fastifySessionPlugin");
  });

  test("nestjs.d.ts should declare SessionGuard", () => {
    const content = fs.readFileSync(path.join(DIST, "nestjs.d.ts"), "utf-8");
    expect(content).toContain("SessionGuard");
  });

  test("nestjs.d.ts should declare SessionInterceptor", () => {
    const content = fs.readFileSync(path.join(DIST, "nestjs.d.ts"), "utf-8");
    expect(content).toContain("SessionInterceptor");
  });
});

describe("Consumer: Exports map matches dist/", () => {
  const pkg = require("../package.json");

  const subpaths = [".", "./storage", "./storage/memory", "./storage/redis", "./express", "./fastify", "./nestjs"];

  test.each(subpaths)('exports map entry "%s" should point to existing dist file', (subpath) => {
    const entry = pkg.exports[subpath];
    expect(entry).toBeDefined();
    expect(entry.require).toBeDefined();
    expect(entry.types).toBeDefined();

    const jsPath = path.join(DIST, entry.require.replace("./dist/", ""));
    const dtsPath = path.join(DIST, entry.types.replace("./dist/", ""));

    expect(fs.existsSync(jsPath)).toBe(true);
    expect(fs.existsSync(dtsPath)).toBe(true);
  });
});
