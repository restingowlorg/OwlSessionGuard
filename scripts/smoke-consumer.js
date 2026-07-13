#!/usr/bin/env node
/**
 * Consumer Smoke Test
 *
 * Creates an isolated temporary project, installs the packed tarball
 * with production peer dependencies, and verifies that all public
 * subpath exports resolve correctly via CommonJS require().
 *
 * Exit 0 = all exports resolve. Exit 1 = at least one import failed.
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const PKG_ROOT = path.resolve(__dirname, "..");
const PKG_NAME = require(path.join(PKG_ROOT, "package.json")).name;

const SUBPATHS = [
  { specifier: PKG_NAME, label: "root" },
  { specifier: `${PKG_NAME}/storage`, label: "./storage" },
  { specifier: `${PKG_NAME}/storage/memory`, label: "./storage/memory" },
  { specifier: `${PKG_NAME}/storage/redis`, label: "./storage/redis" },
  { specifier: `${PKG_NAME}/express`, label: "./express" },
  { specifier: `${PKG_NAME}/fastify`, label: "./fastify" },
  { specifier: `${PKG_NAME}/nestjs`, label: "./nestjs" },
];

const EXPECTED_EXPORTS = {
  root: ["SessionService", "SessionStatus", "SessionReasonCode"],
  "./storage": ["MemoryStoreAdapter", "RedisStoreAdapter"],
  "./storage/memory": ["MemoryStoreAdapter"],
  "./storage/redis": ["RedisStoreAdapter"],
  "./express": ["createExpressMiddleware", "requireSession"],
  "./fastify": ["fastifySessionPlugin", "fastifyRequireSession"],
  "./nestjs": ["SessionGuard", "SessionInterceptor", "Session", "RequireRoles", "RequireScopes"],
};

function cleanup(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // best-effort cleanup
  }
}

function run(cmd, opts) {
  return execSync(cmd, { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"], ...opts });
}

// ── Step 1: npm pack ─────────────────────────────────────────────────────
console.log("\n[smoke] Packing tarball...");
const packOutput = run("npm pack --json --pack-destination .", { cwd: PKG_ROOT });
const packResult = JSON.parse(packOutput);
const tgzFile = Array.isArray(packResult) ? packResult[0].filename : packResult.filename;
const tgzPath = path.join(PKG_ROOT, tgzFile);
console.log(`[smoke] Created ${tgzFile}`);

// ── Step 2: Create temp project ──────────────────────────────────────────
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "owl-session-smoke-"));
console.log(`[smoke] Temp project: ${tmpDir}`);

try {
  // ── Step 3: npm init + install ────────────────────────────────────────
  run("npm init -y", { cwd: tmpDir });
  console.log("[smoke] Installing tarball + peer deps...");
  run(`npm install ${tgzPath} express fastify @nestjs/common @nestjs/core rxjs`, {
    cwd: tmpDir,
    timeout: 120000,
  });

  // ── Step 4: CommonJS require checks ──────────────────────────────────
  console.log("\n[smoke] Testing CommonJS imports...");
  let failures = 0;

  for (const { specifier, label } of SUBPATHS) {
    try {
      const script = `const m = require("${specifier}"); const keys = Object.keys(m); console.log(JSON.stringify(keys));`;
      const output = run(`node -e "${script}"`, { cwd: tmpDir });
      const keys = JSON.parse(output.trim());

      const expected = EXPECTED_EXPORTS[label] || [];
      for (const exp of expected) {
        if (!keys.includes(exp)) {
          console.error(`  FAIL [${label}] — missing export: ${exp}`);
          failures++;
        }
      }

      if (failures === 0) {
        console.log(`  OK   [${label}] — ${keys.length} exports`);
      }
    } catch (err) {
      const stderr = err.stderr || err.message || "";
      console.error(`  FAIL [${label}] — require failed: ${stderr.split("\n")[0]}`);
      failures++;
    }
  }

  // ── Step 5: TypeScript declaration check ──────────────────────────────
  console.log("\n[smoke] Testing TypeScript declarations...");
  const tsContent = SUBPATHS.map(
    ({ specifier }) => `import * as ${specifier.replace(/[@\/]/g, "_")} from "${specifier}";`
  ).join("\n") + "\nconsole.log('TypeScript imports OK');\n";

  fs.writeFileSync(path.join(tmpDir, "test.ts"), tsContent);
  fs.writeFileSync(
    path.join(tmpDir, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          module: "commonjs",
          moduleResolution: "node",
          esModuleInterop: true,
          strict: true,
          noEmit: true,
          skipLibCheck: false,
          types: [],
        },
        include: ["test.ts"],
      },
      null,
      2
    )
  );

  try {
    run("npx tsc --noEmit", { cwd: tmpDir, timeout: 60000 });
    console.log("  OK   TypeScript declarations resolve");
  } catch (err) {
    const stderr = err.stderr || err.message || "";
    console.error(`  FAIL TypeScript declarations: ${stderr.split("\n")[0]}`);
    failures++;
  }

  // ── Step 6: Report ────────────────────────────────────────────────────
  console.log("");
  if (failures > 0) {
    console.error(`[smoke] FAILED — ${failures} import(s) did not resolve`);
    process.exit(1);
  }

  console.log("[smoke] PASSED — all exports resolve correctly");
} finally {
  cleanup(tmpDir);
  // Clean up tarball
  try {
    fs.unlinkSync(tgzPath);
  } catch {
    // ignore
  }
}
