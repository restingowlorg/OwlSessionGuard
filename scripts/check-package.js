#!/usr/bin/env node
/**
 * Smoke test: Ensures no test artifacts leak into the npm package.
 * Parses `npm pack --json --dry-run` and fails if __tests__, .spec, .test,
 * fixture, or mock files appear in the output.
 */

const { execSync } = require("child_process");

const FORBIDDEN_PATTERNS = [
  /__tests__/,
  /\.spec\./,
  /\.test\./,
  /fixtures/,
  /mocks/,
];

const FORBIDDEN_LABELS = [
  "__tests__",
  ".spec.",
  ".test.",
  "fixtures",
  "mocks",
];

let output;
try {
  output = execSync("npm pack --json --dry-run", {
    encoding: "utf-8",
    stdio: ["pipe", "pipe", "pipe"],
  });
} catch (err) {
  console.error("Failed to run npm pack --dry-run");
  console.error(err.message);
  process.exit(1);
}

let packRaw;
try {
  packRaw = JSON.parse(output);
} catch {
  console.error("Failed to parse npm pack output as JSON");
  process.exit(1);
}

// npm pack --json returns an array; take the first entry.
const pack = Array.isArray(packRaw) ? packRaw[0] : packRaw;
const files = pack.files.map((f) => f.path);
const violations = [];

for (const file of files) {
  for (let i = 0; i < FORBIDDEN_PATTERNS.length; i++) {
    if (FORBIDDEN_PATTERNS[i].test(file)) {
      violations.push({ file, reason: FORBIDDEN_LABELS[i] });
      break;
    }
  }
}

if (violations.length > 0) {
  console.error(
    `\n  FAIL: ${violations.length} test artifact(s) found in package:\n`
  );
  for (const v of violations) {
    console.error(`    - ${v.file} (matched: ${v.reason})`);
  }
  console.error(
    "\n  Remove test files from src/ or update tsconfig.json exclude rules.\n"
  );
  process.exit(1);
}

console.log(`  OK: ${files.length} files in package, no test artifacts.`);
