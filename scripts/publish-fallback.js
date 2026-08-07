"use strict";

const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const REGISTRY = "https://registry.npmjs.org/";

function log(message) {
  console.log(`[publish] ${message}`);
}

function warn(message) {
  console.warn(`[publish] WARNING: ${message}`);
}

function fail(message) {
  console.error(`[publish] ERROR: ${message}`);
}

function run(command, args, env) {
  execFileSync(command, args, {
    stdio: "inherit",
    env,
  });
}

function createNpmConfig({ token } = {}) {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "owl-session-guard-npm-"),
  );

  const npmrcPath = path.join(directory, ".npmrc");

  const lines = [
    `registry=${REGISTRY}`,
    "access=public",
  ];

  if (token) {
    lines.push("//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}");
  }

  fs.writeFileSync(npmrcPath, `${lines.join("\n")}\n`, {
    mode: 0o600,
  });

  return {
    directory,
    npmrcPath,
  };
}

function cleanup(directory) {
  if (!directory) {
    return;
  }

  try {
    fs.rmSync(directory, {
      recursive: true,
      force: true,
    });
  } catch {
    warn("Could not remove temporary npm configuration directory.");
  }
}

function createBaseEnvironment() {
  const env = {
    ...process.env,
    npm_config_registry: REGISTRY,
  };

  // Prevent an existing token from overriding Trusted Publishing.
  delete env.NPM_TOKEN;
  delete env.NODE_AUTH_TOKEN;

  return env;
}

function publishWithOidc() {
  const config = createNpmConfig();

  try {
    const env = {
      ...createBaseEnvironment(),
      NPM_CONFIG_USERCONFIG: config.npmrcPath,
    };

    log("Attempting npm Trusted Publishing via GitHub OIDC...");

    run("npm", ["run", "release"], env);

    log("Successfully published using npm Trusted Publishing (OIDC).");

    return true;
  } finally {
    cleanup(config.directory);
  }
}

function publishWithToken(token) {
  const config = createNpmConfig({ token });

  try {
    const env = {
      ...createBaseEnvironment(),

      // NODE_AUTH_TOKEN is referenced by the temporary .npmrc.
      NODE_AUTH_TOKEN: token,

      // Force npm to use our isolated config instead of repository/user
      // configuration that may have been created by another GitHub Action.
      NPM_CONFIG_USERCONFIG: config.npmrcPath,
    };

    log("Verifying fallback npm authentication...");

    run(
      "npm",
      ["whoami", `--registry=${REGISTRY}`],
      env,
    );

    log("Fallback npm authentication verified.");
    log("Publishing using fallback npm token...");

    run("npm", ["run", "release"], env);

    log("Successfully published using fallback npm authentication.");

    return true;
  } finally {
    cleanup(config.directory);
  }
}

function main() {
  let oidcError;

  try {
    if (publishWithOidc()) {
      return;
    }
  } catch (error) {
    oidcError = error;

    warn("OIDC publishing failed.");

    if (typeof error?.status === "number") {
      warn(`OIDC publish exited with status ${error.status}.`);
    }

    warn(
      "This is expected when Trusted Publishing is not configured yet, " +
        "including the initial package bootstrap.",
    );
  }

  const fallbackToken = process.env.FALLBACK_NPM_TOKEN;

  if (!fallbackToken) {
    fail("OIDC publishing failed and no fallback npm token is configured.");

    fail(
      "Configure the GitHub Actions secret NPM_TOKEN with a granular npm " +
        "access token that has permission to publish this package.",
    );

    if (oidcError?.message) {
      fail(`OIDC error: ${oidcError.message}`);
    }

    process.exit(1);
  }

  try {
    publishWithToken(fallbackToken);
  } catch (error) {
    fail("Fallback npm publishing failed.");

    if (typeof error?.status === "number") {
      fail(`Fallback publish exited with status ${error.status}.`);
    }

    if (error?.message) {
      fail(error.message);
    }

    process.exit(1);
  }
}

main();