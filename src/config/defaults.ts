import { SessionLibraryConfig } from "../types";

/**
 * OWASP-aligned secure defaults for the session library.
 */
export const DEFAULT_CONFIG: Partial<SessionLibraryConfig> = {
  transport: {
    mode: "cookie",
    cookie: {
      name: "ossec.sid",
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    },
  },

  expiration: {
    idleTimeoutSeconds: 900, // 15 minutes (NIST/OWASP recommended)
    absoluteTimeoutSeconds: 86400, // 24 hours
    rolling: true,
  },

  rotation: {
    rotateOnLogin: true,
    rotateOnPrivilegeChange: true,
    gracePeriodSeconds: 10,
  },

  security: {
    enforceTlsInProduction: true,
    ipBinding: "soft",
    fingerprinting: "off",
    csrf: {
      enabled: true,
      cookieName: "x-csrf-token",
    },
  },

  limits: {
    maxSessionsPerUser: 5,
  },

  concurrency: {
    lockTimeoutMs: 50,
    pollIntervalMs: 5,
  },

  store: {
    provider: "memory",
  },

  observability: {
    debug: false,
    emitEvents: true,
    metrics: false,
  },
};
