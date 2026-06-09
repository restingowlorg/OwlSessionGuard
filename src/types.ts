import { SessionStoreAdapter } from "./storage/contracts";

/**
 * Session status enum representing the current lifecycle stage of a session.
 */
export enum SessionStatus {
  ACTIVE = "active",
  ROTATED = "rotated",
  REVOKED = "revoked",
  EXPIRED = "expired",
}

/**
 * Typed reason codes for session state changes, used for auditing and debugging.
 */
export enum SessionReasonCode {
  // Normal operations
  MANUAL_LOGOUT = "manual_logout",
  ROTATION = "rotation",

  // Expiration
  IDLE_TIMEOUT = "idle_timeout",
  ABSOLUTE_TIMEOUT = "absolute_timeout",
  ROTATION_GRACE_EXPIRED = "rotation_grace_expired",

  // Security violations
  IP_MISMATCH = "ip_mismatch",
  DEVICE_MISMATCH = "device_mismatch",
  FINGERPRINT_MISMATCH = "fingerprint_mismatch",
  CSRF_VIOLATION = "csrf_violation",
  SECURITY_BREACH = "security_breach",

  // Administrative
  ADMIN_REVOKED = "admin_revoked",
  USER_ALL_SESSIONS_REVOKED = "user_all_sessions_revoked",
}

/**
 * Strictly typed enums for Device Context to prevent magic string typos.
 */
export enum DeviceOS {
  WINDOWS = "Windows",
  MAC_OS = "Mac OS",
  LINUX = "Linux",
  IOS = "iOS",
  ANDROID = "Android",
  UNKNOWN = "Unknown",
}

export enum DeviceBrowser {
  CHROME = "Chrome",
  FIREFOX = "Firefox",
  SAFARI = "Safari",
  EDGE = "Edge",
  OPERA = "Opera",
  UNKNOWN = "Unknown",
}

export enum DeviceType {
  DESKTOP = "Desktop",
  MOBILE = "Mobile",
  TABLET = "Tablet",
  UNKNOWN = "Unknown",
}

/**
 * Consumer-supplied session metadata. The `deviceFingerprint` is intentionally
 * absent here because it is computed internally by DeviceContextExtractor and
 * stored on the SessionRecord. Allowing consumers to write it directly would
 * break the API contract and open a spoofing vector.
 */
export interface SessionMetadata {
  ipAddress: string;
  userAgent?: string;
  deviceId?: string; // WHY: Persistent cookie-based device identifier (OWASP Gold Standard).
  deviceContext?: Record<string, string | number | boolean>;
}

/**
 * WHY: This prefix is defined as a shared constant — not a magic string — because
 * both DeviceContextExtractor (writer) and SecurityPolicyEvaluator (reader) must
 * agree on the same boundary marker. A mismatch would cause a silent global
 * logout of all fallback-fingerprinted sessions with no compiler warning.
 */
export const FALLBACK_FP_PREFIX = "fallback_" as const;

/**
 * The resolved device context attached to a stored session after extraction.
 * Separated from SessionMetadata to enforce the read/write boundary:
 * consumers write SessionMetadata, the library writes ResolvedDeviceContext.
 */
export interface ResolvedDeviceContext {
  deviceFingerprint: string;
  deviceContext: Record<string, string | number | boolean>;
}

/**
 * The full session record as stored in the session store.
 */
export interface SessionRecord {
  id: string;
  userId: string;
  tokenHash: string;
  status: SessionStatus;

  // Authorization
  roles: string[];
  scopes: string[];

  // Lifespan
  createdAt: Date;
  lastUsedAt: Date;
  expiresAt: Date;
  idleExpiresAt: Date;

  // Security Binding
  // WHY: Non-partial — every record emitted by SessionService.createSession() will
  // always have deviceFingerprint and deviceContext set by DeviceContextExtractor.
  // Test fixtures that do not test fingerprinting must use createBaseRecord() helper.
  metadata: SessionMetadata & ResolvedDeviceContext;
  csrfToken?: string; // State-bound double submit CSRF token

  // Revocation
  revokedAt?: Date;
  revocationReason?: SessionReasonCode;

  // Hierarchy/Tracing
  parentSessionId?: string; // Used for rotation tracking
  childSessionId?: string; // Pointer to descendant session generated during rotation
}

/**
 * Standard response wrapper for session operations.
 */
export type SessionOpResult<T> =
  | {
      success: true;
      data: T;
      httpCode: number;
      newToken?: string;
      newCsrfToken?: string;
      clearCsrfToken?: boolean;
      error?: never;
    }
  | {
      success: false;
      data?: never;
      error: {
        code: string;
        message: string;
        reason?: SessionReasonCode;
      };
      httpCode: number;
      clearCsrfToken?: boolean;
    };

/**
 * Explicit success result for operations that don't return data.
 */
export interface SessionSuccess {
  acknowledged: boolean;
  timestamp: Date;
  alreadyRevoked?: boolean;
}

/**
 * Service operation parameters
 */
export interface CreateSessionParams {
  userId: string;
  roles?: string[];
  scopes?: string[];
  metadata: SessionMetadata;
}

export interface ValidateSessionParams {
  token: string;
  csrfToken?: string; // Optional client-provided CSRF token for validation
  context: SessionMetadata & {
    method?: string;
    // WHY: deviceFingerprint is only accepted here (read/verify path), not on
    // CreateSessionParams (write path). On creation, the library generates it.
    // On validation, the consumer supplies the stored cookie value for comparison.
    deviceFingerprint?: string;
  };
}

export interface RotateSessionParams {
  token: string;
  context: SessionMetadata & {
    method?: string;
    deviceFingerprint?: string; // Same rationale as ValidateSessionParams
  };
  reason?: SessionReasonCode;
}

export interface RevokeSessionParams {
  token?: string;
  sessionId?: string;
  reason: SessionReasonCode;
}

/**
 * Configuration for the Session Management Library
 */
export interface SessionLibraryConfig {
  env: "development" | "test" | "production";

  transport: {
    mode: "cookie" | "header" | "hybrid";
    cookie?: {
      name: string;
      httpOnly: boolean;
      secure: boolean;
      signed?: boolean;
      sameSite: "lax" | "strict" | "none";
      path?: string;
      domain?: string;
      maxAgeSeconds?: number;
    };
    header?: {
      name: string;
      scheme?: string;
      responseHeader?: string;
    };
  };

  expiration: {
    idleTimeoutSeconds: number;
    absoluteTimeoutSeconds: number;
    rolling: boolean;
  };

  rotation: {
    rotateOnLogin: boolean;
    rotateOnPrivilegeChange: boolean;
    gracePeriodSeconds: number;
  };

  security: {
    enforceTlsInProduction: boolean;
    ipBinding: "off" | "soft" | "hard";
    fingerprinting: "off" | "soft" | "hard";
    csrf: {
      enabled: boolean;
      cookieName?: string;
      headerName?: string;
    };
  };

  limits: {
    maxSessionsPerUser: number;
    maxSessionsPerRole?: Record<string, number>;
  };

  concurrency?: {
    lockTimeoutMs?: number;
    pollIntervalMs?: number;
  };

  store: {
    provider: "memory" | "redis" | "mongo" | "postgres" | "custom";
    redis?: {
      url: string;
      keyPrefix?: string;
      ttlBufferSeconds?: number;
    };
    mongo?: {
      uri: string;
      collectionName?: string;
    };
    postgres?: {
      url: string;
      tableName?: string;
    };
    custom?: {
      adapter: SessionStoreAdapter;
    };
  };

  observability: {
    debug: boolean;
    emitEvents: boolean;
    metrics: boolean;
  };
}

/**
 * Security evaluation context containing current request metadata.
 */
export interface SecurityEvaluationContext {
  ipAddress: string;
  userAgent?: string;
  deviceFingerprint?: string;
  method: string; // HTTP method of the current request (used to enforce read-only grace checks)
  csrfToken?: string; // Client-provided CSRF token
}

/**
 * Result of a security policy evaluation.
 */
export interface SecurityEvaluationResult {
  isValid: boolean;
  isWithinGracePeriod: boolean;
  actionRequired?: "revoke" | "revoke_tree" | "none";
  reason?: SessionReasonCode;
  message?: string;
  /** Signals a soft security mismatch for event emission without exposing details in the result. */
  softWarning?: boolean;
}
