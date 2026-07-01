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

  // Selective Revocation
  DEVICE_LOGOUT = "device_logout",
  ROLE_DEPRECATED = "role_deprecated",
  TIMESTAMP_PURGE = "timestamp_purge",
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
 * WHY: failedSessionIds surfaces partial revocation failures so callers
 * can retry or alert — silently swallowing them was a design gap.
 */
export interface SessionSuccess {
  acknowledged: boolean;
  timestamp: Date;
  alreadyRevoked?: boolean;
  failedSessionIds?: string[];
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
  /**
   * Optional new role set for the rotated session.
   * WHY: Rotation is used for privilege changes (e.g. USER → SUPER_ADMIN).
   * When provided, the new session inherits these roles instead of the old roles.
   * The store enforces limits against the NEW roles — so a privilege elevation
   * correctly evaluates the SUPER_ADMIN limit, not the USER limit.
   */
  roles?: string[];
}

export interface RevokeSessionParams {
  token?: string;
  sessionId?: string;
  reason: SessionReasonCode;
}

/**
 * Parameters for selective revocation by device fingerprint.
 * WHY: Allows targeting a single device (e.g., lost phone) without affecting other sessions.
 */
export interface RevokeByDeviceParams {
  userId: string;
  deviceFingerprint: string;
  reason: SessionReasonCode;
  excludeSessionId?: string;
}

/**
 * Parameters for selective revocation by timestamp.
 * WHY: Critical for password resets — kills all old sessions while keeping the one
 * the user just used to change their password.
 */
export interface RevokeBeforeTimestampParams {
  userId: string;
  issuedBefore: Date;
  reason: SessionReasonCode;
  keepSessionId?: string;
}

/**
 * Parameters for selective revocation by role.
 * WHY: Useful when a role is compromised or deprecated — kills all sessions
 * holding that specific permission.
 */
export interface RevokeByRoleParams {
  userId: string;
  role: string;
  reason: SessionReasonCode;
  excludeSessionId?: string;
}

/**
 * Result of a bulk revocation operation.
 * WHY: Reports both succeeded and failed session IDs so callers can handle
 * partial revocation (e.g., retry failed ones, alert on partial failure).
 */
export interface RevocationResult {
  revokedCount: number;
  revokedSessionIds: string[];
  failedSessionIds: string[];
  timestamp: Date;
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
    gracePeriodSeconds?: number;
  };

  security: {
    enforceTlsInProduction: boolean;
    ipBinding: "off" | "soft" | "hard";
    fingerprinting: "off" | "soft" | "hard";
    csrf:
      | { enabled: false; cookieName?: string; headerName?: string }
      | {
          enabled: true;
          secret: string;
          previousSecret?: string;
          cookieName?: string;
          headerName?: string;
        };
  };

  device?: {
    enabled: boolean;
    cookie?: {
      name?: string;
      httpOnly?: boolean;
      secure?: boolean;
      sameSite?: "lax" | "strict" | "none";
      path?: string;
      domain?: string;
      maxAgeSeconds?: number;
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
 * Session limit configuration passed to store adapters atomically.
 * WHY: Role limits must be independent counters — the store checks BOTH
 * the global user cap and the per-role cap in a single atomic operation.
 */
export interface SessionLimits {
  maxSessionsPerUser: number;
  maxSessionsPerRole?: Record<string, number>;
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

/**
 * Safe projection of a session record for external consumption.
 * Strips all secrets (tokenHash, csrfToken) and internal linkage (parentSessionId, childSessionId).
 */
export interface SessionSnapshot {
  sessionId: string;
  status: SessionStatus;
  roles: string[];
  scopes: string[];
  createdAt: Date;
  lastUsedAt: Date;
  expiresAt: Date;
  /** Derived device label (e.g. "Windows PC — Chrome"). Sanitized — no raw deviceContext exposed. */
  deviceLabel?: string;
}

/**
 * Parameters for querying sessions via the store adapter.
 */
export interface SessionListParams {
  status?: SessionStatus;
  limit?: number;
  cursor?: string;
}

/**
 * Paginated result from a session listing query.
 * WARNING: This is a store-internal type. Consumers should use the service-layer
 * return type which returns SessionSnapshot[], not SessionRecord[].
 */
export interface SessionListResult {
  sessions: SessionRecord[];
  total: number;
  /** When true, total is approximate (SCAN hit timeout or 10K cap). UI should show "X+" not "X". */
  totalIsApproximate: boolean;
  nextCursor: string | null;
}

/** Result shape returned by a validateFn to BridgeProcessor.handle(). */
export interface ValidateResult {
  success: boolean;
  data?: SessionRecord;
  error?: { message: string; httpCode: number };
  newToken?: string;
  newCsrfToken?: string;
  clearCsrfToken?: boolean;
}

/** Callback signature for validateFn passed to BridgeProcessor.handle(). */
export type ValidateFunction = (
  token: string,
  clientInfo: {
    ipAddress: string;
    userAgent?: string;
    method: string;
    csrfToken?: string;
    deviceFingerprint?: string;
  },
) => Promise<ValidateResult>;
