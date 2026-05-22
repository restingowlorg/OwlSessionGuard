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
 * Contextual metadata for a session, used for binding and fingerprinting.
 */
export interface SessionMetadata {
  ipAddress: string;
  userAgent?: string;
  deviceFingerprint?: string;
  deviceContext?: Record<string, string | number | boolean>;
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
  metadata: SessionMetadata;

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
    };

/**
 * Explicit success result for operations that don't return data.
 */
export interface SessionSuccess {
  acknowledged: boolean;
  timestamp: Date;
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
  context: SessionMetadata & { method?: string };
}

export interface RotateSessionParams {
  token: string;
  context: SessionMetadata & { method?: string };
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
      mode: "double-submit" | "external";
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
}
