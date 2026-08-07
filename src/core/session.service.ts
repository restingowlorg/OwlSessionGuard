import { EventEmitter } from "events";
import { v4 as uuidv4 } from "uuid";
import { ISessionService } from "../interfaces";
import {
  fastHash,
  generateBase64UrlToken,
  hmacSign,
  CSRF_SIGNING_PREFIX,
} from "../infra/crypto/crypto";
import {
  SessionOpResult,
  CreateSessionParams,
  ValidateSessionParams,
  RotateSessionParams,
  RevokeSessionParams,
  SessionRecord,
  SessionStatus,
  SessionReasonCode,
  SessionLibraryConfig,
  SessionSuccess,
  SecurityEvaluationContext,
  SecurityEvaluationResult,
  SessionSnapshot,
  SessionListParams,
  SessionLimits,
  DeviceOS,
  DeviceBrowser,
  DeviceType,
  FALLBACK_FP_PREFIX,
} from "../types";
import { SessionStoreAdapter } from "../storage/contracts";
import { SessionStateMachine } from "./state-machine";
import { SecurityPolicyEvaluator } from "./security-policy-evaluator";
import { ConfigValidator } from "./config-validator";
import { DeviceContextExtractor } from "./device-context-extractor";
import { SelectiveRevocationEngine } from "./selective-revocation-engine";

/**
 * SessionService — Core session manager supporting locking concurrency queues,
 * Automatic Reuse Detection (ARD) cascading tree revocation, and strongly-typed observability.
 */
export class SessionService implements ISessionService {
  private readonly evaluator: SecurityPolicyEvaluator;
  private readonly events = new EventEmitter();
  private readonly revocationEngine: SelectiveRevocationEngine;

  constructor(
    private readonly store: SessionStoreAdapter,
    private readonly config: SessionLibraryConfig,
  ) {
    ConfigValidator.validate(config);
    this.evaluator = new SecurityPolicyEvaluator(config);
    // WHY: Engine receives emitEvent bound to this instance so events go through
    // the same isolated listener dispatch as all other SessionService events.
    this.revocationEngine = new SelectiveRevocationEngine(
      this.store,
      this.emitEvent.bind(this),
    );
  }

  /**
   * Expose the selective revocation engine for targeted session killing.
   * WHY: Keeps SessionService focused on CRUD/validate/rotate while
   * delegating bulk revocation concerns to a dedicated component.
   */
  public get selectiveRevocation(): SelectiveRevocationEngine {
    return this.revocationEngine;
  }

  /**
   * Register a session security/observability event listener.
   * Listeners are dispatched asynchronously via setImmediate() with per-listener
   * error isolation — one throwing listener never silences the rest.
   * Async functions are safe; rejections are caught by the internal try-catch.
   */
  public on(event: string, listener: (...args: unknown[]) => void): this {
    // WHY: Async listeners return uncaught Promises because emitEvent() wraps
    // each listener in setImmediate() + try-catch, which only catches synchronous
    // throws. Detect at registration time to warn developers.
    if (listener.constructor.name === "AsyncFunction") {
      console.warn(
        `[OWL SESSION GUARD] Event listener for '${event}' is async. ` +
          `Synchronous listeners only — async rejections will be unhandled. ` +
          `Wrap async logic in setImmediate().`,
      );
    }
    this.events.on(event, listener);
    return this;
  }

  /**
   * Deregister a session security/observability event listener.
   */
  public off(event: string, listener: (...args: unknown[]) => void): this {
    this.events.off(event, listener);
    return this;
  }

  /**
   * Create a new session.
   */
  public async createSession(params: CreateSessionParams): Promise<
    SessionOpResult<{
      token: string;
      record: SessionRecord;
    }>
  > {
    const limits = this.resolveLimits();
    try {
      const { token, tokenHash } = this.generateSecureToken();

      const now = new Date();
      const expiresAt = new Date(
        now.getTime() + this.config.expiration.absoluteTimeoutSeconds * 1000,
      );
      const idleExpiresAt = new Date(
        now.getTime() + this.config.expiration.idleTimeoutSeconds * 1000,
      );

      let deviceFingerprint: string;
      let deviceContext: Record<string, string | number | boolean>;
      try {
        const extracted = DeviceContextExtractor.extract(params.metadata);
        deviceFingerprint = extracted.deviceFingerprint;
        deviceContext = extracted.deviceContext;
      } catch (extractorError) {
        // Defensive boundary: Ensure session creation never fails due to parsing errors
        this.emitEvent("security.extractor_failed", {
          userId: params.userId,
          error:
            extractorError instanceof Error
              ? extractorError.message
              : String(extractorError),
          metadata: params.metadata,
          timestamp: now,
        });
        deviceFingerprint = `${FALLBACK_FP_PREFIX}${uuidv4()}`;
        deviceContext = {
          os: DeviceOS.UNKNOWN,
          browser: DeviceBrowser.UNKNOWN,
          type: DeviceType.UNKNOWN,
        };
      }

      const sessionId = uuidv4();
      const record: SessionRecord = {
        id: sessionId,
        userId: params.userId,
        tokenHash,
        status: SessionStatus.ACTIVE,
        roles: params.roles || [],
        scopes: params.scopes || [],
        createdAt: now,
        lastUsedAt: now,
        expiresAt,
        idleExpiresAt,
        metadata: {
          ...params.metadata,
          deviceFingerprint,
          deviceContext,
        },
        csrfToken: this.config.security.csrf.enabled
          ? this.signCsrfToken(sessionId)
          : undefined,
      };

      if (deviceFingerprint.startsWith(FALLBACK_FP_PREFIX)) {
        this.emitEvent("session.fallback_fingerprint", {
          sessionId: record.id,
          userId: record.userId,
          deviceContext,
          timestamp: now,
        });
      }

      await this.store.create(record, limits);

      // Emit session creation event
      this.emitEvent("session.created", {
        sessionId: record.id,
        userId: record.userId,
        timestamp: now,
      });

      return {
        success: true,
        data: { token, record },
        httpCode: 201,
        newCsrfToken: record.csrfToken,
      };
    } catch (error: unknown) {
      if (error instanceof Error && error.message === "SESSION_LIMIT_REACHED") {
        return this.fail(
          `User exceeded maximum session limit`,
          403,
          SessionReasonCode.SECURITY_BREACH,
        );
      }
      return this.handleError("Failed to create session", error);
    }
  }

  /**
   * Validate a session token.
   */
  public async validateSession(
    params: ValidateSessionParams,
  ): Promise<SessionOpResult<SessionRecord>> {
    try {
      const tokenHash = fastHash(params.token);
      let record = await this.store.findByTokenHash(tokenHash);

      if (!record) {
        return this.fail("Invalid session token", 401, undefined, true);
      }

      const lockResult = await this.handleRotationLockQueue(record);
      if (!lockResult.success) {
        return this.fail(
          "Concurrent request timeout - session locked",
          401,
          undefined,
          true,
        );
      }
      record = lockResult.record;

      const now = new Date();
      const evaluationContext: SecurityEvaluationContext = {
        ipAddress: params.context.ipAddress,
        userAgent: params.context.userAgent,
        deviceFingerprint: params.context.deviceFingerprint,
        method: params.context.method || "GET",
        csrfToken: params.csrfToken,
      };

      // Invoke Pipeline Policy Guard
      const evaluation = this.evaluator.evaluate(
        record,
        evaluationContext,
        now,
      );

      if (!evaluation.isValid) {
        const reason = evaluation.reason || SessionReasonCode.SECURITY_BREACH;
        await this.handlePolicyViolation(
          record,
          evaluation,
          evaluationContext,
          reason,
        );

        return this.fail(
          evaluation.message || "Security violation",
          401,
          reason,
          true,
        );
      }

      // Soft context binding warnings
      // WHY: softWarning is set by the evaluator for soft mismatches (IP, User-Agent, fingerprint).
      // Full details are emitted to the secure event boundary — never exposed in the result.
      if (evaluation.softWarning) {
        this.emitSecurityRejection({
          record,
          reason: SessionReasonCode.SECURITY_BREACH,
          context: evaluationContext,
        });
      }

      // Rolling expiration update
      if (this.config.expiration.rolling) {
        const updates: Partial<SessionRecord> = {
          lastUsedAt: now,
          idleExpiresAt: new Date(
            now.getTime() + this.config.expiration.idleTimeoutSeconds * 1000,
          ),
        };
        await this.store.update(record.id, updates);
        Object.assign(record, updates);
      }

      return {
        success: true,
        data: record,
        httpCode: 200,
      };
    } catch (error) {
      return this.handleError("Validation error", error);
    }
  }

  /**
   * Rotate a session token.
   */
  public async rotateSession(params: RotateSessionParams): Promise<
    SessionOpResult<{
      newToken: string;
      record: SessionRecord;
    }>
  > {
    const oldTokenHash = fastHash(params.token);
    const record = await this.store.findByTokenHash(oldTokenHash);

    if (
      !record ||
      !SessionStateMachine.isValidTransition(
        record.status,
        SessionStatus.ROTATED,
      )
    ) {
      return this.fail("Invalid or unusable session for rotation", 401);
    }

    // Set up transition lock key (Mitigated: 500ms max TTL)
    const lockKey = `lock:rotate:${record.id}`;
    if (this.store.acquireLock) {
      const acquired = await this.store.acquireLock(lockKey, 500);
      if (!acquired) {
        return this.fail("Session rotation already in progress", 409);
      }
    }

    const limits = this.resolveLimits();

    try {
      // WHY: Run security evaluation before rotation to enforce IP binding,
      // fingerprinting, and CSRF policies. This prevents unauthorized rotation
      // from compromised contexts. Only run if context is provided (backward compat).
      const now = new Date();
      if (params.context) {
        const evaluationContext: SecurityEvaluationContext = {
          ipAddress: params.context.ipAddress,
          userAgent: params.context.userAgent,
          deviceFingerprint: params.context.deviceFingerprint,
          method: "GET", // WHY: Skip CSRF gate — rotation is internal, not a user action
          csrfToken: undefined, // Rotation does not require CSRF validation
        };

        const evaluation = this.evaluator.evaluate(
          record,
          evaluationContext,
          now,
        );
        if (!evaluation.isValid) {
          const reason = evaluation.reason || SessionReasonCode.SECURITY_BREACH;
          await this.handlePolicyViolation(
            record,
            evaluation,
            evaluationContext,
            reason,
          );
          return this.fail(
            evaluation.message || "Security violation during rotation",
            401,
            reason,
            true,
          );
        }
      }

      const { token: newToken, tokenHash: newTokenHash } =
        this.generateSecureToken();

      const newSessionId = uuidv4();
      const newRecord: SessionRecord = {
        ...record,
        id: newSessionId,
        tokenHash: newTokenHash,
        status: SessionStatus.ACTIVE,
        createdAt: now,
        lastUsedAt: now,
        parentSessionId: record.id,
        csrfToken: this.config.security.csrf.enabled
          ? this.signCsrfToken(newSessionId)
          : record.csrfToken,
        ...(params.roles ? { roles: params.roles } : {}),
      };

      const oldUpdates: Partial<SessionRecord> = {
        status: SessionStatus.ROTATED,
        revokedAt: now,
        childSessionId: newRecord.id, // Direct pointer link for ARD traversal
        revocationReason: params.reason || SessionReasonCode.ROTATION,
      };

      // Atomic rotation in database adapter
      await this.store.rotate(
        record.id,
        newRecord,
        oldUpdates,
        limits,
        record.roles,
      );

      // Emit rotation success event
      this.emitEvent("session.rotated", {
        oldSessionId: record.id,
        newSessionId: newRecord.id,
        userId: record.userId,
        timestamp: now,
      });

      return {
        success: true,
        data: { newToken, record: newRecord },
        httpCode: 200,
        newCsrfToken: newRecord.csrfToken,
      };
    } catch (error: unknown) {
      if (error instanceof Error && error.message === "SESSION_LIMIT_REACHED") {
        return this.fail(
          `User exceeded maximum session limit`,
          403,
          SessionReasonCode.SECURITY_BREACH,
        );
      }
      return this.handleError("Rotation error", error);
    } finally {
      // Guarantee lock release even if database write fails (Anti-Hang Mitigation)
      if (this.store.releaseLock) {
        await this.store.releaseLock(lockKey);
      }
    }
  }

  /**
   * Revoke a specific session.
   */
  public async revokeSession(
    params: RevokeSessionParams,
  ): Promise<SessionOpResult<SessionSuccess>> {
    try {
      let record: SessionRecord | null = null;

      if (params.token) {
        record = await this.store.findByTokenHash(fastHash(params.token));
      } else if (params.sessionId) {
        record = await this.store.findById(params.sessionId);
      }

      if (!record) return this.fail("Session not found", 404);

      if (
        !SessionStateMachine.isValidTransition(
          record.status,
          SessionStatus.REVOKED,
        )
      ) {
        this.emitEvent("session.already_revoked", {
          sessionId: record.id,
          userId: record.userId,
          timestamp: new Date(),
        });
        return {
          success: true,
          data: {
            acknowledged: true,
            timestamp: new Date(),
            alreadyRevoked: true,
          },
          httpCode: 200,
          clearCsrfToken: true,
        };
      }

      await this.store.update(record.id, {
        status: SessionStatus.REVOKED,
        revokedAt: new Date(),
        revocationReason: params.reason,
      });

      // Emit revocation event
      this.emitEvent("session.revoked", {
        sessionId: record.id,
        userId: record.userId,
        reason: params.reason,
        timestamp: new Date(),
      });

      return {
        success: true,
        data: { acknowledged: true, timestamp: new Date() },
        httpCode: 200,
        clearCsrfToken: true,
      };
    } catch (error) {
      return this.handleError("Revocation error", error);
    }
  }

  /**
   * Revoke all sessions for a user (soft-revoke, preserves audit trail).
   * WHY: Delegates to SelectiveRevocationEngine for consistent soft-revocation
   * behavior across all bulk revocation operations.
   */
  public async revokeAllSessionsForUser(
    userId: string,
    reason: SessionReasonCode,
  ): Promise<SessionOpResult<SessionSuccess>> {
    try {
      const result = await this.revocationEngine.revokeAllForUser(
        userId,
        reason,
      );

      if (!result.success) {
        return {
          success: false,
          error: result.error,
          httpCode: result.httpCode,
          clearCsrfToken: true,
        };
      }

      return {
        success: true,
        data: {
          acknowledged: true,
          timestamp: result.data.timestamp,
          alreadyRevoked: result.data.revokedCount === 0,
          failedSessionIds:
            result.data.failedSessionIds.length > 0
              ? result.data.failedSessionIds
              : undefined,
        },
        httpCode: 200,
        clearCsrfToken: true,
      };
    } catch (error) {
      return this.handleError("Failed to revoke all sessions", error);
    }
  }

  /**
   * List sessions for a user with pagination.
   * Returns safe snapshots — no token hashes, no CSRF tokens, no session tree linkage.
   */
  public async listUserSessions(
    userId: string,
    params?: SessionListParams,
  ): Promise<
    SessionOpResult<{
      sessions: SessionSnapshot[];
      total: number;
      totalIsApproximate: boolean;
      nextCursor: string | null;
    }>
  > {
    // WHY: OWASP A03 — assume all input is malicious. Reject empty/invalid userId
    // at the boundary rather than letting it propagate to the store layer.
    if (!userId || typeof userId !== "string") {
      return this.fail("Invalid userId: must be a non-empty string", 400);
    }

    try {
      const result = await this.store.findAllForUser(userId, {
        status: params?.status,
      });

      let sessions = result.sessions;

      // 1. Service-layer Filtering
      if (params?.deviceFingerprint) {
        sessions = sessions.filter(
          (s) => s.metadata?.deviceFingerprint === params.deviceFingerprint,
        );
      }
      if (params?.role) {
        sessions = sessions.filter((s) => s.roles?.includes(params.role!));
      }
      if (params?.issuedBefore) {
        const threshold = new Date(params.issuedBefore).getTime();
        if (isNaN(threshold)) {
          return this.fail("Invalid issuedBefore: must be a valid date", 400);
        }
        sessions = sessions.filter((s) => s.createdAt.getTime() < threshold);
      }

      // 2. Pagination
      const limit = Math.min(Math.max(params?.limit || 20, 1), 100);
      const cursor = params?.cursor;
      const total = sessions.length;

      let startIndex = 0;
      if (cursor) {
        const cursorIndex = sessions.findIndex((s) => s.id === cursor);
        if (cursorIndex < 0) {
          // Cursor not found (e.g. deleted session)
          sessions = [];
        } else {
          startIndex = cursorIndex + 1;
        }
      }

      const page = sessions.slice(startIndex, startIndex + limit);
      const nextCursor =
        startIndex + limit < total ? page[page.length - 1]?.id || null : null;

      const snapshots: SessionSnapshot[] = page.map((r) => this.toSnapshot(r));

      this.emitEvent("sessions.listed", {
        userId,
        status: params?.status || SessionStatus.ACTIVE,
        count: snapshots.length,
        total,
        timestamp: new Date(),
      });

      return {
        success: true,
        data: {
          sessions: snapshots,
          total,
          // WHY: totalIsApproximate reflects whether the adapter's scan was truncated
          // (e.g., Redis SCAN timeout or 10K cap). After service-layer filtering,
          // the total is the filtered count, but the flag still indicates whether
          // the adapter saw ALL sessions. If the adapter truncated, the filtered
          // total is also approximate. Consumers should show "X+" when true.
          totalIsApproximate: result.totalIsApproximate,
          nextCursor,
        },
        httpCode: 200,
      };
    } catch (error) {
      // WHY: Store errors (Redis down, connection timeout) are upstream failures — 502,
      // not 500. 500 implies the server is broken; 502 implies a dependency is broken.
      const errorId = uuidv4();
      const errorClass = error instanceof Error ? error.name : "UnknownError";

      this.emitEvent("internal_error", {
        context: "listUserSessions",
        errorClass,
        category: "storage",
        errorId,
        timestamp: new Date(),
      });
      return {
        success: false,
        error: {
          code: "STORAGE_ERROR",
          message: "Failed to list sessions",
        },
        httpCode: 502,
      };
    }
  }

  /**
   * Recursively revokes a session and its descendants (Automatic Reuse Detection).
   */
  private async revokeSessionTree(
    sessionId: string,
    reason: SessionReasonCode,
    visited: Set<string> = new Set(),
    affectedIds: string[] = [],
  ): Promise<string[]> {
    if (visited.has(sessionId)) return affectedIds;
    visited.add(sessionId);

    const record = await this.store.findById(sessionId);
    if (!record) return affectedIds;

    if (record.status !== SessionStatus.REVOKED) {
      await this.store.update(record.id, {
        status: SessionStatus.REVOKED,
        revokedAt: new Date(),
        revocationReason: reason,
      });

      affectedIds.push(record.id);

      this.emitEvent("session.revoked", {
        sessionId: record.id,
        userId: record.userId,
        reason,
        timestamp: new Date(),
      });
    }

    if (record.childSessionId) {
      await this.revokeSessionTree(
        record.childSessionId,
        reason,
        visited,
        affectedIds,
      );
    }

    return affectedIds;
  }

  private async handleRotationLockQueue(
    record: SessionRecord,
  ): Promise<{ success: boolean; record: SessionRecord }> {
    const lockKey = `lock:rotate:${record.id}`;

    if (record.status === SessionStatus.ROTATED && this.store.isLocked) {
      let isLocked = await this.store.isLocked(lockKey);
      if (isLocked) {
        const startTime = Date.now();
        const capMs = this.config.concurrency?.lockTimeoutMs || 50;
        const retryIntervalMs = this.config.concurrency?.pollIntervalMs || 5;

        while (isLocked && Date.now() - startTime < capMs) {
          await new Promise((resolve) => setTimeout(resolve, retryIntervalMs));
          isLocked = await this.store.isLocked(lockKey);
        }

        if (isLocked) {
          return { success: false, record };
        }

        const updatedRecord = await this.store.findById(record.id);
        if (updatedRecord) {
          return { success: true, record: updatedRecord };
        }
      }
    }
    return { success: true, record };
  }

  private async handlePolicyViolation(
    record: SessionRecord,
    evaluation: SecurityEvaluationResult,
    evaluationContext: SecurityEvaluationContext,
    reason: SessionReasonCode,
  ): Promise<void> {
    let affectedSessionIds: string[] | undefined;
    if (evaluation.actionRequired === "revoke") {
      await this.revokeSession({ sessionId: record.id, reason });
    } else if (evaluation.actionRequired === "revoke_tree") {
      affectedSessionIds = await this.revokeSessionTree(record.id, reason);
    }

    this.emitSecurityRejection({
      record,
      reason,
      message: evaluation.message,
      affectedSessionIds,
      context: evaluationContext,
    });
  }

  private generateSecureToken(): { token: string; tokenHash: string } {
    const token = generateBase64UrlToken(32);
    const tokenHash = fastHash(token);
    return { token, tokenHash };
  }

  // WHY: HMAC binds the CSRF token to a specific session ID.
  // Validates that the token belongs to this session, not another.
  // Prefix ensures domain separation — same session ID used for a different
  // purpose (e.g. API key signing) produces a different HMAC.
  private signCsrfToken(sessionId: string): string {
    const { csrf } = this.config.security;
    if (!csrf.enabled) {
      throw new Error("CSRF must be enabled for signed tokens");
    }
    return hmacSign(`${CSRF_SIGNING_PREFIX}${sessionId}`, csrf.secret);
  }

  private emitEvent(event: string, payload: Record<string, unknown>): void {
    if (this.config.observability.emitEvents) {
      // WHY: Shallow-clone the payload to prevent listener-to-listener corruption.
      // EventEmitter.emit() passes the same object reference to every registered
      // listener. If listener A mutates the payload (e.g. payload.userId = "HACKED"),
      // listener B sees the corrupted data. A shallow clone ensures each listener
      // gets its own copy.
      const safePayload = { ...payload };

      // WHY: Iterate listeners individually with per-listener try-catch instead of
      // using this.events.emit(). EventEmitter.emit() stops at the first throwing
      // listener and subsequent listeners never run. Our approach ensures one faulty
      // listener never silences the rest.
      //
      // WHY: setImmediate defers listener execution so a buggy or malicious listener
      // (e.g. while(true) {}) blocks only its own tick, not the critical session
      // lifecycle path. The session response is sent before any listener runs.
      const listeners = this.events.rawListeners(event);
      for (const listener of listeners) {
        setImmediate(() => {
          try {
            listener(safePayload);
          } catch (listenerError) {
            console.error(
              `[OWL SESSION GUARD] Telemetry listener threw on event '${event}':`,
              listenerError,
            );
          }
        });
      }
    }
  }

  private emitSecurityRejection(params: {
    record: SessionRecord;
    reason: SessionReasonCode;
    message?: string;
    affectedSessionIds?: string[];
    context?: SecurityEvaluationContext;
  }): void {
    this.emitEvent("security.rejection", {
      sessionId: params.record.id,
      userId: params.record.userId,
      reason: params.reason,
      message: params.message,
      affectedSessionIds: params.affectedSessionIds,
      expectedIp: params.record.metadata?.ipAddress,
      actualIp: params.context?.ipAddress,
      expectedUserAgent: params.record.metadata?.userAgent,
      actualUserAgent: params.context?.userAgent,
      timestamp: new Date(),
    });
  }

  /**
   * Resolves the effective session limits for a set of roles.
   * WHY: Returns a full SessionLimits object so the store adapter can enforce
   * BOTH the global user cap and per-role caps in a single atomic operation.
   * The global cap is ALWAYS the configured maxSessionsPerUser.
   * Role-specific limits are independent counters — the store checks both
   * caps and rejects if EITHER is exceeded.
   */
  private resolveLimits(): SessionLimits {
    return {
      maxSessionsPerUser: this.config.limits.maxSessionsPerUser,
      maxSessionsPerRole: this.config.limits.maxSessionsPerRole,
    };
  }

  /**
   * Projects a full SessionRecord into a safe SessionSnapshot.
   * WHY: Never expose tokenHash, csrfToken, or parent/child linkage to consumers.
   * Roles and scopes ARE included — they're authorization context, not secrets.
   * Device label is derived from deviceContext — sanitized, not raw.
   */
  private toSnapshot(record: SessionRecord): SessionSnapshot {
    const dc = record.metadata?.deviceContext;
    let deviceLabel: string | undefined;
    if (dc) {
      const parts = [dc.os, dc.browser, dc.deviceType].filter(Boolean);
      if (parts.length > 0) {
        deviceLabel = parts.join(" — ");
      }
    }

    return {
      sessionId: record.id,
      status: record.status,
      roles: record.roles,
      scopes: record.scopes,
      createdAt: record.createdAt,
      lastUsedAt: record.lastUsedAt,
      expiresAt: record.expiresAt,
      deviceLabel,
    };
  }

  private fail<T>(
    message: string,
    httpCode: number,
    reason?: SessionReasonCode,
    clearCsrfToken?: boolean,
  ): SessionOpResult<T> {
    return {
      success: false,
      error: {
        code: "SESSION_ERROR",
        message,
        reason,
      },
      httpCode,
      ...(clearCsrfToken ? { clearCsrfToken: true } : {}),
    };
  }

  private handleError<T>(context: string, error: unknown): SessionOpResult<T> {
    const errorId = uuidv4();
    const errorClass = error instanceof Error ? error.name : "UnknownError";

    this.emitEvent("internal_error", {
      context,
      errorClass,
      category: "storage",
      errorId,
      timestamp: new Date(),
    });

    console.error(
      `[OWL SESSION GUARD] INTERNAL_ERROR in ${context} (${errorId})`,
    );

    return {
      success: false,
      error: {
        code: "INTERNAL_ERROR",
        message: context,
      },
      httpCode: 500,
    };
  }
}
