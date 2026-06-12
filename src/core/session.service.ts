import { EventEmitter } from "events";
import { v4 as uuidv4 } from "uuid";
import { ISessionService } from "../interfaces";
import { fastHash, generateBase64UrlToken } from "../infra/crypto/crypto";
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
} from "../types";
import { SessionStoreAdapter } from "../storage/contracts";
import { SessionStateMachine } from "./state-machine";
import { SecurityPolicyEvaluator } from "./security-policy-evaluator";
import { ConfigValidator } from "./config-validator";

/**
 * SessionService — Core session manager supporting locking concurrency queues,
 * Automatic Reuse Detection (ARD) cascading tree revocation, and strongly-typed observability.
 */
export class SessionService implements ISessionService {
  private readonly evaluator: SecurityPolicyEvaluator;
  private readonly events = new EventEmitter();

  constructor(
    private readonly store: SessionStoreAdapter,
    private readonly config: SessionLibraryConfig,
  ) {
    ConfigValidator.validate(config);
    this.evaluator = new SecurityPolicyEvaluator(config);
  }

  /**
   * Register a session security/observability event listener.
   */
  public on(event: string, listener: (...args: unknown[]) => void): this {
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
    try {
      const maxSessions = this.config.limits.maxSessionsPerUser;

      const { token, tokenHash } = this.generateSecureToken();

      const now = new Date();
      const expiresAt = new Date(
        now.getTime() + this.config.expiration.absoluteTimeoutSeconds * 1000,
      );
      const idleExpiresAt = new Date(
        now.getTime() + this.config.expiration.idleTimeoutSeconds * 1000,
      );

      const record: SessionRecord = {
        id: uuidv4(),
        userId: params.userId,
        tokenHash,
        status: SessionStatus.ACTIVE,
        roles: params.roles || [],
        scopes: params.scopes || [],
        createdAt: now,
        lastUsedAt: now,
        expiresAt,
        idleExpiresAt,
        metadata: params.metadata,
        csrfToken: this.config.security.csrf.enabled
          ? generateBase64UrlToken(32)
          : undefined,
      };

      await this.store.create(record, maxSessions);

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
          `User exceeded maximum session limit (${this.config.limits.maxSessionsPerUser})`,
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
      if (evaluation.reason) {
        this.emitSecurityRejection({
          record,
          reason: evaluation.reason,
          message: evaluation.message,
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

    try {
      const { token: newToken, tokenHash: newTokenHash } =
        this.generateSecureToken();

      const now = new Date();

      const newRecord: SessionRecord = {
        ...record,
        id: uuidv4(),
        tokenHash: newTokenHash,
        status: SessionStatus.ACTIVE,
        createdAt: now,
        lastUsedAt: now,
        parentSessionId: record.id,
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
        this.config.limits.maxSessionsPerUser,
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
          `User exceeded maximum session limit (${this.config.limits.maxSessionsPerUser})`,
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
        return {
          success: true,
          data: { acknowledged: true, timestamp: new Date() },
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
   * Revoke all sessions for a user.
   */
  public async revokeAllSessionsForUser(
    userId: string,
    reason: SessionReasonCode,
  ): Promise<SessionOpResult<SessionSuccess>> {
    try {
      await this.store.deleteAllForUser(userId);

      this.emitEvent("user.all_sessions_revoked", {
        userId,
        reason,
        timestamp: new Date(),
      });

      return {
        success: true,
        data: { acknowledged: true, timestamp: new Date() },
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
        limit: params?.limit,
        cursor: params?.cursor,
      });

      const snapshots: SessionSnapshot[] = result.sessions.map((r) =>
        this.toSnapshot(r),
      );

      this.emitEvent("sessions.listed", {
        userId,
        status: params?.status || SessionStatus.ACTIVE,
        count: snapshots.length,
        total: result.total,
        timestamp: new Date(),
      });

      return {
        success: true,
        data: {
          sessions: snapshots,
          total: result.total,
          nextCursor: result.nextCursor,
        },
        httpCode: 200,
      };
    } catch (error) {
      // WHY: Store errors (Redis down, connection timeout) are upstream failures — 502,
      // not 500. 500 implies the server is broken; 502 implies a dependency is broken.
      const message = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        error: {
          code: "STORAGE_ERROR",
          message: `Failed to list sessions: ${message}`,
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

  private emitEvent(event: string, payload: Record<string, unknown>): void {
    if (this.config.observability.emitEvents) {
      this.events.emit(event, payload);
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
   * Projects a full SessionRecord into a safe SessionSnapshot.
   * WHY: Never expose tokenHash, csrfToken, or parent/child linkage to consumers.
   * Roles and scopes ARE included — they're authorization context, not secrets.
   */
  private toSnapshot(record: SessionRecord): SessionSnapshot {
    return {
      sessionId: record.id,
      status: record.status,
      roles: record.roles,
      scopes: record.scopes,
      createdAt: record.createdAt,
      lastUsedAt: record.lastUsedAt,
      expiresAt: record.expiresAt,
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
    let message = "Unknown error";
    if (error instanceof Error) {
      message = error.message;
    } else if (typeof error === "string") {
      message = error;
    }

    return {
      success: false,
      error: {
        code: "INTERNAL_ERROR",
        message: `${context}: ${message}`,
      },
      httpCode: 500,
    };
  }
}
