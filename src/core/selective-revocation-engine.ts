import { SessionStoreAdapter } from "../storage/contracts";
import {
  SessionStatus,
  SessionReasonCode,
  SessionOpResult,
  RevocationResult,
  RevokeByDeviceParams,
  RevokeBeforeTimestampParams,
  RevokeByRoleParams,
} from "../types";

// WHY: Prevent DoS via oversized input strings. Matches DeviceContextExtractor's 512-char cap.
const MAX_INPUT_LENGTH = 512;

// WHY: Per-session timeout to prevent a slow store from blocking the revocation loop.
// Each store.update gets 10s. With maxSessionsPerUser (typically 5-10), worst case is ~50-100s.
const REVOKE_TIMEOUT_MS = 10_000;

/**
 * SelectiveRevocationEngine — Surgical session killing across 4 target dimensions.
 * WHY: Extracted from SessionService to keep the core service focused on CRUD/validate/rotate
 * while this engine handles targeted bulk revocation with audit trail preservation.
 */
export class SelectiveRevocationEngine {
  constructor(
    private readonly store: SessionStoreAdapter,
    private readonly emitEvent: (
      event: string,
      payload: Record<string, unknown>,
    ) => void,
  ) {}

  /**
   * Nuclear option: soft-revoke ALL sessions for a user.
   * WHY: Uses adapter's atomic revokeAllForUser when available, falls back to
   * fetchLiveSessions + update loop for adapters that don't implement it.
   */
  async revokeAllForUser(
    userId: string,
    reason: SessionReasonCode,
  ): Promise<SessionOpResult<RevocationResult>> {
    try {
      const validationError = this.validateString(userId, "userId");
      if (validationError) return validationError;
      const reasonError = this.validateReason(reason);
      if (reasonError) return reasonError;

      const revokedAt = new Date();
      let revoked: string[];
      let failed: string[];

      if (this.store.revokeAllForUser) {
        // WHY: Atomic adapter method — no per-session failure granularity.
        // All-or-nothing: either all are revoked or the adapter throws.
        revoked = await this.store.revokeAllForUser(userId, reason, revokedAt);
        failed = [];
      } else {
        const sessions = await this.fetchLiveSessions(userId);
        const result = await this.revokeSessions(sessions, reason, revokedAt);
        revoked = result.revoked;
        failed = result.failed;
      }

      const result: RevocationResult = {
        revokedCount: revoked.length,
        revokedSessionIds: revoked,
        failedSessionIds: failed,
        timestamp: revokedAt,
      };

      this.emitBatchEvent("all", revokedAt, {
        userId,
        reason,
        count: result.revokedCount,
        sessionIds: revoked,
        failedSessionIds: failed,
      });
      this.emitSessionEvents(revoked, userId, reason, revokedAt);

      return { success: true, data: result, httpCode: 200 };
    } catch (error) {
      return this.handleError("revokeAllForUser", error);
    }
  }

  /**
   * Kill sessions by device fingerprint (e.g., logging out of a lost phone).
   * WHY: Targets a single device without affecting other user sessions.
   */
  async revokeByDevice(
    params: RevokeByDeviceParams,
  ): Promise<SessionOpResult<RevocationResult>> {
    try {
      const validationError = this.validateRevokeParams(params);
      if (validationError) return validationError;

      const { userId, deviceFingerprint, reason, excludeSessionId } = params;
      const revokedAt = new Date();
      const sessions = await this.fetchLiveSessions(userId);
      const toRevoke = sessions.filter(
        (s) =>
          s.metadata?.deviceFingerprint === deviceFingerprint &&
          s.id !== excludeSessionId,
      );

      return this.executeRevocation(toRevoke, "device", revokedAt, {
        userId,
        deviceFingerprint,
        reason,
      });
    } catch (error) {
      return this.handleError("revokeByDevice", error);
    }
  }

  /**
   * Kill sessions older than a date (critical for password resets).
   * WHY: Preserves the current session while revoking all others —
   * the caller explicitly passes keepSessionId to avoid accidental self-lockout.
   */
  async revokeBeforeTimestamp(
    params: RevokeBeforeTimestampParams,
  ): Promise<SessionOpResult<RevocationResult>> {
    try {
      const validationError = this.validateTimestampParams(params);
      if (validationError) return validationError;

      const { userId, issuedBefore, reason, keepSessionId } = params;
      const revokedAt = new Date();
      const sessions = await this.fetchLiveSessions(userId);
      const toRevoke = sessions.filter(
        (s) => s.createdAt < issuedBefore && s.id !== keepSessionId,
      );

      return this.executeRevocation(toRevoke, "timestamp", revokedAt, {
        userId,
        issuedBefore,
        reason,
      });
    } catch (error) {
      return this.handleError("revokeBeforeTimestamp", error);
    }
  }

  /**
   * Kill all sessions holding a specific role (e.g., deprecated or compromised role).
   * WHY: Useful when a role is compromised — revokes only sessions with that permission.
   */
  async revokeByRole(
    params: RevokeByRoleParams,
  ): Promise<SessionOpResult<RevocationResult>> {
    try {
      const validationError = this.validateRoleParams(params);
      if (validationError) return validationError;

      const { userId, role, reason, excludeSessionId } = params;
      const revokedAt = new Date();
      const sessions = await this.fetchLiveSessions(userId);
      const toRevoke = sessions.filter(
        (s) => s.roles.includes(role) && s.id !== excludeSessionId,
      );

      return this.executeRevocation(toRevoke, "role", revokedAt, {
        userId,
        role,
        reason,
      });
    } catch (error) {
      return this.handleError("revokeByRole", error);
    }
  }

  // ─── Private Helpers ────────────────────────────────────────────

  /**
   * WHY: Generic revocation execution — eliminates copy-paste across all 4 methods.
   * Handles: revoke → emit → result. Single responsibility.
   */
  private async executeRevocation(
    sessions: { id: string; userId?: string }[],
    target: string,
    revokedAt: Date,
    context: Record<string, unknown>,
  ): Promise<SessionOpResult<RevocationResult>> {
    const { revoked, failed } = await this.revokeSessions(
      sessions,
      context.reason as SessionReasonCode,
      revokedAt,
    );

    const result: RevocationResult = {
      revokedCount: revoked.length,
      revokedSessionIds: revoked,
      failedSessionIds: failed,
      timestamp: revokedAt,
    };

    this.emitBatchEvent(target, revokedAt, {
      ...context,
      count: result.revokedCount,
      sessionIds: revoked,
      failedSessionIds: failed,
    });
    this.emitSessionEvents(
      revoked,
      context.userId as string,
      context.reason as SessionReasonCode,
      revokedAt,
    );

    return { success: true, data: result, httpCode: 200 };
  }

  /**
   * WHY: Uses store.findLiveSessionsForUser when available (efficient, only ACTIVE + ROTATED).
   * Falls back to findAllForUser + filter for adapters that don't implement it.
   * No redundant REVOKED/EXPIRED checks downstream — this method guarantees clean input.
   */
  private async fetchLiveSessions(userId: string) {
    if (this.store.findLiveSessionsForUser) {
      return this.store.findLiveSessionsForUser(userId);
    }
    const result = await this.store.findAllForUser(userId, { limit: 10000 });
    return result.sessions.filter(
      (s) =>
        s.status !== SessionStatus.REVOKED &&
        s.status !== SessionStatus.EXPIRED,
    );
  }

  /**
   * WHY: Revokes sessions sequentially with per-session timeout protection.
   * Returns both succeeded and failed IDs for partial-result reporting.
   * WHY timeout: Prevents a slow store from blocking the entire loop indefinitely.
   * A single slow update should not prevent remaining sessions from being revoked.
   */
  private async revokeSessions(
    sessions: { id: string }[],
    reason: SessionReasonCode,
    revokedAt: Date,
  ): Promise<{ revoked: string[]; failed: string[] }> {
    const revoked: string[] = [];
    const failed: string[] = [];

    for (const session of sessions) {
      try {
        await this.withTimeout(
          this.store.update(session.id, {
            status: SessionStatus.REVOKED,
            revokedAt,
            revocationReason: reason,
          }),
          REVOKE_TIMEOUT_MS,
        );
        revoked.push(session.id);
      } catch {
        failed.push(session.id);
      }
    }

    return { revoked, failed };
  }

  /**
   * WHY: Wraps a promise with a timeout. If the operation takes too long,
   * rejects with a clear error instead of hanging indefinitely.
   */
  private withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("STORE_UPDATE_TIMEOUT")),
        ms,
      );
      promise.then(
        (val) => {
          clearTimeout(timer);
          resolve(val);
        },
        (err) => {
          clearTimeout(timer);
          reject(err);
        },
      );
    });
  }

  // ─── Validation ──────────────────────────────────────────────────

  private validateString(
    value: string,
    field: string,
  ): SessionOpResult<RevocationResult> | null {
    if (!value || typeof value !== "string") {
      return this.fail(`${field} must be a non-empty string`, 400);
    }
    if (value.length > MAX_INPUT_LENGTH) {
      return this.fail(
        `${field} must not exceed ${MAX_INPUT_LENGTH} characters`,
        400,
      );
    }
    return null;
  }

  private validateReason(
    reason: SessionReasonCode,
  ): SessionOpResult<RevocationResult> | null {
    if (!Object.values(SessionReasonCode).includes(reason)) {
      return this.fail(`reason must be a valid SessionReasonCode`, 400);
    }
    return null;
  }

  private validateRevokeParams(
    params: RevokeByDeviceParams,
  ): SessionOpResult<RevocationResult> | null {
    const userIdErr = this.validateString(params.userId, "userId");
    if (userIdErr) return userIdErr;
    const fpErr = this.validateString(
      params.deviceFingerprint,
      "deviceFingerprint",
    );
    if (fpErr) return fpErr;
    return this.validateReason(params.reason);
  }

  private validateTimestampParams(
    params: RevokeBeforeTimestampParams,
  ): SessionOpResult<RevocationResult> | null {
    const userIdErr = this.validateString(params.userId, "userId");
    if (userIdErr) return userIdErr;
    if (
      !(params.issuedBefore instanceof Date) ||
      isNaN(params.issuedBefore.getTime())
    ) {
      return this.fail("issuedBefore must be a valid Date", 400);
    }
    return this.validateReason(params.reason);
  }

  private validateRoleParams(
    params: RevokeByRoleParams,
  ): SessionOpResult<RevocationResult> | null {
    const userIdErr = this.validateString(params.userId, "userId");
    if (userIdErr) return userIdErr;
    const roleErr = this.validateString(params.role, "role");
    if (roleErr) return roleErr;
    return this.validateReason(params.reason);
  }

  // ─── Event Emission ─────────────────────────────────────────────

  // WHY: Emit errors are caught to prevent poisoning the return value.
  // Store writes are already committed — a failing listener should not
  // make the caller think the revocation failed.
  private emitBatchEvent(
    target: string,
    timestamp: Date,
    payload: Record<string, unknown>,
  ): void {
    try {
      this.emitEvent("batch.revoked", { target, timestamp, ...payload });
    } catch (emitError) {
      console.error("[OSSEC] batch.revoked emit failed:", emitError);
    }
  }

  private emitSessionEvents(
    sessionIds: string[],
    userId: string,
    reason: SessionReasonCode,
    timestamp: Date,
  ): void {
    for (const sid of sessionIds) {
      try {
        this.emitEvent("session.revoked", {
          sessionId: sid,
          userId,
          reason,
          timestamp,
        });
      } catch (emitError) {
        console.error("[OSSEC] session.revoked emit failed:", emitError);
      }
    }
  }

  // ─── Error Handling ─────────────────────────────────────────────

  private fail<T>(
    message: string,
    httpCode: number,
    reason?: SessionReasonCode,
  ): SessionOpResult<T> {
    return {
      success: false,
      error: { code: "SESSION_ERROR", message, reason },
      httpCode,
    };
  }

  private handleError<T>(context: string, error: unknown): SessionOpResult<T> {
    let message = "Unknown error";
    if (error instanceof Error) {
      message = error.message;
    } else if (typeof error === "string") {
      message = error;
    }

    this.emitEvent("internal_error", {
      context,
      message,
      error:
        error instanceof Error
          ? { name: error.name, message: error.message, stack: error.stack }
          : String(error),
      timestamp: new Date(),
    });

    console.error(`[OSSEC] INTERNAL_ERROR in ${context}:`, error);

    return {
      success: false,
      error: { code: "INTERNAL_ERROR", message: `${context}: ${message}` },
      httpCode: 500,
    };
  }
}
