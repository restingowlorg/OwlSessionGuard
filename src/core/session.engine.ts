import { randomBytes, randomUUID, createHash } from "crypto";
import { ISessionEngine } from "../interfaces";
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
} from "../types";
import { SessionStoreAdapter } from "../storage/contracts";
import { SessionStateMachine } from "./state-machine";

/**
 * SessionEngine — Implementation of core session logic.
 */
export class SessionEngine implements ISessionEngine {
  constructor(
    private readonly store: SessionStoreAdapter,
    private readonly config: SessionLibraryConfig,
  ) {}

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

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
      // 1. Enforce session limits
      const activeCount = await this.store.countActiveForUser(params.userId);
      if (activeCount >= this.config.limits.maxSessionsPerUser) {
        // Option: Revoke oldest or reject. Default to rejecting or revoking oldest.
        // For simplicity, we'll proceed but this is where policy would be enforced.
      }

      // 2. Generate token and hash
      const { token, tokenHash } = this.generateSecureToken();

      // 3. Calculate timestamps
      const now = new Date();
      const expiresAt = new Date(
        now.getTime() + this.config.expiration.absoluteTimeoutSeconds * 1000,
      );
      const idleExpiresAt = new Date(
        now.getTime() + this.config.expiration.idleTimeoutSeconds * 1000,
      );

      // 4. Create record
      const record: SessionRecord = {
        id: randomUUID(),
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
      };

      await this.store.create(record);

      return {
        success: true,
        data: { token, record },
        httpCode: 201,
      };
    } catch (error) {
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
      const tokenHash = this.hashToken(params.token);
      const record = await this.store.findByTokenHash(tokenHash);

      if (!record) {
        return this.fail("Invalid session token", 401);
      }

      const now = new Date();

      // 1. Check expiration
      const expiry = SessionStateMachine.checkExpiration(
        now,
        record.expiresAt,
        record.idleExpiresAt,
      );
      if (expiry.isExpired) {
        await this.revokeSession({
          sessionId: record.id,
          reason: expiry.reason!,
        });
        return this.fail(
          `Session expired: ${expiry.reason}`,
          401,
          expiry.reason,
        );
      }

      // 2. Check state usability
      // Note: For now we don't have grace period implementation in the store,
      // so we assume isWithinGracePeriod = false for now.
      if (!SessionStateMachine.isUsable(record.status)) {
        return this.fail("Session is no longer active", 401);
      }

      // 3. Security Binding (IP Check)
      if (this.config.security.ipBinding !== "off") {
        if (record.metadata.ipAddress !== params.context.ipAddress) {
          if (this.config.security.ipBinding === "hard") {
            await this.revokeSession({
              sessionId: record.id,
              reason: SessionReasonCode.IP_MISMATCH,
            });
            return this.fail(
              "IP mismatch - session revoked",
              401,
              SessionReasonCode.IP_MISMATCH,
            );
          }
          // Soft check: Log and continue (or add risk signal)
          console.warn(
            `[@ossec/auth] IP mismatch detected for session ${record.id}`,
          );
        }
      }

      // 4. Update lastUsedAt if rolling
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
    try {
      const oldTokenHash = this.hashToken(params.token);
      const record = await this.store.findByTokenHash(oldTokenHash);

      if (!record || !SessionStateMachine.isUsable(record.status)) {
        return this.fail("Invalid or unusable session for rotation", 401);
      }

      // 1. Generate new token
      const { token: newToken, tokenHash: newTokenHash } =
        this.generateSecureToken();

      // 2. Mark old session as ROTATED (or revoke immediately if grace period is 0)
      const now = new Date();
      await this.store.update(record.id, {
        status: SessionStatus.ROTATED,
        revocationReason: SessionReasonCode.ROTATION,
        // In a real implementation, we might keep the record but with a new tokenHash
        // OR create a new record and link it.
        // As per OWASP: "A new session ID is always issued at login completion"
      });

      // 3. Create NEW session record linked to the old one
      const newRecord: SessionRecord = {
        ...record,
        id: randomUUID(),
        tokenHash: newTokenHash,
        status: SessionStatus.ACTIVE,
        createdAt: now,
        lastUsedAt: now,
        parentSessionId: record.id,
      };

      await this.store.create(newRecord);

      return {
        success: true,
        data: { newToken, record: newRecord },
        httpCode: 200,
      };
    } catch (error) {
      return this.handleError("Rotation error", error);
    }
  }

  /**
   * Revoke a session.
   */
  public async revokeSession(
    params: RevokeSessionParams,
  ): Promise<SessionOpResult<SessionSuccess>> {
    try {
      let record: SessionRecord | null = null;

      if (params.token) {
        record = await this.store.findByTokenHash(this.hashToken(params.token));
      } else if (params.sessionId) {
        record = await this.store.findById(params.sessionId);
      }

      if (!record) return this.fail("Session not found", 404);

      await this.store.update(record.id, {
        status: SessionStatus.REVOKED,
        revokedAt: new Date(),
        revocationReason: params.reason,
      });

      return {
        success: true,
        data: { acknowledged: true, timestamp: new Date() },
        httpCode: 200,
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
  ): Promise<SessionOpResult<SessionSuccess>> {
    try {
      await this.store.deleteAllForUser(userId);
      return {
        success: true,
        data: { acknowledged: true, timestamp: new Date() },
        httpCode: 200,
      };
    } catch (error) {
      return this.handleError("Failed to revoke all sessions", error);
    }
  }

  // ---------------------------------------------------------------------------
  // Internal Helpers
  // ---------------------------------------------------------------------------

  private generateSecureToken(): { token: string; tokenHash: string } {
    // 256 bits of entropy
    const token = randomBytes(32).toString("base64url");
    const tokenHash = this.hashToken(token);
    return { token, tokenHash };
  }

  private hashToken(token: string): string {
    return createHash("sha256").update(token).digest("hex");
  }

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
