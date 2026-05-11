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
} from "../types";
import { SessionStoreAdapter } from "../storage/contracts";
import { SessionStateMachine } from "./state-machine";

/**
 * SessionService — Implementation of core session logic.
 */
export class SessionService implements ISessionService {
  constructor(
    private readonly store: SessionStoreAdapter,
    private readonly config: SessionLibraryConfig,
  ) {}

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
      const activeCount = await this.store.countActiveForUser(params.userId);
      if (activeCount >= this.config.limits.maxSessionsPerUser) {
        return this.fail(
          `User exceeded maximum session limit (${this.config.limits.maxSessionsPerUser})`,
          403,
          SessionReasonCode.SECURITY_BREACH,
        );
      }

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
      const tokenHash = fastHash(params.token);
      const record = await this.store.findByTokenHash(tokenHash);

      if (!record) {
        return this.fail("Invalid session token", 401);
      }

      const now = new Date();

      // Check lifecycle status via state machine
      if (!SessionStateMachine.isUsable(record.status)) {
        return this.fail(`Session is in ${record.status} state`, 401);
      }

      // Check expiration
      const expiry = SessionStateMachine.checkExpiration(
        now,
        record.expiresAt,
        record.idleExpiresAt,
      );
      if (expiry.isExpired) {
        const reason = expiry.reason || SessionReasonCode.ABSOLUTE_TIMEOUT;
        await this.store.update(record.id, {
          status: SessionStatus.EXPIRED,
          revocationReason: reason,
        });
        return this.fail(`Session expired: ${reason}`, 401, reason);
      }

      // IP Binding check
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
        }
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
    try {
      const oldTokenHash = fastHash(params.token);
      const record = await this.store.findByTokenHash(oldTokenHash);

      if (!record || !SessionStateMachine.isUsable(record.status)) {
        return this.fail("Invalid or unusable session for rotation", 401);
      }

      const { token: newToken, tokenHash: newTokenHash } =
        this.generateSecureToken();

      const now = new Date();

      // Update old session status to ROTATED
      await this.store.update(record.id, {
        status: SessionStatus.ROTATED,
        revocationReason: params.reason || SessionReasonCode.ROTATION,
      });

      // Create new session linked to the old one
      const newRecord: SessionRecord = {
        ...record,
        id: uuidv4(),
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

      // Enforce valid transition to REVOKED
      if (record.status === SessionStatus.REVOKED) {
        return {
          success: true,
          data: { acknowledged: true, timestamp: new Date() },
          httpCode: 200,
        };
      }

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
    _reason: SessionReasonCode,
  ): Promise<SessionOpResult<SessionSuccess>> {
    try {
      // In a real implementation, we might want to update all records to REVOKED
      // rather than just deleting them, to maintain an audit trail.
      // For now, we'll follow the store's delete pattern but we could also
      // iterate and update status if the store supports it.
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

  private generateSecureToken(): { token: string; tokenHash: string } {
    // 32 bytes = 256 bits of entropy
    const token = generateBase64UrlToken(32);
    const tokenHash = fastHash(token);
    return { token, tokenHash };
  }

  private fail<T>(
    message: string,
    httpCode: number,
    reason?: SessionReasonCode,
  ): SessionOpResult<T> {
    return {
      success: false,
      error: {
        code: "SESSION_ERROR",
        message,
        reason,
      },
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
