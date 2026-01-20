import { randomBytes, createHash } from "crypto";
import { SessionRepository } from "../repositories/contracts";
import { SessionResult } from "../types";

export class SessionService {
  constructor(
    private readonly sessions: SessionRepository,
    private readonly maxSessionsPerUser?: number,
  ) {}

  // ------------------------------
  // Helpers
  // ------------------------------
  private generateToken(): { token: string; tokenHash: string } {
    const token = randomBytes(32).toString("hex"); // 256-bit
    const tokenHash = createHash("sha256").update(token).digest("hex");
    return { token, tokenHash };
  }

  private hashToken(token: string): string {
    return createHash("sha256").update(token).digest("hex");
  }

  // ------------------------------
  // Create Session
  // ------------------------------
  async create(userId: string, ttlSeconds: number): Promise<SessionResult> {
    try {
      if (this.maxSessionsPerUser && this.maxSessionsPerUser > 0) {
        await this.sessions.revokeOldestForUser(
          userId,
          this.maxSessionsPerUser - 1,
        );
      }

      const { token, tokenHash } = this.generateToken();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

      const session = await this.sessions.create({
        userId,
        tokenHash,
        expiresAt,
        lastUsedAt: now,
      });

      return {
        success: true,
        data: {
          sessionId: session.id,
          userId,
          sessionToken: token,
          expiresAt,
        },
        message: "Session created",
        httpCode: 200,
      };
    } catch (err: any) {
      return {
        success: false,
        data: null,
        message: `Failed to create session: ${err.message || "Unknown error"}`,
        httpCode: 500,
      };
    }
  }

  // ------------------------------
  // Validate Session (NO rotation)
  // ------------------------------
  async validate(
    token: string,
    idleTtlSeconds?: number,
  ): Promise<SessionResult> {
    try {
      const tokenHash = this.hashToken(token);
      const now = Date.now();

      const session = await this.sessions.findByTokenHash(tokenHash);
      if (!session || session.revokedAt) {
        return {
          success: false,
          data: null,
          message: "Invalid session",
          httpCode: 401,
        };
      }

      // Absolute expiration
      if (session.expiresAt.getTime() < now) {
        await this.sessions.revokeByTokenHash(tokenHash);
        return {
          success: false,
          data: null,
          message: "Session expired",
          httpCode: 401,
        };
      }

      // Idle expiration
      if (idleTtlSeconds && session.lastUsedAt) {
        const idleExpiry =
          session.lastUsedAt.getTime() + idleTtlSeconds * 1000;

        if (idleExpiry < now) {
          await this.sessions.revokeByTokenHash(tokenHash);
          return {
            success: false,
            data: null,
            message: "Session expired due to inactivity",
            httpCode: 401,
          };
        }
      }

      // Update last-used timestamp
      const nowDate = new Date();
      await this.sessions.updateLastUsed(tokenHash, nowDate);

      return {
        success: true,
        data: {
          sessionId: session.id,
          userId: session.userId,
          expiresAt: session.expiresAt,
        },
        message: "Session valid",
        httpCode: 200,
      };
    } catch (err: any) {
      return {
        success: false,
        data: null,
        message: `Failed to validate session: ${err.message || "Unknown error"}`,
        httpCode: 500,
      };
    }
  }

  // ------------------------------
  // Rotate Session Token (explicit)
  // ------------------------------
  async rotate(token: string): Promise<SessionResult> {
    try {
      const oldTokenHash = this.hashToken(token);

      const session = await this.sessions.findByTokenHash(oldTokenHash);
      if (!session || session.revokedAt) {
        return {
          success: false,
          data: null,
          message: "Invalid session",
          httpCode: 401,
        };
      }

      const { token: newToken, tokenHash: newTokenHash } =
        this.generateToken();

      // Atomic rotation (old token must die immediately)
      const rotated = await this.sessions.rotateToken(
        oldTokenHash,
        newTokenHash,
        new Date(),
      );

      if (!rotated) {
        return {
          success: false,
          data: null,
          message: "Session rotation failed",
          httpCode: 409,
        };
      }

      return {
        success: true,
        data: {
          sessionId: session.id,
          userId: session.userId,
          sessionToken: newToken,
          expiresAt: session.expiresAt,
        },
        message: "Session rotated",
        httpCode: 200,
      };
    } catch (err: any) {
      return {
        success: false,
        data: null,
        message: `Failed to rotate session: ${err.message || "Unknown error"}`,
        httpCode: 500,
      };
    }
  }

  // ------------------------------
  // Destroy Session
  // ------------------------------
  async destroy(token: string): Promise<SessionResult> {
    try {
      const tokenHash = this.hashToken(token);
      await this.sessions.revokeByTokenHash(tokenHash);

      return {
        success: true,
        data: null,
        message: "Session revoked",
        httpCode: 200,
      };
    } catch (err: any) {
      return {
        success: false,
        data: null,
        message: `Failed to revoke session: ${err.message || "Unknown error"}`,
        httpCode: 500,
      };
    }
  }
}
