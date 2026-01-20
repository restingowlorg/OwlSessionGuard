export interface SessionRepository {
  create(input: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
    lastUsedAt: Date;
  }): Promise<{
    id: string;
    userId: string;
    expiresAt: Date;
    lastUsedAt: Date;
    revokedAt: Date | null;
  }>;

  findByTokenHash(tokenHash: string): Promise<{
    id: string;
    userId: string;
    expiresAt: Date;
    lastUsedAt: Date;
    revokedAt: Date | null;
  } | null>;

  updateLastUsed(tokenHash: string, date: Date): Promise<void>;

  rotateToken(
    oldTokenHash: string,
    newTokenHash: string,
    rotatedAt: Date,
  ): Promise<boolean>;

  revokeByTokenHash(tokenHash: string): Promise<void>;

  revokeOldestForUser(userId: string, keepLatest: number): Promise<void>;
}
