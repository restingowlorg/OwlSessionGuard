import { Collection, ObjectId } from "mongodb";
import { SessionRepository } from "../contracts";

export class MongoSessionRepository implements SessionRepository {
  constructor(private collection: Collection) {}

  async create(input: {
    userId: number | string;
    tokenHash: string;
    expiresAt: Date;
    lastUsedAt: Date;
  }): Promise<{
    id: string;
    userId: number | string;
    expiresAt: Date;
    lastUsedAt: Date;
    revokedAt: Date | null;
  }> {
    const now = new Date();

    const result = await this.collection.insertOne({
      user_id: input.userId,
      token_hash: input.tokenHash,
      created_at: now,
      expires_at: input.expiresAt,
      last_used_at: input.lastUsedAt,
      revoked: false,
    });

    return {
      id: result.insertedId.toString(),
      userId: input.userId,
      expiresAt: input.expiresAt,
      lastUsedAt: input.lastUsedAt,
      revokedAt: null,
    };
  }

  async findByTokenHash(tokenHash: string): Promise<{
    id: string;
    userId: number | string;
    expiresAt: Date;
    lastUsedAt: Date;
    revokedAt: Date | null;
  } | null> {
    const session = await this.collection.findOne({
      token_hash: tokenHash,
    });

    if (!session) return null;

    return {
      id: (session._id as ObjectId).toString(),
      userId: session.user_id,
      expiresAt: session.expires_at,
      lastUsedAt: session.last_used_at,
      revokedAt: session.revoked ? new Date() : null,
    };
  }

  async updateLastUsed(tokenHash: string, date: Date): Promise<void> {
    await this.collection.updateOne(
      { token_hash: tokenHash, revoked: false },
      { $set: { last_used_at: date } },
    );
  }

  async rotateToken(
    oldTokenHash: string,
    newTokenHash: string,
    rotatedAt: Date,
  ): Promise<boolean> {
    const result = await this.collection.updateOne(
      { token_hash: oldTokenHash, revoked: false },
      {
        $set: {
          token_hash: newTokenHash,
          last_used_at: rotatedAt,
        },
      },
    );

    return result.modifiedCount === 1;
  }

  async revokeByTokenHash(tokenHash: string): Promise<void> {
    await this.collection.updateOne(
      { token_hash: tokenHash, revoked: false },
      { $set: { revoked: true } },
    );
  }

  async revokeOldestForUser(
    userId: number | string,
    keepLatest: number,
  ): Promise<void> {
    const sessions = await this.collection
      .find({ user_id: userId, revoked: false })
      .sort({ created_at: 1 }) // oldest first
      .toArray();

    const toRevoke = sessions.slice(
      0,
      Math.max(0, sessions.length - keepLatest),
    );

    for (const session of toRevoke) {
      await this.collection.updateOne(
        { _id: session._id },
        { $set: { revoked: true } },
      );
    }
  }
}
