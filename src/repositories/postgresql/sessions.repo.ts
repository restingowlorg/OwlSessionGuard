// src/repositories/postgresql/sessions.repo.ts
import { Pool } from "pg";
import { SessionRepository } from "../contracts";
import { q } from "../../infra/postgresql/helpers";
import { randomUUID } from "crypto";

type UserId = string | number;

export class PostgresSessionRepository implements SessionRepository {
  private constructor(
    private readonly pool: Pool,
    private readonly sessionTable: string,
  ) {}

  /**
   * Async initializer to check table exists
   */
  public static async init(pool: Pool, sessionTable: string) {
    const repo = new PostgresSessionRepository(pool, sessionTable);
    await repo.checkTableExists(); // check table immediately
    return repo;
  }

  private async checkTableExists(): Promise<void> {
    const { rows } = await this.pool.query(
      `
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = $1
      )
      `,
      [this.sessionTable],
    );

    if (!rows[0].exists) {
      throw new Error(
        `Session table "${this.sessionTable}" does not exist. Please create it first.`,
      );
    }
  }

  async create(input: {
    userId: UserId;
    tokenHash: string;
    expiresAt: Date;
    lastUsedAt: Date;
  }) {

    console.log("session lib userId", input.userId);
    const id = randomUUID();
    console.log("uuid", id);
    const { rows } = await this.pool.query(
      `
      INSERT INTO ${q(this.sessionTable)} 
        (id , user_id, token_hash, expires_at, last_used_at)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, user_id, expires_at, last_used_at, revoked_at
      `,
      [id, input.userId, input.tokenHash, input.expiresAt, input.lastUsedAt],
    );

    const row = rows[0];
    console.log("row ID", row.id);

    return {
      id: row.id,
      userId: row.user_id,
      expiresAt: row.expires_at,
      lastUsedAt: row.last_used_at,
      revokedAt: row.revoked_at,
    };
  }

  async findByTokenHash(tokenHash: string) {
    const { rows } = await this.pool.query(
      `
      SELECT id, user_id, expires_at, last_used_at, revoked_at
      FROM ${q(this.sessionTable)}
      WHERE token_hash = $1
      `,
      [tokenHash],
    );

    if (!rows.length) return null;

    const row = rows[0];

    return {
      id: row.id,
      userId: row.user_id,
      expiresAt: row.expires_at,
      lastUsedAt: row.last_used_at,
      revokedAt: row.revoked_at,
    };
  }

  async updateLastUsed(tokenHash: string, date: Date) {
    await this.pool.query(
      `
      UPDATE ${q(this.sessionTable)}
      SET last_used_at = $1
      WHERE token_hash = $2
        AND revoked_at IS NULL
      `,
      [date, tokenHash],
    );
  }

  async rotateToken(
    oldTokenHash: string,
    newTokenHash: string,
    rotatedAt: Date,
  ): Promise<boolean> {
    console.log('oldTokenHash',oldTokenHash);
    console.log('newTokenHash',newTokenHash);
    console.log('rotatedAt',rotatedAt);
    
    const result = await this.pool.query(
      `
      UPDATE ${q(this.sessionTable)}
      SET token_hash = $1, last_used_at = $2
      WHERE token_hash = $3
        AND revoked_at IS NULL
      RETURNING id
      `,
      [newTokenHash, rotatedAt, oldTokenHash],
    );

    return (result.rowCount ?? 0) > 0;
  }

  async revokeByTokenHash(tokenHash: string) {
    await this.pool.query(
      `
      UPDATE ${q(this.sessionTable)}
      SET revoked_at = NOW()
      WHERE token_hash = $1
        AND revoked_at IS NULL
      `,
      [tokenHash],
    );
  }

  async revokeOldestForUser(userId: UserId, keepLatest: number) {
    const { rows } = await this.pool.query(
      `
      SELECT id
      FROM ${q(this.sessionTable)}
      WHERE user_id = $1
        AND revoked_at IS NULL
      ORDER BY last_used_at ASC
      `,
      [userId],
    );

    const toRevoke = rows.slice(0, Math.max(0, rows.length - keepLatest));

    if (!toRevoke.length) return;

    const ids = toRevoke.map((s) => s.id);

    await this.pool.query(
      `
      UPDATE ${q(this.sessionTable)}
      SET revoked_at = NOW()
      WHERE id = ANY($1)
      `,
      [ids],
    );
  }
}
