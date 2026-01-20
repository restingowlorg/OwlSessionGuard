import { getPostgresPool } from "../../infra/postgresql/db";
import { SessionRepository } from "../contracts";

export class PostgresSessionRepository implements SessionRepository {
  constructor(private readonly table: string) {}

  private t() {
    return `"${this.table}"`;
  }

  async create(input: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
    lastUsedAt: Date;
  }) {
    const pool = getPostgresPool();

    const result = await pool.query(
      `
      INSERT INTO ${this.t()}
        (user_id, token_hash, expires_at, last_used_at)
      VALUES ($1, $2, $3, $4)
      RETURNING id, user_id, expires_at, last_used_at, revoked_at
      `,
      [input.userId, input.tokenHash, input.expiresAt, input.lastUsedAt],
    );

    const row = result.rows[0];

    return {
      id: row.id,
      userId: row.user_id,
      expiresAt: row.expires_at,
      lastUsedAt: row.last_used_at,
      revokedAt: row.revoked_at,
    };
  }

  async findByTokenHash(tokenHash: string) {
    const pool = getPostgresPool();

    const result = await pool.query(
      `
      SELECT id, user_id, expires_at, last_used_at, revoked_at
      FROM ${this.t()}
      WHERE token_hash = $1
      `,
      [tokenHash],
    );

    const row = result.rows[0];
    if (!row) return null;

    return {
      id: row.id,
      userId: row.user_id,
      expiresAt: row.expires_at,
      lastUsedAt: row.last_used_at,
      revokedAt: row.revoked_at,
    };
  }

  async updateLastUsed(tokenHash: string, date: Date) {
    const pool = getPostgresPool();

    await pool.query(
      `
      UPDATE ${this.t()}
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
  ) {
    const pool = getPostgresPool();

    const result = await pool.query(
      `
      UPDATE ${this.t()}
      SET token_hash = $1, last_used_at = $2
      WHERE token_hash = $3
        AND revoked_at IS NULL
      RETURNING id
      `,
      [newTokenHash, rotatedAt, oldTokenHash],
    );

    if (result.rowCount === null) return false;

    return result.rowCount > 0;
  }

  async revokeByTokenHash(tokenHash: string) {
    const pool = getPostgresPool();

    await pool.query(
      `
      UPDATE ${this.t()}
      SET revoked_at = NOW()
      WHERE token_hash = $1
        AND revoked_at IS NULL
      `,
      [tokenHash],
    );
  }

  async revokeOldestForUser(userId: string, keepLatest: number) {
    const pool = getPostgresPool();

    // Get active sessions ordered by last_used_at ASC
    const result = await pool.query(
      `
      SELECT id
      FROM ${this.t()}
      WHERE user_id = $1
        AND revoked_at IS NULL
      ORDER BY last_used_at ASC
      `,
      [userId],
    );

    const sessions = result.rows;
    const toRevoke = sessions.slice(
      0,
      Math.max(0, sessions.length - keepLatest),
    );

    if (toRevoke.length === 0) return;

    const ids = toRevoke.map((s) => s.id);

    await pool.query(
      `
      UPDATE ${this.t()}
      SET revoked_at = NOW()
      WHERE id = ANY($1::uuid[])
      `,
      [ids],
    );
  }
}
