// src/repositories/postgresql/sessions.repo.ts
import { getPostgresPool } from "../../infra/postgresql/db";
import { SessionRepository } from "../contracts";
import { q } from "../../infra/postgresql/helpers";

export class PostgresSessionRepository implements SessionRepository {
  /**
   * @param sessionTable Name of the session table
   * @param userTable Optional name of the user table for validation
   */
  constructor(
    private sessionTable: string,
    private userTable?: string,
  ) {}

  /**
   * Check if a user exists in the provided user table
   */
  private async checkUserExists(userId: string): Promise<boolean> {
    if (!this.userTable) return true; 

    const { rows } = await getPostgresPool().query(
      `SELECT 1 FROM ${q(this.userTable)} WHERE id = $1 LIMIT 1`,
      [userId],
    );
    return rows.length > 0;
  }

  /**
   * Create a new session
   */
  async create(input: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
    lastUsedAt: Date;
  }) {
    const exists = await this.checkUserExists(input.userId);
    if (!exists) {
      throw new Error(
        `User ${input.userId} does not exist in table "${this.userTable}"`,
      );
    }

    const { rows } = await getPostgresPool().query(
      `
      INSERT INTO ${q(this.sessionTable)} 
        (user_id, token_hash, expires_at, last_used_at)
      VALUES ($1, $2, $3, $4)
      RETURNING id, user_id, expires_at, last_used_at, revoked_at
      `,
      [input.userId, input.tokenHash, input.expiresAt, input.lastUsedAt],
    );

    return rows[0];
  }

  /**
   * Find a session by token hash
   */
  async findByTokenHash(tokenHash: string) {
    const { rows } = await getPostgresPool().query(
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

  /**
   * Update the last_used_at timestamp
   */
  async updateLastUsed(tokenHash: string, date: Date) {
    await getPostgresPool().query(
      `
      UPDATE ${q(this.sessionTable)}
      SET last_used_at = $1
      WHERE token_hash = $2
        AND revoked_at IS NULL
      `,
      [date, tokenHash],
    );
  }

  /**
   * Rotate a session token
   */
  async rotateToken(
    oldTokenHash: string,
    newTokenHash: string,
    rotatedAt: Date,
  ) {
    let isRotaed = false;
    const result = await getPostgresPool().query(
      `
      UPDATE ${q(this.sessionTable)}
      SET token_hash = $1, last_used_at = $2
      WHERE token_hash = $3
        AND revoked_at IS NULL
      RETURNING id
      `,
      [newTokenHash, rotatedAt, oldTokenHash],
    );

    if (result.rowCount && result.rowCount > 0) {
      isRotaed = true;
    }
    return isRotaed;
  }

  /**
   * Revoke a session by token hash
   */
  async revokeByTokenHash(tokenHash: string) {
    await getPostgresPool().query(
      `
      UPDATE ${q(this.sessionTable)}
      SET revoked_at = NOW()
      WHERE token_hash = $1
        AND revoked_at IS NULL
      `,
      [tokenHash],
    );
  }

  /**
   * Revoke oldest sessions to enforce max concurrent sessions
   */
  async revokeOldestForUser(userId: string, keepLatest: number) {
    const { rows: sessions } = await getPostgresPool().query(
      `
      SELECT id
      FROM ${q(this.sessionTable)}
      WHERE user_id = $1
        AND revoked_at IS NULL
      ORDER BY last_used_at ASC
      `,
      [userId],
    );

    const toRevoke = sessions.slice(
      0,
      Math.max(0, sessions.length - keepLatest),
    );
    if (!toRevoke.length) return;

    const ids = toRevoke.map((s) => s.id);
    await getPostgresPool().query(
      `
      UPDATE ${q(this.sessionTable)}
      SET revoked_at = NOW()
      WHERE id = ANY($1::uuid[])
      `,
      [ids],
    );
  }
}
