import { Pool } from "pg";
import { SessionDB } from "../../interfaces";
import { ensureSessionTable } from "./helpers";
import { PostgresSessionRepository } from "../../repositories/postgresql/sessions.repo";

let pool: Pool | null = null;

/**
 * Get the initialized PostgreSQL pool
 */
export function getPostgresPool(): Pool {
  if (!pool) {
    throw new Error("PostgreSQL not initialized. Call initPostgres first.");
  }
  return pool;
}

/**
 * Initialize PostgreSQL connection and session repository
 */
export async function initPostgres(
  connectionString: string,
  sessionTableName = "sessions",
  userTable: string,
): Promise<SessionDB> {
  if (pool) {
    throw new Error("PostgreSQL already initialized");
  }

  pool = new Pool({ connectionString });

  // Ensure the sessions table exists
  await ensureSessionTable(pool, sessionTableName, userTable);

  return {
    sessionRepo: new PostgresSessionRepository(sessionTableName, userTable),
  };
}
