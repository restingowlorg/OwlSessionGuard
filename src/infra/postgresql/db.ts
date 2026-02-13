import { Pool } from "pg";
import { SessionDB } from "../../interfaces";
import { PostgresSessionRepository } from "../../repositories/postgresql/sessions.repo";
import { InitDBOptions } from "../../types";

let pool: Pool | null = null;

// Get the PostgreSQL connection pool
export function getPostgresPool(): Pool {
  if (!pool) {
    throw new Error("PostgreSQL not initialized. Call initPostgres first.");
  }
  return pool;
}

// Initialize PostgreSQL connection and verify schema
export async function initPostgres(
  options: InitDBOptions,
): Promise<SessionDB> {
  if (pool) {
    throw new Error("PostgreSQL already initialized");
  }

  if (!options.postgresUrl) {
    throw new Error("postgresUrl is required");
  }

  pool = new Pool({ connectionString: options.postgresUrl });

  // Ensure DB connectivity
  await pool.query("SELECT 1");

  const { sessionTableName, userTableName } = options;

  // Verify user table exists
  const userTableCheck = await pool.query(`SELECT to_regclass($1) as exists`, [
    userTableName,
  ]);

  if (!userTableCheck.rows[0].exists) {
    throw new Error(
      `MVP Session Init Failed: User table '${userTableName}' does not exist.`,
    );
  }

  // Verify session table exists
  const sessionTableCheck = await pool.query(
    `SELECT to_regclass($1) as exists`,
    [sessionTableName],
  );

  if (!sessionTableCheck.rows[0].exists) {
    throw new Error(
      `MVP Session Init Failed: Session table '${sessionTableName}' does not exist.`,
    );
  }

  // Verify required columns and foreign key constraints
  const columnResult = await pool.query(
    `
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = $1
    `,
    [sessionTableName],
  );

  const existingColumns = columnResult.rows.map((r) => r.column_name);

  const requiredColumns = [
    "id",
    "user_id",
    "token_hash",
    "created_at",
    "expires_at",
    "last_used_at",
    "revoked",
  ];

  const missingColumns = requiredColumns.filter(
    (col) => !existingColumns.includes(col),
  );

  if (missingColumns.length > 0) {
    throw new Error(
      `MVP Session Init Failed: Missing required columns in '${sessionTableName}': ${missingColumns.join(
        ", ",
      )}`,
    );
  }

  const fkResult = await pool.query(
    `
    SELECT
      rc.delete_rule
    FROM
      information_schema.referential_constraints rc
    JOIN information_schema.key_column_usage kcu
      ON rc.constraint_name = kcu.constraint_name
    WHERE
      kcu.table_name = $1
      AND kcu.column_name = 'user_id'
    `,
    [sessionTableName],
  );

  if (fkResult.rowCount === 0) {
    throw new Error(
      `MVP Session Init Failed: '${sessionTableName}.user_id' must reference '${userTableName}(id)' with a FOREIGN KEY.`,
    );
  }

  const deleteRule = fkResult.rows[0].delete_rule;

  if (deleteRule !== "CASCADE") {
    throw new Error(
      `MVP Session Init Failed: Foreign key on '${sessionTableName}.user_id' must use ON DELETE CASCADE.`,
    );
  }

  // Initialize session repository
  const sessionRepo = await PostgresSessionRepository.init(
    pool,
    sessionTableName,
  );

  return {
    sessionRepo,
  };
}
