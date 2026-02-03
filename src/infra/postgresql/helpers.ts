// src/infra/postgres/helpers.ts
import { Pool } from "pg";
import { sessionLog } from "../../utils/logger";

// Quote identifier
export function q(identifier: string) {
  return `"${identifier.replace(/"/g, '""')}"`;
}

// Detect primary key for user table
export async function getUserPrimaryKey(pool: Pool, table: string) {
  const { rows } = await pool.query(
    `
    SELECT
      kcu.column_name,
      c.data_type
    FROM information_schema.table_constraints tc
    JOIN information_schema.key_column_usage kcu
      ON tc.constraint_name = kcu.constraint_name
    JOIN information_schema.columns c
      ON c.table_name = tc.table_name
     AND c.column_name = kcu.column_name
    WHERE tc.constraint_type = 'PRIMARY KEY'
      AND tc.table_schema = 'public'
      AND tc.table_name = $1
    `,
    [table],
  );

  if (!rows.length) {
    throw new Error(`User table "${table}" has no PRIMARY KEY`);
  }

  return {
    name: rows[0].column_name,
    type: rows[0].data_type,
  };
}

// Ensure session table exists
export async function ensureSessionTable(
  pool: Pool,
  table: string,
  userTable: string,
) {
  let userIdType = "UUID"; // default type
  if (userTable) {
    sessionLog("info", `Detecting primary key type for user table "${userTable}"`);
    const pk = await getUserPrimaryKey(pool, userTable);
    userIdType = pk.type.toUpperCase(); 
    sessionLog("info", `Detected user_id type: ${userIdType}`);
  }

  // Check if table exists
  const { rows } = await pool.query(
    `
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = $1
    )
  `,
    [table],
  );

  const exists = rows[0]?.exists;

  if (!exists) {
    // Table does not exist → create fresh
    await pool.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

      CREATE TABLE ${q(table)} (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id ${userIdType} NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        last_used_at TIMESTAMP NOT NULL,
        revoked_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX idx_${table}_token_hash ON ${q(table)} (token_hash);
      CREATE INDEX idx_${table}_user_id ON ${q(table)} (user_id);
    `);

    sessionLog("info", `Session table created with FK user_id = ${userIdType}`);
    return;
  }

  // Table exists → check for missing columns
  const { rows: cols } = await pool.query(
    `
    SELECT column_name, data_type
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name=$1
  `,
    [table],
  );

  const existingCols = cols.map((c) => c.column_name);
  const migrations: string[] = [];

  // Ensure essential columns exist
  if (!existingCols.includes("token_hash")) {
    migrations.push(
      `ALTER TABLE ${q(table)} ADD COLUMN token_hash TEXT UNIQUE NOT NULL;`,
    );
  }
  if (!existingCols.includes("last_used_at")) {
    migrations.push(
      `ALTER TABLE ${q(table)} ADD COLUMN last_used_at TIMESTAMP NOT NULL DEFAULT NOW();`,
    );
  }
  if (!existingCols.includes("revoked_at")) {
    migrations.push(
      `ALTER TABLE ${q(table)} ADD COLUMN revoked_at TIMESTAMP NULL;`,
    );
  }
  if (!existingCols.includes("expires_at")) {
    migrations.push(
      `ALTER TABLE ${q(table)} ADD COLUMN expires_at TIMESTAMP NOT NULL;`,
    );
  }
  if (!existingCols.includes("user_id")) {
    migrations.push(
      `ALTER TABLE ${q(table)} ADD COLUMN user_id ${userIdType} NOT NULL;`,
    );
  }

  if (migrations.length > 0) {
    for (const sql of migrations) {
      await pool.query(sql);
    }
    console.log(
      `ℹ️ Session table "${table}" migrated: added columns ${migrations
        .map((s) => s.match(/ADD COLUMN (\w+)/)?.[1])
        .join(", ")}`,
    );
  }
}
