
export type SessionOptions = {
  dbType: "mongo" | "postgres" | "mysql" | string;

  // DB connection strings
  mongoUri?: string;
  postgresUrl?: string;

  // Optional custom table/collection names (for Postgres)
  postgresSessionTable?: string;
  userTable: string;

  // Session configuration
  sessionTtlSeconds?: number; // Absolute TTL
  idleTtlSeconds?: number; // Sliding idle TTL
  maxSessionsPerUser?: number; // Limit concurrent sessions

};

export type InitPostgresOptions = {
  userTableName?: string;
};

export type AuthLogLevel = "info" | "warn" | "error";
