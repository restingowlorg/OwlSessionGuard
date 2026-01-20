
export type SessionOptions = {
  dbType: "mongo" | "postgres" | "mysql" | string;

  // DB connection strings
  mongoUri?: string;
  postgresUrl?: string;

  // Optional custom table/collection names (for Postgres)
  postgresSessionTable?: string;

  // Session configuration
  sessionTtlSeconds?: number; // Absolute TTL
  idleTtlSeconds?: number; // Sliding idle TTL
  maxSessionsPerUser?: number; // Limit concurrent sessions

  // Cookie options if exposing sessions via cookies
  cookieName?: string;
  cookieOptions?: {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "lax" | "strict" | "none";
  };
};

export interface SessionDB {
  sessionRepo: any;
}

export interface SessionResult<T = any> {
  success: boolean;
  data?: T;
  httpCode: number;
  message: string;
}

export type InitPostgresOptions = {
  userTableName?: string;
};

export type AuthLogLevel = "info" | "warn" | "error";
