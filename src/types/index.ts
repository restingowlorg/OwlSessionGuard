// ------------------------------
// src/types/index.ts
// ------------------------------

export type InitDBOptions = {
  postgresUrl: string;
  sessionTableName: string;
  userTableName: string;
};

export type InitMongoOptions = {
  mongoUri: string;
  sessionCollectionName: string;
  userCollectionName: string;
};

export type UserId = string | number;
export type AuthLogLevel = "info" | "warn" | "error";

// ------------------------------
// Base session config options
// ------------------------------
type BaseSessionOptions = {
  sessionTtlSeconds?: number; // Absolute TTL
  idleTtlSeconds?: number;    // Sliding idle TTL
  maxSessionsPerUser?: number; // Limit concurrent sessions
};

// ------------------------------
// Discriminated union for dbType
// ------------------------------
export type SessionOptions =
  | (BaseSessionOptions & {
      dbType: "postgres";
      dbOptions: InitDBOptions;
    })
  | (BaseSessionOptions & {
      dbType: "mongo";
      dbOptions: InitMongoOptions;
    });
