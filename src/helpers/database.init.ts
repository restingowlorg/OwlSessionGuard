// src/utils/db-helper.ts
import { connectMongo } from "../infra/mongo/db";
import { initPostgres } from "../infra/postgresql/db";
import { SessionOptions } from "../types";
import { sessionLog } from "../utils/logger";

export async function initDatabase(options: SessionOptions) {
  switch (options.dbType) {
    case "mongo":
      if (!options.mongoUri) throw new Error("mongoUri is required");
      const mongoDb = await connectMongo(options.mongoUri);
      sessionLog("info", "Successfully connected to MongoDB");
      return mongoDb;

    case "postgres":
      if (!options.postgresUrl) throw new Error("postgresUrl is required");
      const pgDb = await initPostgres(
        options.postgresUrl,
        options.postgresSessionTable
      );
      sessionLog("info", "Successfully connected to PostgreSQL");
      return pgDb;

    default:
      throw new Error(`Unsupported dbType: ${options.dbType}`);
  }
}
