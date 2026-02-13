// src/utils/db-helper.ts
import { connectMongo } from "../infra/mongo/db";
import { initPostgres } from "../infra/postgresql/db";
import { SessionOptions } from "../types";
import { sessionLog } from "../utils/logger";

export async function initDatabase(options: SessionOptions) {
  switch (options.dbType) {
    case "mongo": {
      const { mongoUri, sessionCollectionName, userCollectionName } =
        options.dbOptions;

      if (!mongoUri) {
        throw new Error("mongoUri is required in dbOptions for MongoDB");
      }

      const mongoDb = await connectMongo({
        mongoUri,
        sessionCollectionName,
        userCollectionName,
      });

      sessionLog("info", "Successfully connected to MongoDB");
      return mongoDb;
    }

    case "postgres": {
      const { postgresUrl, sessionTableName, userTableName } =
        options.dbOptions;

      if (!postgresUrl) {
        throw new Error("postgresUrl is required in dbOptions for PostgreSQL");
      }

      const pgDb = await initPostgres({
        postgresUrl,
        sessionTableName,
        userTableName,
      });

      sessionLog("info", "Successfully connected to PostgreSQL");
      return pgDb;
    }

    default:
      throw new Error(
        `Unsupported dbType entered. Supported types are 'mongo' and 'postgres'.`,
      );
  }
}
