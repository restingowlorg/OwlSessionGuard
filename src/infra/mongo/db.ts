import mongoose from "mongoose";
import { SessionDB } from "../../interfaces";
import { MongoSessionRepository } from "../../repositories/mongo/session.repo";
import { InitMongoOptions } from "../../types";

export async function connectMongo(
  options: InitMongoOptions,
): Promise<SessionDB> {
  const { mongoUri, sessionCollectionName, userCollectionName } = options;

  if (!mongoUri) {
    throw new Error("mongoUri is required");
  }

  if (!sessionCollectionName) {
    throw new Error("sessionCollectionName is required");
  }

  if (!userCollectionName) {
    throw new Error("userCollectionName is required");
  }

  //Connect to MongoDB
  await mongoose.connect(mongoUri);

  const db = mongoose.connection.db;

  if (!db) {
    throw new Error(
      "MVP Session Init Failed: MongoDB connection not established.",
    );
  }

  // Verify user collection exists
  const userCollectionExists = await db
    .listCollections({ name: userCollectionName })
    .hasNext();

  if (!userCollectionExists) {
    throw new Error(
      `MVP Session Init Failed: User collection '${userCollectionName}' does not exist.`,
    );
  }

  // Verify session collection exists
  const sessionCollectionExists = await db
    .listCollections({ name: sessionCollectionName })
    .hasNext();

  if (!sessionCollectionExists) {
    throw new Error(
      `MVP Session Init Failed: Session collection '${sessionCollectionName}' does not exist.`,
    );
  }

  const collection = db.collection(sessionCollectionName);

  // Verify required indexes
  const indexes = await collection.indexes();

  // token_hash UNIQUE
  const hasTokenUniqueIndex = indexes.some(
    (i) => i.key && i.key.token_hash === 1 && i.unique === true,
  );

  if (!hasTokenUniqueIndex) {
    throw new Error(
      `MVP Session Init Failed: '${sessionCollectionName}' must have UNIQUE index on 'token_hash'.`,
    );
  }

  // user_id index
  const hasUserIndex = indexes.some((i) => i.key && i.key.user_id === 1);

  if (!hasUserIndex) {
    throw new Error(
      `MVP Session Init Failed: '${sessionCollectionName}' must have index on 'user_id'.`,
    );
  }

  // expires_at index (recommended for cleanup queries)
  const hasExpiresIndex = indexes.some((i) => i.key && i.key.expires_at === 1);

  if (!hasExpiresIndex) {
    throw new Error(
      `MVP Session Init Failed: '${sessionCollectionName}' must have index on 'expires_at'.`,
    );
  }

  return {
    sessionRepo: new MongoSessionRepository(collection),
  };
}
