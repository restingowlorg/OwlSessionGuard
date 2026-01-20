import mongoose from "mongoose";
import { MongoSessionRepo } from "../../repositories/mongo/session.repo";
import { SessionDB } from "../../types";

export async function connectMongo(uri: string): Promise<SessionDB> {
  await mongoose.connect(uri);
  return {
    sessionRepo: MongoSessionRepo,
  };
}
