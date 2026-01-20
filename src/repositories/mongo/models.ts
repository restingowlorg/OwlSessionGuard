import { Schema, model, Types } from "mongoose";

/* -------------------- SESSION -------------------- */
const SessionSchema = new Schema(
  {
    userId: { type: Types.ObjectId, ref: "User", required: true, index: true },
    tokenHash: { type: String, required: true, unique: true, index: true },
    expiresAt: { type: Date, required: true, index: true },
    lastUsedAt: { type: Date, required: true, index: true },
    revokedAt: { type: Date, default: null, index: true },
  },
  { timestamps: true },
);

/* -------------------- MODELS -------------------- */
export const SessionModel = model("Session", SessionSchema);
