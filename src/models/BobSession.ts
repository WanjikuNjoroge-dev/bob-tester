import mongoose, { Document, Model, Schema } from "mongoose";

export type AdminRole = "admin" | "super_admin";

export interface IBobSession extends Document {
  sessionId: string;
  email: string;
  role: AdminRole;
  createdAt: Date;
  expiresAt: Date;
}

const BobSessionSchema = new Schema<IBobSession>(
  {
    sessionId: { type: String, required: true, unique: true },
    email: { type: String, required: true, lowercase: true, trim: true },
    role: { type: String, required: true, enum: ["admin", "super_admin"] },
    createdAt: { type: Date, default: () => new Date() },
    expiresAt: { type: Date, required: true },
  },
  { collection: "bob_sessions", timestamps: false }
);

BobSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const BobSession: Model<IBobSession> =
  (mongoose.models.BobSession as Model<IBobSession>) ||
  mongoose.model<IBobSession>("BobSession", BobSessionSchema);
