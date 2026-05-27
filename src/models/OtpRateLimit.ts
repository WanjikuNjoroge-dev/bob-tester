import mongoose, { Document, Model, Schema } from "mongoose";

export type OtpRateLimitScope = "email_send" | "attempt_ip";

export interface IOtpRateLimit extends Document {
  scope: OtpRateLimitScope;
  jti: string | null;
  emailHash: string;
  ipHash: string | null;
  attempts: number;
  windowStartedAt: Date;
  lastAttemptAt: Date | null;
  cooldownUntil: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

const OtpRateLimitSchema = new Schema<IOtpRateLimit>(
  {
    scope: {
      type: String,
      required: true,
      enum: ["email_send", "attempt_ip"],
    },
    jti: { type: String, default: null },
    emailHash: { type: String, required: true },
    ipHash: { type: String, default: null },
    attempts: { type: Number, required: true, default: 0 },
    windowStartedAt: { type: Date, required: true, default: () => new Date() },
    lastAttemptAt: { type: Date, default: null },
    cooldownUntil: { type: Date, default: null },
  },
  { collection: "bob_otp_rate_limits", timestamps: true }
);

OtpRateLimitSchema.index(
  { scope: 1, jti: 1, ipHash: 1 },
  { unique: true, partialFilterExpression: { scope: "attempt_ip" } }
);
OtpRateLimitSchema.index(
  { scope: 1, emailHash: 1 },
  { unique: true, partialFilterExpression: { scope: "email_send" } }
);
OtpRateLimitSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 24 * 60 * 60 });

export const OtpRateLimit: Model<IOtpRateLimit> =
  (mongoose.models.OtpRateLimit as Model<IOtpRateLimit>) ||
  mongoose.model<IOtpRateLimit>("OtpRateLimit", OtpRateLimitSchema);
