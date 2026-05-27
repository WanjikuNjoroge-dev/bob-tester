import mongoose, { Document, Model, Schema } from "mongoose";

export interface IOtpChallenge extends Document {
  email: string;
  codeHash: string;
  createdAt: Date;
}

const OtpChallengeSchema = new Schema<IOtpChallenge>(
  {
    email: { type: String, required: true, unique: true },
    codeHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "bob_otp_challenges", timestamps: false }
);

OtpChallengeSchema.index({ createdAt: 1 }, { expireAfterSeconds: 600 });

export const OtpChallenge: Model<IOtpChallenge> =
  (mongoose.models.OtpChallenge as Model<IOtpChallenge>) ||
  mongoose.model<IOtpChallenge>("OtpChallenge", OtpChallengeSchema);
