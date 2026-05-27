import mongoose, { Document, Model, Schema } from "mongoose";

export interface IWebAuthnChallenge extends Document {
  challenge: string;
  email: string;
  type: "registration" | "authentication";
  createdAt: Date;
}

const WebAuthnChallengeSchema = new Schema<IWebAuthnChallenge>(
  {
    challenge: { type: String, required: true },
    email: { type: String, required: true },
    type: {
      type: String,
      required: true,
      enum: ["registration", "authentication"],
    },
    createdAt: { type: Date, default: () => new Date() },
  },
  { collection: "bob_webauthn_challenges", timestamps: false }
);

WebAuthnChallengeSchema.index({ email: 1, type: 1 });
WebAuthnChallengeSchema.index({ createdAt: 1 }, { expireAfterSeconds: 300 });

export const WebAuthnChallenge: Model<IWebAuthnChallenge> =
  (mongoose.models.WebAuthnChallenge as Model<IWebAuthnChallenge>) ||
  mongoose.model<IWebAuthnChallenge>(
    "WebAuthnChallenge",
    WebAuthnChallengeSchema
  );
