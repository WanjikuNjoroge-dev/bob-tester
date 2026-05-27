import mongoose, { Document, Model, Schema } from "mongoose";

export interface IAdminPasskey {
  email: string;
  credentialID: string;
  credentialPublicKey: string;
  counter: number;
  transports: string[];
  name: string;
  rpId?: string | null;
  addedAt: Date;
}

export interface IBobAdmin extends Document {
  emails: string[];
  passkeys: IAdminPasskey[];
}

const AdminPasskeySchema = new Schema<IAdminPasskey>(
  {
    email: { type: String, required: true, lowercase: true, trim: true },
    credentialID: { type: String, required: true },
    credentialPublicKey: { type: String, required: true },
    counter: { type: Number, required: true, default: 0 },
    transports: [{ type: String }],
    name: { type: String, default: "Passkey" },
    rpId: { type: String, default: null },
    addedAt: { type: Date, default: () => new Date() },
  },
  { _id: false }
);

const BobAdminSchema = new Schema<IBobAdmin>(
  {
    emails: [{ type: String, lowercase: true, trim: true }],
    passkeys: [AdminPasskeySchema],
  },
  { collection: "bob_admins" }
);

export const BobAdmin: Model<IBobAdmin> =
  (mongoose.models.BobAdmin as Model<IBobAdmin>) ||
  mongoose.model<IBobAdmin>("BobAdmin", BobAdminSchema);
