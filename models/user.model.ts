import { Document, Schema, Types, model } from "mongoose";

interface UserType extends Document {
  name: string;
  email: string;
  password: string;
  role: string;
  docVersion: number;
  isDisabled: boolean;
}

const UserSchema = new Schema<UserType>(
  {
    name: { type: String },
    email: { type: String, unique: true },
    password: { type: String },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    docVersion: { type: Number, default: 0 },
    isDisabled: { type: Boolean, default: false },
  },
  { timestamps: true }
);

export const User = model<UserType>("User", UserSchema);
