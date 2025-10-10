import mongoose from "mongoose";

const twoFactorSchema = new mongoose.Schema({
  email: { type: Boolean, default: false },
  sms: { type: Boolean, default: false },
  totp: { type: Boolean, default: false }, // authenticator app
  totpSecret: { type: String }, // speakeasy secret base32
});

const verifyTokenSchema = new mongoose.Schema({
  token: String,
  expiresAt: Date,
});

const otpSchema = new mongoose.Schema({
  code: String,
  type: { type: String, enum: ["email", "sms"], required: true },
  expiresAt: Date,
});

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String }, // optional for OAuth users
    phone: { type: String },
    role: { type: String, enum: ["buyer", "seller", "admin"], default: "buyer" },
    isEmailVerified: { type: Boolean, default: false },
    googleId: { type: String }, // for Google OAuth
    twoFactor: { type: twoFactorSchema, default: () => ({}) },
    verifyToken: verifyTokenSchema, // one-time email verification token
    otps: [otpSchema], // active OTPs
    isActive: { type: Boolean, default: true }, // deactivation flag
  },
  { timestamps: true }
);

export default mongoose.model("User", userSchema);