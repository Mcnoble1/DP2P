import crypto from "crypto";
import speakeasy from "speakeasy";

/** generate numeric OTP */
export const genOtp = (digits = 6) =>
  (Math.floor(Math.random() * Math.pow(10, digits)) + Math.pow(10, digits - 1)).toString().slice(0, digits);

/** generate random token (email verify link) */
export const genRandomToken = (len = 48) => crypto.randomBytes(len).toString("hex");

/** TOTP helpers for authenticator apps */
export const generateTotpSecret = (name = "P2PPlatform", userEmail = "") =>
  speakeasy.generateSecret({ name: `${name} (${userEmail})` });

export const verifyTotpToken = (secret, token) =>
  speakeasy.totp.verify({ secret, encoding: "base32", token, window: 1 });
