import jwt from "jsonwebtoken";
import TokenBlacklist from "../models/tokenBlacklist.model.js";

const JWT_SECRET = process.env.JWT_SECRET;
const ACCESS_EXPIRES = process.env.JWT_EXPIRES || "7d";

export const signToken = (payload) =>
  jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });

export const verifyToken = (token) => jwt.verify(token, JWT_SECRET);

/** Blacklist a token until its expiry time */
export const blacklistToken = async (token) => {
  try {
    const decoded = jwt.decode(token);
    const exp = decoded?.exp ? new Date(decoded.exp * 1000) : new Date(Date.now() + 7 * 24 * 3600 * 1000);
    await TokenBlacklist.create({ token, expiresAt: exp });
  } catch (err) {
    console.error("blacklistToken err", err);
  }
};

export const isBlacklisted = async (token) => {
  const found = await TokenBlacklist.findOne({ token });
  return !!found;
};
