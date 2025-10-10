import { verifyToken, isBlacklisted } from "../utils/jwt.js";

export const authenticate = async (req, res, next) => {
  try {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ message: "No authorization header" });
    const token = header.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token" });

    if (await isBlacklisted(token)) return res.status(401).json({ message: "Token revoked" });

    const payload = verifyToken(token);
    req.user = payload; // contains id, role, email
    req.token = token;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token", error: err.message });
  }
};

export const requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }
  next();
};
