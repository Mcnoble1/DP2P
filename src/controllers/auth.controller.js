import bcrypt from "bcrypt";
import User from "../models/user.model.js";
import { signToken, blacklistToken } from "../utils/jwt.js";
import { sendEmail } from "../utils/email.js";
import { genOtp, genRandomToken, generateTotpSecret, verifyTotpToken } from "../utils/otp.js";
// import { sendSms } from "../utils/sms.js";
import TokenBlacklist from "../models/tokenBlacklist.model.js";
import jwt from "jsonwebtoken";
import fetch from "node-fetch"; // if you need to verify Google idTokens server-side

const EMAIL_OTP_EXP = 10 * 60 * 1000; // 10 minutes
const VERIFY_TOKEN_EXP = 24 * 3600 * 1000; // 24 hours

/** Signup local */
export const register = async (req, res) => {
  try {
    const { name, email, password, phone, role } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already in use" });

    const hashed = await bcrypt.hash(password, 10);
    const verifyToken = genRandomToken(24);
    const user = await User.create({
      name,
      email,
      password: hashed,
      phone,
      role: role || "buyer",
      verifyToken: { token: verifyToken, expiresAt: new Date(Date.now() + VERIFY_TOKEN_EXP) },
    });

    // send email verification
    const link = `${process.env.APP_URL}/api/auth/verify-email?token=${verifyToken}`;
    await sendEmail({
      to: user.email,
      subject: "Verify your email",
      html: `<p>Welcome ${user.name}, click <a href="${link}">here</a> to verify your email.</p>`,
    });

    res.status(201).json({ message: "User created. Check email to verify." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Registration failed" });
  }
};

/** Login local */
export const login = async (req, res) => {
  try {
    const { email, password, totp } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });
    if (!user.isActive) return res.status(403).json({ message: "Account deactivated" });

    if (!user.password) return res.status(400).json({ message: "Use social login" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: "Invalid credentials" });

    // If TOTP (authenticator app) enabled, require totp verify
    if (user.twoFactor.totp) {
      if (!totp) return res.status(206).json({ message: "TOTP required", twoFactor: "totp" });
      const okTotp = verifyTotpToken(user.twoFactor.totpSecret, totp);
      if (!okTotp) return res.status(400).json({ message: "Invalid TOTP code" });
    }

    // Otherwise if email or sms 2FA is enabled, produce an OTP flow instead of immediate login.
    if (user.twoFactor.email || user.twoFactor.sms) {
      // generate and send OTP (email prioritized if both enabled)
      const code = genOtp();
      const expiresAt = new Date(Date.now() + EMAIL_OTP_EXP);
      user.otps = user.otps.filter((o) => o.expiresAt > new Date());
      user.otps.push({ code, type: user.twoFactor.email ? "email" : "sms", expiresAt });
      await user.save();

      if (user.twoFactor.email) {
        await sendEmail({
          to: user.email,
          subject: "Your login OTP",
          html: `<p>Your login code is <b>${code}</b> (valid 10 minutes).</p>`,
        });
        return res.status(206).json({ message: "Email OTP sent", twoFactor: "email" });
      } else if (user.twoFactor.sms && user.phone) {
        await sendSms({ to: user.phone, body: `Your login code: ${code}` });
        return res.status(206).json({ message: "SMS OTP sent", twoFactor: "sms" });
      } else {
        // no phone -> fallback
        return res.status(400).json({ message: "2FA configured but no phone available" });
      }
    }

    // login success -> return JWT
    const token = signToken({ id: user._id.toString(), role: user.role, email: user.email });
    res.json({ message: "Login successful", token, user: { id: user._id, email: user.email, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
};

/** Verify email from link */
export const verifyEmail = async (req, res) => {
  try {
    const token = req.query.token || req.body.token;
    if (!token) return res.status(400).json({ message: "Token required" });
    const user = await User.findOne({ "verifyToken.token": token });
    if (!user) return res.status(400).json({ message: "Invalid token" });
    if (user.verifyToken.expiresAt < new Date()) return res.status(400).json({ message: "Token expired" });

    user.isEmailVerified = true;
    user.verifyToken = undefined;
    await user.save();
    res.json({ message: "Email verified" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Verification failed" });
  }
};

/** Resend verification email */
export const resendVerifyEmail = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.isEmailVerified) return res.status(400).json({ message: "Already verified" });

    const verifyToken = genRandomToken(24);
    user.verifyToken = { token: verifyToken, expiresAt: new Date(Date.now() + VERIFY_TOKEN_EXP) };
    await user.save();

    const link = `${process.env.APP_URL}/api/auth/verify-email?token=${verifyToken}`;
    await sendEmail({ to: user.email, subject: "Verify your email", html: `Click <a href="${link}">here</a>` });
    res.json({ message: "Verification email resent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Resend failed" });
  }
};

/** Google sign in (client sends idToken) */
export const googleSignIn = async (req, res) => {
  try {
    const { idToken } = req.body;
    // Option A: verify idToken with Google's tokeninfo endpoint (quick)
    const googleClientId = process.env.GOOGLE_CLIENT_ID;
    const resp = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
    const data = await resp.json();
    if (data.aud !== googleClientId) return res.status(400).json({ message: "Invalid ID token" });

    const email = data.email;
    const googleId = data.sub;
    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({
        name: data.name || email.split("@")[0],
        email,
        isEmailVerified: true,
        googleId,
      });
    } else {
      // attach googleId if absent
      if (!user.googleId) {
        user.googleId = googleId;
        await user.save();
      }
    }

    const token = signToken({ id: user._id.toString(), role: user.role, email: user.email });
    res.json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Google sign-in failed" });
  }
};

/** Send OTP (email or sms) - used for login or separate flows */
export const sendOtp = async (req, res) => {
  try {
    const { type } = req.body;
    const userId = req.user?.id || req.body.email; // allow email lookup too
    const user = req.user ? await User.findById(req.user.id) : await User.findOne({ email: req.body.email });

    if (!user) return res.status(404).json({ message: "User not found" });

    const code = genOtp();
    const expiresAt = new Date(Date.now() + EMAIL_OTP_EXP);
    user.otps = user.otps.filter((o) => o.expiresAt > new Date());
    user.otps.push({ code, type, expiresAt });
    await user.save();

    if (type === "email") {
      await sendEmail({ to: user.email, subject: "Your OTP", html: `Code: <b>${code}</b>` });
      return res.json({ message: "OTP sent to email" });
    } else if (type === "sms") {
      if (!user.phone) return res.status(400).json({ message: "No phone on file" });
      await sendSms({ to: user.phone, body: `Your OTP: ${code}` });
      return res.json({ message: "OTP sent via SMS" });
    } else {
      return res.status(400).json({ message: "Unsupported type" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Send OTP failed" });
  }
};

/** Verify OTP */
export const verifyOtp = async (req, res) => {
  try {
    const { type, code, email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    user.otps = user.otps.filter((o) => o.expiresAt > new Date());
    const found = user.otps.find((o) => o.type === type && o.code === code);
    if (!found) return res.status(400).json({ message: "Invalid or expired OTP" });

    // remove used OTP
    user.otps = user.otps.filter((o) => !(o.type === type && o.code === code));
    await user.save();

    // on successful OTP for login -> issue token
    const token = signToken({ id: user._id.toString(), role: user.role, email: user.email });
    res.json({ message: "OTP verified", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Verify OTP failed" });
  }
};

/** TOTP (authenticator app) generate / verify / disable flow */
export const totpFlow = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const { action, token } = req.body;

    if (action === "generate") {
      const secret = generateTotpSecret(process.env.APP_NAME || "P2PPlatform", user.email);
      // store secret temporarily in response; verify before enabling
      return res.json({ secret: secret.base32, otpauth_url: secret.otpauth_url });
    }

    if (action === "verify") {
      // token provided -> verify then persist secret on user
      const { secret } = req.body;
      if (!secret || !token) return res.status(400).json({ message: "secret and token required" });
      const ok = verifyTotpToken(secret, token);
      if (!ok) return res.status(400).json({ message: "Invalid TOTP" });

      user.twoFactor.totp = true;
      user.twoFactor.totpSecret = secret;
      await user.save();
      return res.json({ message: "TOTP enabled" });
    }

    if (action === "disable") {
      user.twoFactor.totp = false;
      user.twoFactor.totpSecret = undefined;
      await user.save();
      return res.json({ message: "TOTP disabled" });
    }

    return res.status(400).json({ message: "Unknown action" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "TOTP flow error" });
  }
};

/** Signout - blacklist JWT */
export const signout = async (req, res) => {
  try {
    const token = req.token || req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(400).json({ message: "No token" });
    await blacklistToken(token);
    res.json({ message: "Signed out" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Signout failed" });
  }
};

/** Deactivate account (soft) */
export const deactivate = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.user.id, { isActive: false }, { new: true });
    // optional: invalidate tokens by blacklisting current token
    if (req.token) await blacklistToken(req.token);
    res.json({ message: "Account deactivated", user: { id: user._id, isActive: user.isActive } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Deactivate failed" });
  }
};

/** Delete account (permanent) */
export const deleteAccount = async (req, res) => {
  try {
    const userId = req.user.id;
    await User.findByIdAndDelete(userId);
    if (req.token) await blacklistToken(req.token);
    res.json({ message: "Account deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Delete failed" });
  }
};
