import Joi from "joi";

export const registerSchema = Joi.object({
  name: Joi.string().min(2).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  phone: Joi.string().optional(),
  role: Joi.string().valid("buyer", "seller").optional(),
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  totp: Joi.string().optional(), // if 2FA enabled for authenticator app
});

export const googleSignInSchema = Joi.object({
  idToken: Joi.string().required(), // Google ID token from client
});

export const sendOtpSchema = Joi.object({
  type: Joi.string().valid("email", "sms").required(),
});

export const verifyOtpSchema = Joi.object({
  type: Joi.string().valid("email", "sms").required(),
  code: Joi.string().required(),
});

export const enableTotpSchema = Joi.object({
  action: Joi.string().valid("generate", "verify", "disable").required(),
  token: Joi.string().optional(), // verify with code when enabling
});

export const emailVerifySchema = Joi.object({
  token: Joi.string().required(),
});
