import express from "express";
import {
  register,
  login,
  googleSignIn,
  verifyEmail,
  resendVerifyEmail,
  sendOtp,
  verifyOtp,
  totpFlow,
  signout,
  deactivate,
  deleteAccount,
} from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validate.middleware.js";
import { authenticate } from "../middlewares/auth.middleware.js";
import {
  registerSchema,
  loginSchema,
  googleSignInSchema,
  sendOtpSchema,
  verifyOtpSchema,
  enableTotpSchema,
  emailVerifySchema,
} from "../validations/auth.validation.js";

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: User registration, login, verification, and account management
 */

/**
 * @openapi
 * /api/auth/register:
 *   post:
 *     summary: Register a new user (Buyer, Seller, or Admin)
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - fullName
 *               - email
 *               - password
 *               - role
 *             properties:
 *               fullName:
 *                 type: string
 *                 example: Festus Idowu
 *               email:
 *                 type: string
 *                 example: idowufestustemiloluwa@gmail.com
 *               password:
 *                 type: string
 *                 example: MySecurePassword123
 *               role:
 *                 type: string
 *                 enum: [buyer, seller, admin]
 *     responses:
 *       201:
 *         description: User registered successfully. Email verification link sent.
 *       400:
 *         description: Validation error or email already in use.
 */
router.post("/register", validate(registerSchema), register);

/**
 * @openapi
 * /api/auth/login:
 *   post:
 *     tags: [Authentication]
 *     summary: Login with email and password (may trigger 2FA)
  *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 example: idowufestustemiloluwa@gmail.com
 *               password:
 *                 type: string
 *                 example: MySecurePassword123
 *     responses:
 *       200:
 *         description: Login successful, returns JWT token.
 *       401:
 *         description: Invalid credentials or email not verified.
 */

router.post("/login", validate(loginSchema), login);

/**
 * @openapi
 * /api/auth/google:
 *   post:
 *     tags: [Authentication]
 *     summary: Sign in with Google (idToken)
 */
router.post("/google", validate(googleSignInSchema), googleSignIn);

/**
 * @openapi
 * /api/auth/verify-email:
 *   get:
 *     tags: [Authentication]
 *     summary: Verify email via token (link)
 */
router.get("/verify-email", verifyEmail);

router.post("/verify-email", validate(emailVerifySchema), verifyEmail);

/**
 * @openapi
 * /api/auth/resend-verify:
 *   post:
 *     tags: [Authentication]
 *     summary: Resend verification email
 */
router.post("/resend-verify", resendVerifyEmail);

/**
 * @openapi
 * /api/auth/send-otp:
 *   post:
 *     tags: [Authentication]
 *     summary: Send OTP via email or sms
 */
router.post("/send-otp", authenticate, validate(sendOtpSchema), sendOtp);

/**
 * @openapi
 * /api/auth/verify-otp:
 *   post:
 *     tags: [Authentication]
 *     summary: Verify OTP (email or sms)
 */
router.post("/verify-otp", validate(verifyOtpSchema), verifyOtp);

/**
 * @openapi
 * /api/auth/totp:
 *   post:
 *     tags: [Authentication]
 *     summary: TOTP flow for authenticator app (generate/verify/disable)
 */
router.post("/totp", authenticate, validate(enableTotpSchema), totpFlow);

/**
 * @openapi
 * /api/auth/signout:
 *   post:
 *     tags: [Authentication]
 *     summary: Sign out (blacklist token)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully.
 *       401:
 *         description: Unauthorized request.
 */
router.post("/signout", authenticate, signout);

/**
 * @openapi
 * /api/auth/deactivate:
 *   post:
 *     tags: [Authentication]
 *     summary: Temporarily Deactivate account (soft)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Account deactivated successfully.
 *       401:
 *         description: Unauthorized.
 */
router.post("/deactivate", authenticate, deactivate);

/**
 * @openapi
 * /api/auth/delete:
 *   delete:
 *     tags: [Authentication]
 *     summary: Delete account (hard)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Account deleted successfully.
 *       401:
 *         description: Unauthorized.

 */
router.delete("/delete", authenticate, deleteAccount);

export default router;
