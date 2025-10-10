import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

console.log("Setting up email transporter with host:", process.env.SMTP_HOST);
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

export const sendEmail = async ({ to, subject, html, text }) => {
  console.log("Sending email to:", to);
  const info = await transporter.sendMail({
    from: process.env.EMAIL_FROM || "no-reply@p2p.example",
    to,
    subject,
    text,
    html,
  });
  console.log("Email sent:", info);
  return info;
};
