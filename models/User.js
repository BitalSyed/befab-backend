const mongoose = require("mongoose");

const roles = ["admin", "member"];

const UserSchema = new mongoose.Schema(
  {
    firstName: { type: String, trim: true, },
    lastName: { type: String, trim: true, },
    username: {
      type: String,
      trim: true,
      unique: true,
      match: /^[a-zA-Z0-9_.-]+@befab$/i, // “username@Befab” format from spec
    }, // :contentReference[oaicite:0]{index=0}
    userId: {
      type: String,
      trim: true,
      unique: true,
    }, // :contentReference[oaicite:0]{index=0}
    email: {
      type: String,
      trim: true,
      lowercase: true,
      unique: true,
    },
    otp: {
    type: String,
  },
  otpExpiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 5 * 60 * 1000),
  },
    passwordHash: { type: String, },
    role: { type: String, enum: roles, default: "member" }, // only Admin, Member per spec :contentReference[oaicite:1]{index=1}
    institution: { type: String, trim: true }, // SSO selected institution (optional) :contentReference[oaicite:2]{index=2}
    avatarUrl: { type: String, trim: true },
    isActive: { type: Boolean, default: true },
    lastPing: { type: Date, default: Date.now() },
    isLocked: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const User = mongoose.models.User || mongoose.model("User", UserSchema);
module.exports = User;
