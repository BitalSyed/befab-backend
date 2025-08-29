const mongoose = require("mongoose");

const GoalSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    name: { type: String, required: true, trim: true },
    durationDays: { type: Number, required: true, min: 1 },
    trackProgress: { type: Boolean, default: true },
    milestones: { type: Number, required: true },
    progressValue: { type: Number, default: 0 },
    progressPercent: { type: Number, default: 0 },
    status: {
      type: String,
      enum: ["active", "completed", "expired", 'upcoming'],
      default: "active",
    },
    startDate: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// 🔹 Virtual: check if expired based on createdAt + durationDays
GoalSchema.virtual("isExpired").get(function () {
  if (!this.createdAt || !this.durationDays) return false;
  const endDate = new Date(this.createdAt);
  endDate.setDate(endDate.getDate() + this.durationDays);
  return new Date() > endDate;
});

// 🔹 Pre hook: whenever doc is loaded, update status automatically
GoalSchema.pre("save", function (next) {
  if (this.createdAt && this.durationDays) {
    const endDate = new Date(this.createdAt);
    endDate.setDate(endDate.getDate() + this.durationDays);
    if (new Date() > endDate) {
      this.status = "completed";
    }
  }
  next();
});

module.exports = mongoose.model("Goal", GoalSchema);
