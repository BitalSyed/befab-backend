const mongoose = require("mongoose");

const GoalSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    name: { type: String, required: true, trim: true },
    durationDays: { type: Number, required: true, min: 1 },
    trackProgress: { type: Boolean, default: true },
    milestones: { type: Number, required: true },

    progressValue: { type: Number, default: 0 },
    progressPercent: { type: Number, default: 0 }, // ✅ only once

    status: {
      type: String,
      enum: ["active", "completed", "expired", "upcoming"],
      default: "upcoming",
    },

    category: {
      type: String,
      enum: ["Steps", "Distance", "Calories Burned", "Calories Taken", "Water Intake"],
      default: "Steps",
    },

    creator: {
      type: String,
      enum: ["Admin", "User", "AI"],
      default: "User",
    },

    startDate: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// 🔹 Virtual: Calculate end date
GoalSchema.virtual("endDate").get(function () {
  if (!this.startDate || !this.durationDays) return null;
  const endDate = new Date(this.startDate);
  endDate.setDate(endDate.getDate() + this.durationDays);
  return endDate;
});

// 🔹 Function: Calculate current status
GoalSchema.methods.computeStatus = function () {
  const now = new Date();
  const endDate = this.endDate;

  if (this.progressPercent >= 100 || this.progressValue >= this.milestones) {
    return "completed";
  }
  if (endDate && now > endDate) {
    return "expired";
  }
  if (now >= this.startDate && endDate && now <= endDate) {
    return "active";
  }
  if (now < this.startDate) {
    return "upcoming";
  }
  return "upcoming";
};

// 🔹 Always return dynamic status in JSON
GoalSchema.methods.toJSON = function () {
  const goal = this.toObject();
  goal.status = this.computeStatus();
  return goal;
};

// 🔹 Pre-save hook: keep DB status updated
GoalSchema.pre("save", function (next) {
  this.status = this.computeStatus();
  next();
});

module.exports = mongoose.model("Goal", GoalSchema);
