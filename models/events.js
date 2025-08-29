const mongoose = require("mongoose");

const CompetitionSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
    },
    ip: {
      type: String,
    },
    location: {
      type: String,
    },
    date: {
      type: Date,
      required: true,
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },   // include virtuals when sending as JSON
    toObject: { virtuals: true }, // include virtuals when converting to object
  }
);

// Virtual status field (not stored in DB, always computed dynamically)
CompetitionSchema.virtual("status").get(function () {
  const now = new Date();

  // event is upcoming
  if (now < this.date) return "upcoming";

  // event is today
  if (now.toDateString() === this.date.toDateString()) return "active";

  // event already passed
  if (now > this.date) return "completed";

  return "upcoming"; // fallback
});

const Event = mongoose.model("Event", CompetitionSchema);
module.exports = Event;
