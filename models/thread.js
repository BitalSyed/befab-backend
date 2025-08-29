const mongoose = require("mongoose");
const ThreadSchema = new mongoose.Schema({
  forum: { type: mongoose.Schema.Types.ObjectId, ref: "Forum", required: true },
  title: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: String,
  tags: [String],

  reactions: [
    {
      user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      type: String,
    },
  ],
  views: { type: Number, default: 0 },

  createdAt: { type: Date, default: Date.now },
  updatedAt: Date,
});
const Thread = mongoose.model("Thread", ThreadSchema);
module.exports = Thread;
