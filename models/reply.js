const mongoose = require("mongoose");
const ReplySchema = new mongoose.Schema({
  thread: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Thread",
    required: true,
  },
  parentReply: { type: mongoose.Schema.Types.ObjectId, ref: "Reply" }, // for nested comments
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: String,

  reactions: [
    {
      user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      type: String,
    },
  ],

  createdAt: { type: Date, default: Date.now },
  updatedAt: Date,
});
const Reply = mongoose.model("Reply", ReplySchema);
module.exports = Reply;
