const mongoose = require("mongoose");
const CommentSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: String,
  targetType: { type: String, enum: ["blog", "file", "thread"] },
  targetId: { type: mongoose.Schema.Types.ObjectId, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Comment = mongoose.model("Comment", CommentSchema);
module.exports = Comment;
