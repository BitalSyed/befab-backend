const mongoose = require("mongoose");
const ForumSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  type: {
    type: String,
    enum: ["public", "private", "secret"],
    default: "public",
  },
  categories: [String],
  tags: [String],

  moderators: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  permissions: {
    canView: [String], // roles
    canPost: [String],
  },

  stats: {
    membersCount: { type: Number, default: 0 },
    postsCount: { type: Number, default: 0 },
    lastActivity: Date,
  },

  createdAt: { type: Date, default: Date.now },
});
const Forum = mongoose.model("Forum", ForumSchema);
module.exports = Forum;
