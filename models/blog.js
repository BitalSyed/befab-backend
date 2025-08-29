const mongoose = require("mongoose");
const BlogSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, required: true },
  content: String,
  featuredImage: String,
  tags: [String],
  status: { type: String, enum: ["draft", "published"], default: "draft" },
  scheduledPublish: Date,

  reactions: [
    {
      user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      type: String,
    },
  ],
  comments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Comment" }],

  views: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date,
});
const Blog = mongoose.model("Blog", BlogSchema);
module.exports = Blog;
