const mongoose = require("mongoose");
const FileSchema = new mongoose.Schema({
  uploader: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  fileName: String,
  fileUrl: String,
  size: Number,
  type: String,
  tags: [String],
  description: String,

  visibility: {
    type: String,
    enum: ["public", "private", "group"],
    default: "public",
  },
  group: { type: mongoose.Schema.Types.ObjectId, ref: "Group" }, // optional

  versionHistory: [
    {
      fileUrl: String,
      updatedAt: Date,
    },
  ],

  comments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Comment" }],

  createdAt: { type: Date, default: Date.now },
});
const File = mongoose.model("File", FileSchema);
module.exports = File;
