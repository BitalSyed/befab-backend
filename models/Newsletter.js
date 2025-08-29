const mongoose = require('mongoose');

const CommentSchema = new mongoose.Schema(
  {
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true, trim: true },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    parent: { type: mongoose.Schema.Types.ObjectId, ref: 'Newsletter.comments' } // subcomments
  },
  { timestamps: true }
);

const NewsletterSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true },
    picture: { type: String }, // optional thumbnail/image
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Admin only per spec :contentReference[oaicite:3]{index=3}
    status: { type: String, enum: ['draft', 'scheduled', 'published'], default: 'draft' }, // :contentReference[oaicite:4]{index=4}
    scheduledAt: { type: Date },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [CommentSchema],
    savedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  },
  { timestamps: true }
);

module.exports = mongoose.model('Newsletter', NewsletterSchema);
