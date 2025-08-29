const mongoose = require('mongoose');

const categories = ['BeFAB HBCU', 'Mentor Meetup', 'Students']; // posting rules vary by role :contentReference[oaicite:5]{index=5}
const types = ['Post', 'Story', 'Reel', 'Live']; // posting rules vary by role :contentReference[oaicite:5]{index=5}
const statuses = ['pending', 'approved', 'rejected', 'published'];

const VideoSchema = new mongoose.Schema(
  {
    uploader: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, trim: true, required: true },
    caption: { type: String, trim: true },
    category: { type: String, enum: categories, required: true, default: 'BeFAB HBCU' },
    type: { type: String, enum: types, default: 'post' },
    url: { type: String, required: true }, // storage URL
    thumbnailUrl: { type: String },
    durationSec: { type: Number, min: 0 },
    status: { type: String, enum: statuses, default: 'pending' }, // admin moderation :contentReference[oaicite:6]{index=6}
    views: { type: Number, default: 0 },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    savedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [
      {
        author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        content: { type: String, required: true, trim: true },
        likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
      }
    ],
    flags: [
      {
        by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        reason: String,
        createdAt: { type: Date, default: Date.now }
      }
    ]
  },
  { timestamps: true }
);

module.exports = mongoose.model('Video', VideoSchema);
