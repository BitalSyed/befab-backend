const mongoose = require('mongoose');

const GroupSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    imageUrl: { type: String },
    bannerUrl: { type: String },
    visibility: { type: String, enum: ['public', 'private'], default: 'public' }, // admin sets public/private :contentReference[oaicite:7]{index=7}
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Admin per spec :contentReference[oaicite:8]{index=8}
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    joinRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    posts: [
      {
        author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        content: { type: String, required: true },
        images: [String],
        likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
        comments: [
          {
            author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
            content: { type: String, required: true },
            likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
          }
        ]
      }
    ],
    savedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  },
  { timestamps: true }
);

module.exports = mongoose.model('Group', GroupSchema);
