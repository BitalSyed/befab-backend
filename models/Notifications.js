const mongoose = require('mongoose');

const NotificationSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // recipient
    content: { type: String, required: true, trim: true },
    read: { type: Boolean, default: false } // optional: track if user opened it
  },
  { timestamps: { createdAt: true, updatedAt: false } } // only createdAt
);

module.exports = mongoose.model('Notification', NotificationSchema);
