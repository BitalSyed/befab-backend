const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const eventLogSchema = new Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  email: {
    type: String,
    required: true
  },
  eventType: {
    type: String,
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  description: {
    type: String,
    required: true
  },
  autoDelete: {
    type: Boolean,
    default: false
  },
  retentionDays: {
    type: Number,
    default: 365 // you can change the default retention period
  },
  lastCleanup: {
    type: Date,
    default: null
  }
});

const Log = mongoose.model("log", eventLogSchema);
module.exports = Log;
