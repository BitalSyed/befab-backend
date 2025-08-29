const mongoose = require('mongoose');

const CompetitionSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true },
    category: {
      type: String,
      enum: ['Fitness', 'Nutrition', 'Wellness', 'Strength', 'Cardio', 'Team'],
      required: true,
    },
    type: {
      type: String,
      enum: ['Admin', 'AI'],
      default: 'Admin',
      required: true,
    },
    imageUrl: { type: String },
    status: {
      type: String,
      enum: ['draft', 'upcoming', 'active', 'completed', 'paused'],
      default: 'draft',
    }, // can still keep for admin override
    start: { type: Date, required: true },
    end: { type: Date, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    participants: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        progress: { type: Number, default: 0 },
        score: { type: Number, default: 0 },
        lastUpdated: { type: Date, default: Date.now }
      }
    ],
    leaderboard: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        rank: Number,
        score: Number
      }
    ]
  },
  { timestamps: true }
);

// ✅ Virtual for computed status based on start/end
CompetitionSchema.virtual('computedStatus').get(function() {
  const now = new Date();
  if (this.status === 'draft' || this.status === 'paused') {
    return this.status; // keep admin override
  }
  if (now < this.start) return 'upcoming';
  if (now >= this.start && now <= this.end) return 'active';
  if (now > this.end) return 'completed';
  return this.status; // fallback
});

// Optional: always update `status` before saving
CompetitionSchema.pre('save', function(next) {
  const now = new Date();
  if (this.status !== 'draft' && this.status !== 'paused') {
    if (now < this.start) this.status = 'upcoming';
    else if (now >= this.start && now <= this.end) this.status = 'active';
    else if (now > this.end) this.status = 'completed';
  }
  next();
});

module.exports = mongoose.model('Competition', CompetitionSchema);
