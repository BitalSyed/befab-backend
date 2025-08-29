const mongoose = require('mongoose');

const SurveySchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    type: { type: String, enum: ['required', 'optional'], default: 'optional' }, // required/optional per spec :contentReference[oaicite:20]{index=20}
    audience: { type: String, enum: ['all', 'members', 'admins'], default: 'all' },
    dueDate: { type: Date },
    durationMin: { type: Number },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Admin :contentReference[oaicite:21]{index=21}
    questions: [
      {
        q: { type: String, required: true },
        kind: { type: String, enum: ['text', 'single', 'multi', 'number'], default: 'text' },
        options: [String]
      }
    ],
    responses: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        answers: [{}],
        submittedAt: { type: Date, default: Date.now }
      }
    ]
  },
  { timestamps: true }
);

module.exports = mongoose.model('Survey', SurveySchema);
