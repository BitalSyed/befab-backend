const mongoose = require('mongoose');

const FitnessSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    date: { type: Date, required: true },
    summary: {
      heartRate_bpm: Number,
      steps: Number,
      calories_kcal: Number,
      sleep_hrs: Number
    }, // Fitness Summary & Sleep Tracker (from Health app) :contentReference[oaicite:17]{index=17}
    vitals: {
      bloodPressure_systolic: Number,
      bloodPressure_diastolic: Number,
      bloodGlucose_mgdl: Number,
      spo2_percent: Number,
      respiratoryRate_bpm: Number,
      bodyTemp_f: Number
    }, // U.S. metrics note :contentReference[oaicite:18]{index=18}
    bodyComposition: {
      weight_lb: Number,
      height_in: Number,
      bmi: Number,
      bodyFat_percent: Number
    },
    workouts: [
      {
        type: { type: String, trim: true },
        duration_min: Number,
        distance_mi: Number,
        calories_kcal: Number,
        notes: String
      }
    ] // manual additions supported :contentReference[oaicite:19]{index=19}
  },
  { timestamps: true }
);

FitnessSchema.index({ user: 1, date: 1 }, { unique: true });

module.exports = mongoose.model('Fitness', FitnessSchema);
