const mongoose = require('mongoose');

const MealItemSchema = new mongoose.Schema(
  {
    name: { type: String, },
    calories: { type: Number, }, // US metrics mandated in spec :contentReference[oaicite:13]{index=13}
    protein_g: { type: Number, default: 0 },
    fat_g: { type: Number, default: 0 },
    carbs_g: { type: Number, default: 0 },
    quantity: { type: Number, default: 1 },
    unit: { type: String, default: 'g' } // search selectable (grams/cups) :contentReference[oaicite:14]{index=14}
  },
  { _id: false }
);

const DayNutritionSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    date: { type: Date, required: true },
    meals: {
      breakfast: [MealItemSchema],
      lunch: [MealItemSchema],
      dinner: [MealItemSchema],
      snacks: [MealItemSchema],
      other: [MealItemSchema]
    },
    waterIntake_oz: { type: Number, default: 0 }, // hydration tracker; US metrics (oz) :contentReference[oaicite:15]{index=15}
    hydrationReminder: {
      enabled: { type: Boolean, default: false },
      frequency: { type: String, enum: ['daily', 'weekly', 'monthly'], default: 'daily' } // :contentReference[oaicite:16]{index=16}
    },
    notes: String
  },
  { timestamps: true }
);

DayNutritionSchema.index({ user: 1, date: 1 }, { unique: true });

module.exports = mongoose.model('DayNutrition', DayNutritionSchema);
