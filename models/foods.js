const mongoose = require("mongoose");
const UserSchema = new mongoose.Schema({
  // nutrition: { type: mongoose.Schema.Types.ObjectId, ref: "nutrition" },
  name: { type: String },
  category: { type: String },
  // consumed: { type: Number },
  // quantity: { type: Number },
  calories: { type: Number },
  createdAt: { type: Date, default: Date.now },
});
const Food = mongoose.model("food", UserSchema);
module.exports = Food;
