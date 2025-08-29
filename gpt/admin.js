const express = require("express");
const app = express.Router();
// const users = require("../../models/users");
const transporter = require("../config/transporter.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
// const Log = require("../../models/logs.js");
const mongoose = require("mongoose");
// const passport = require("passport");
// const session = require("express-session");
const user = require("../models/user.js");
const Log = require("../models/logs.js");
const Newsletter = require("../models/news.js");
const Competition = require("../models/competition.js");
// const samlStrategy = require("./samlStrategy.js");

const Email = process.env.EMAIL;

// Message, To
async function sms(m, t, link) {
  console.log(m, t);
  return true;
}

// Message, To
async function email(m, t, link) {
  return new Promise((resolve, reject) => {
    const mailOptions = {
      from: Email, // not Email (was probably undefined)
      to: t,
      subject: "Your OTP Code",
      text: `Your OTP is: ${m} ${link ? `\n\nLink to Verify: ${link}` : ""}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending email:", error);
        reject(false);
      } else {
        console.log("Email sent:", info.response);
        resolve(true);
      }
    });
  });
}

function isEmail(input) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(input);
}

function isPhoneNumber(input) {
  const phoneRegex = /^(\+?\d{1,4}[\s-]?)?(\d{10,14})$/;
  return phoneRegex.test(input);
}

function validateInput(input) {
  if (isEmail(input)) {
    return { type: "email", valid: true };
  } else if (isPhoneNumber(input)) {
    return { type: "phone", valid: true };
  } else {
    return { type: "unknown", valid: false };
  }
}

const generateToken = (user, time) => {
  const secret = process.env.JWT_SECRET || "SkillRex-Tech"; // better to use env var

  const token = jwt.sign({ email: user }, secret, {
    expiresIn: `${time}d`, // or '1h', '15m', etc.
  });

  return token;
};

const generateTokenWithoutExpiry = (user) => {
  const secret = process.env.JWT_SECRET || "SkillRex-Tech"; // Use env var in production

  // No expiresIn property here
  const token = jwt.sign({ email: user }, secret);

  return token;
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "../files/news");
    // Ensure directory exists
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + "-" + file.fieldname + ext);
  },
});

// File filter (only images allowed)
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Only images are allowed"), false);
  }
};

const upload = multer({ storage });

app.post("/get", async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: "Session Expired" });
  }

  const email= jwt.verify(token, process.env.JWT_SECRET || "SkillRex-Tech").email;

  // Find user by email
  const u = await user.findOne({ email: email });
  if (!u) {
    return res.status(401).json({ error: "User Not Found" });
  }

  // await createSystemLog(
  //   user._id,
  //   "Logged-in",
  //   `${user.firstName} Logged-in as Admin`
  // );

  return res.json({
    u
  });
});

// *****Dashboard*****
app.post("/dashboard", async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: "Session Expired" });
  }

  const email= jwt.verify(token, process.env.JWT_SECRET || "SkillRex-Tech").email;

  // Find user by email
  const u = await user.findOne({ email: email });
  if (!u) {
    return res.status(401).json({ error: "User Not Found" });
  }



  // await createSystemLog(
  //   user._id,
  //   "Logged-in",
  //   `${user.firstName} Logged-in as Admin`
  // );

  return res.json({
    u
  });
});

// *****Users*****
app.post("/users", async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Session Expired" });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "SkillRex-Tech");
    const email = decoded.email;

    // Find current user
    const currentUser = await user.findOne({ email }).select;
    if (!currentUser) {
      return res.status(401).json({ error: "User Not Found" });
    }

    // Get all other users except me
    const otherUsers = await user.find({ _id: { $ne: currentUser._id } }).select("-password -__v");

    // Logs excluding mine, latest 5
    const logs = await Log.find({  })
      .sort({ createdAt: -1 })
      .limit(5).populate("user");

    // Count totals
    const totalUsers = await user.countDocuments();
    const adminCount = await user.countDocuments({ role: "admin" });
    const memberCount = await user.countDocuments({ role: "member" });

    // Active/Inactive in last 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    // Find distinct user IDs with logs in last 7 days
    const activeUserIds = await Log.distinct("user", { timestamp: { $gte: sevenDaysAgo } });

    const activeUsersCount = await user.countDocuments({
      _id: { $in: activeUserIds.map(id => new mongoose.Types.ObjectId(id)) }
    });

    const inactiveUsersCount = totalUsers - activeUsersCount;

    return res.json({
      currentUser,
      otherUsers,
      logs,
      counts: {
        totalUsers,
        adminCount,
        memberCount
      },
      activity: {
        activeUsers: activeUsersCount,
        inactiveUsers: inactiveUsersCount
      }
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server Error" });
  }
});
app.post("/push-user", async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Session Expired" });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "SkillRex-Tech");
    const email = decoded.email;

    // Find current user
    const currentUser = await user.findOne({ email });
    if (!currentUser) {
      return res.status(401).json({ error: "User Not Found" });
    }

    const existingUser = await user.findOne({ email: req.body.email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const existingUser1 = await user.findOne({ username: req.body.userName });
    if (existingUser1) {
      return res.status(400).json({ error: "User with this user name already exists" });
    }

    const newUser = new user({
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      username: req.body.userName,
      email: req.body.email,
      role: req.body.role || "member", // Default to member if not specified
      password: bcrypt.hashSync(req.body.password, 10), // Hash the password
    });

    await newUser.save();

    // Log the action
    const log = new Log({
      user: currentUser._id,
      email: currentUser.email,
      eventType: "user_created",
      description: `User ${newUser.email} created by ${currentUser.username}`,
    });
    await log.save();

    return res.json({
      message: "User created successfully",
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server Error" });
  }
});

// *****News Letter*****
app.post("/news", async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Session Expired" });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "SkillRex-Tech");
    const email = decoded.email;

    // Find current user
    const currentUser = await user.findOne({ email });
    if (!currentUser) {
      return res.status(401).json({ error: "User Not Found" });
    }

    // Get all newsletters with author populated
    const newsletters = await Newsletter.find()
      .populate("author", "-password -__v")
      .sort({ date: -1 });

    // Total newsletters
    const totalNewsletters = await Newsletter.countDocuments();

    // Last month calculation
    const lastMonth = new Date();
    lastMonth.setDate(lastMonth.getDate() - 30);

    const lastMonthCount = await Newsletter.countDocuments({
      date: { $gte: lastMonth },
    });

    const lastMonthRate =
      totalNewsletters > 0
        ? ((lastMonthCount / totalNewsletters) * 100).toFixed(2)
        : 0;

    // Today's newsletters
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const todayCount = await Newsletter.countDocuments({
      date: { $gte: startOfDay },
    });

    // Average per day in last month
    const avgPerDay = (lastMonthCount / 30).toFixed(2);

    return res.json({
      currentUser,
      newsletters,
      stats: {
        totalNewsletters,
        lastMonth: {
          created: lastMonthCount,
          rate: `${lastMonthRate}%`,
        },
        today: {
          created: todayCount,
        },
        average: {
          perDay: avgPerDay,
        },
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server Error" });
  }
});
app.post("/push-news", upload.single("picture"), async (req, res) => {
  try {
    const { token, title, description } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Session Expired" });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "SkillRex-Tech");
    const email = decoded.email;

    // Find current user
    const currentUser = await user.findOne({ email });
    if (!currentUser) {
      return res.status(401).json({ error: "User Not Found" });
    }

    // Handle uploaded file
    let picturePath = null;
    if (req.file) {
      picturePath = `/news/${req.file.filename}`; // public URL or relative path
    }

    const newUser = new Newsletter({
      title,
      description,
      picture: picturePath,
      author: currentUser._id,
    });

    await newUser.save();

    // Log the action
    const log = new Log({
      user: currentUser._id,
      email: currentUser.email,
      eventType: "newsletter_created",
      description: `Newsletter "${title}" created by ${currentUser.userName}`,
    });
    await log.save();

    return res.json({
      message: "Newsletter created successfully",
      data: newUser,
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server Error" });
  }
});

// *****Competition*****
app.post("/competition", async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Session Expired" });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "SkillRex-Tech");
    const email = decoded.email;

    // Find current user
    const currentUser = await user.findOne({ email });
    if (!currentUser) {
      return res.status(401).json({ error: "User Not Found" });
    }

    // Get all competitions with author & participants populated
    const competitions = await Competition.find()
      .populate("author", "-password -__v")
      .populate("participants", "-password -__v")
      .sort({ start: -1 });

    // Total competitions
    const totalCompetitions = await Competition.countDocuments();

    // Completed competitions count
    const completedCount = await Competition.countDocuments({ status: "Completed" });
    const completionRate =
      totalCompetitions > 0
        ? ((completedCount / totalCompetitions) * 100).toFixed(2)
        : 0;

    // Last month calculation
    const lastMonth = new Date();
    lastMonth.setDate(lastMonth.getDate() - 30);

    const lastMonthCount = await Competition.countDocuments({
      start: { $gte: lastMonth },
    });

    const creationRate =
      totalCompetitions > 0
        ? ((lastMonthCount / totalCompetitions) * 100).toFixed(2)
        : 0;

    // Today's competitions
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const todayCount = await Competition.countDocuments({
      start: { $gte: startOfDay },
    });

    // Average participants
    let totalParticipants = 0;
    competitions.forEach((c) => {
      totalParticipants += c.participants.length;
    });
    const avgParticipants =
      competitions.length > 0
        ? (totalParticipants / competitions.length).toFixed(2)
        : 0;

    return res.json({
      currentUser,
      competitions,
      stats: {
        totalCompetitions,
        completion: {
          completed: completedCount,
          rate: `${completionRate}%`,
        },
        lastMonth: {
          created: lastMonthCount,
          rate: `${creationRate}%`,
        },
        today: {
          created: todayCount,
        },
        average: {
          participants: avgParticipants,
        },
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server Error" });
  }
});

app.post("/push-competition", upload.none(), async (req, res) => {
  try {
    const { token, title, description, start, end } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Session Expired" });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "SkillRex-Tech");
    const email = decoded.email;

    // Find current user
    const currentUser = await user.findOne({ email });
    if (!currentUser) {
      return res.status(401).json({ error: "User Not Found" });
    }

    // Validate required fields
    if (!title || !description || !start || !end) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const startDate = new Date(start);
    const endDate = new Date(end);
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Date validation
    if (startDate < today) {
      return res.status(400).json({ error: "Start date cannot be before today" });
    }
    if (endDate < startDate) {
      return res.status(400).json({ error: "End date cannot be before start date" });
    }

    // Create new competition
    const newCompetition = new Competition({
      title,
      description,
      start: startDate,
      end: endDate,
      author: currentUser._id,
      participants: [], // initially empty
    });

    await newCompetition.save();

    // Log the action
    const log = new Log({
      user: currentUser._id,
      email: currentUser.email,
      eventType: "competition_created",
      description: `Competition "${title}" created by ${currentUser.userName}`,
    });
    await log.save();

    return res.json({
      message: "Competition created successfully",
      data: newCompetition,
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server Error" });
  }
});


module.exports = app;
