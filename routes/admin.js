const express = require("express");
const router = express.Router();
const { requireAuth, requireRole } = require("../middleware/auth");

const User = require("../models/User");
const Newsletter = require("../models/Newsletter");
const Video = require("../models/Video");
const Group = require("../models/Group");
const Competition = require("../models/Competition");
const Survey = require("../models/Survey");
const multer = require("multer");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
const Log = require("../models/logs");
const { events } = require("../models/events");
const Event = require("../models/events");

// All admin routes require admin
router.use(requireAuth, requireRole("admin"));

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

const storage1 = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "../files/videos");
    // Ensure directory exists
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + "-" + file.fieldname + ext);
  },
});

const storage2 = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "../files/groups");
    // Ensure directory exists
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + "-" + file.fieldname + ext);
  },
});

const uploadNews = multer({ storage });
const uploadVideo = multer({ storage: storage1 });
const uploadGroup = multer({ storage: storage2 });

router.post("/get", async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: "Session Expired" });
  }

  const email = req.user.email;

  // Find user by email
  const u = await User.findOne({ email: email });
  if (!u) {
    return res.status(401).json({ error: "User Not Found" });
  }

  // await createSystemLog(
  //   user._id,
  //   "Logged-in",
  //   `${user.firstName} Logged-in as Admin`
  // );

  return res.json({
    u,
  });
});

/**
 * ADMIN: Dashboard snapshots (counts/analytics placeholders)
 * Matches spec: user counts, content stats, etc.
 */
router.get("/dashboard", async (req, res) => {
  const [
    totalUsers,
    admins,
    members,
    newsletters,
    videos,
    groups,
    competitions,
    surveys,
  ] = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ role: "admin" }),
    User.countDocuments({ role: "member" }),
    Newsletter.countDocuments(),
    Video.countDocuments(),
    Group.countDocuments(),
    Competition.countDocuments(),
    Survey.countDocuments(),
  ]);

  res.json({
    users: { total: totalUsers, admins, members },
    content: { newsletters, videos, groups, competitions, surveys },
  });
});

/**
 * USER MANAGEMENT (Admin)
 */
router.get("/users", async (req, res) => {
  const users = await User.find({}).select("-passwordHash");
  res.json(users);
});

router.get("/users/activity", async (req, res) => {
  const logs = await Log.find({})
    .sort({ createdAt: -1 })
    .populate("user");

  // Count totals
  const totalUsers = await User.countDocuments();
  const adminCount = await User.countDocuments({ role: "admin" });
  const memberCount = await User.countDocuments({ role: "member" });

  const activeUsersCount = await User.countDocuments({ isActive: true });
  const lockedUsersCount = await User.countDocuments({ isLocked: true });

  const inactiveUsersCount = totalUsers - activeUsersCount;

  return res.json({
    logs,
    counts: {
      totalUsers,
      adminCount,
      memberCount,
    },
    activity: {
      activeUsers: activeUsersCount,
      inactiveUsers: inactiveUsersCount,
      lockedUsers: lockedUsersCount,
      adminUsers: adminCount,
    },
  });
});

router.post("/users", async (req, res) => {
  const { firstName, lastName, username, email, passwordHash, role } = req.body;
  if (!firstName || !lastName || !username || !email || !passwordHash) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  const exists = await User.findOne({ $or: [{ email }, { username }] });
  if (exists) return res.status(409).json({ error: "User already exists" });

  const u = await User.create({
    firstName,
    lastName,
    username,
    email,
    passwordHash: bcrypt.hashSync(passwordHash, 10), // hash password,
    role: role || "member",
  });
  res.status(201).json({ message: "User created", user: u });
});

router.patch("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    console.log(id, req.body);

    // Build update object dynamically (only provided fields)
    const update = {};
    const allowedFields = [
      "firstName",
      "lastName",
      "username",
      "email",
      "role",
      "isActive",
      "isLocked",
      "avatarUrl",
      "password",
    ];

    allowedFields.forEach((field) => {
      if (req.body[field] !== undefined) {
        update[field] = req.body[field];
      }
    });

    // Handle password separately
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      update.passwordHash = await bcrypt.hash(req.body.password, salt);
    }

    const user = await User.findByIdAndUpdate(id, update, {
      new: true,
      runValidators: true,
    }).select("-passwordHash");

    if (!user) return res.status(404).json({ error: "Not found" });

    res.json(user);
  } catch (error) {
    console.error("Update user error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

router.delete("/users/:id", async (req, res) => {
  const { id } = req.params;
  await User.findByIdAndDelete(id);
  res.json({ ok: true });
});

/**
 * NEWSLETTERS (Admin creates/edits; statuses: draft/scheduled/published)
 * per spec: only admins post; users can read/comment/like/save. :contentReference[oaicite:23]{index=23}
 */
router.get("/newsletters", async (_req, res) => {
  const list = await Newsletter.find()
    .populate("author", "firstName lastName username role")
    .sort({ createdAt: -1 });
  res.json(list);
});

router.get("/newsletters/analytics", async (_req, res) => {
    // Total newsletters
    const totalNewsletters = await Newsletter.countDocuments();

    // Last month calculation
    const lastMonth = new Date();
    lastMonth.setDate(lastMonth.getDate() - 30);

    const lastMonthCount = await Newsletter.countDocuments({
      createdAt: { $gte: lastMonth },
    });

    const lastMonthRate =
      totalNewsletters > 0
        ? ((lastMonthCount / totalNewsletters) * 100).toFixed(2)
        : 0;

    // Today's newsletters
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const todayCount = await Newsletter.countDocuments({
      createdAt: { $gte: startOfDay },
    });

    // Average per day in last month
    const avgPerDay = (lastMonthCount / 30).toFixed(2);

    return res.json({
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
  res.json(list);
});

// Newsletter upload
router.post("/newsletters", uploadNews.single("picture"), async (req, res) => {
  try {
    const { title, description, status, scheduledAt } = req.body;
    if (!title || !description)
      return res.status(400).json({ error: "Missing title/description" });

    // Build relative URL
    const picture = req.file ? `/news/${req.file.filename}` : null;

    const doc = await Newsletter.create({
      title,
      description,
      picture,
      status: status || "draft",
      scheduledAt,
      author: req.user._id,
    });

    res.status(201).json({ message: "Newsletter created", newsletter: doc });
  } catch (err) {
    console.error("Error creating newsletter:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.patch("/newsletters/:id", async (req, res) => {
  const doc = await Newsletter.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  if (!doc) return res.status(404).json({ error: "Not found" });
  res.json(doc);
});

router.delete("/newsletters/:id", async (req, res) => {
  await Newsletter.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

/**
 * VIDEO MANAGEMENT (Admin moderate/approve/remove; analytics later)
 * Categories: BeFAB HBCU, Mentor Meetup, Students. :contentReference[oaicite:24]{index=24}
 */
// Video upload
router.post(
  "/videos",
  uploadVideo.fields([
    { name: "video", maxCount: 1 },
    { name: "thumbnail", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { title, caption, category, durationSec } = req.body;
      if (!title || !category || !req.files?.video?.[0]) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      const videoFile = req.files.video[0];
      const thumbnailFile = req.files.thumbnail?.[0];

      // Save only relative paths
      const videoPath = `/videos/${videoFile.filename}`;
      const thumbnailPath = thumbnailFile ? `/videos/${thumbnailFile.filename}` : "";

      const video = new Video({
        uploader: req.user._id,
        title,
        caption,
        category,
        url: videoPath,
        thumbnailUrl: thumbnailPath,
        durationSec: durationSec ? Number(durationSec) : 0,
      });

      await video.save();

      res.status(201).json({ message: "Video uploaded successfully", video });
    } catch (err) {
      console.error("Error uploading video:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

router.get("/videos", async (_req, res) => {
  const vids = await Video.find()
    .populate("uploader", "username role")
    .sort({ createdAt: -1 });
  res.json(vids);
});

router.patch("/videos/:id/moderate", async (req, res) => {
  const { status } = req.body; // pending/approved/rejected/published
  if (!["pending", "approved", "rejected", "published"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }
  const video = await Video.findByIdAndUpdate(
    req.params.id,
    { status },
    { new: true }
  );
  if (!video) return res.status(404).json({ error: "Not found" });
  res.json(video);
});

router.delete("/videos/:id", async (req, res) => {
  await Video.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

/**
 * GROUPS (Admin creates/edits; can toggle public/private) :contentReference[oaicite:25]{index=25}
 */
router.get("/groups", async (_req, res) => {
  const groups = await Group.find().sort({ createdAt: -1 });
  res.json(groups);
});

router.post(
  "/groups",
  uploadGroup.fields([
    { name: "image", maxCount: 1 },
    { name: "banner", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { name, description, visibility } = req.body;
      if (!name) return res.status(400).json({ error: "Missing name" });

      // extract file paths from multer
      const imageUrl = req.files?.image ? `/groups/${req.files.image[0].filename}` : null;
      const bannerUrl = req.files?.banner ? `/groups/${req.files.banner[0].filename}` : null;

      const grp = await Group.create({
        name,
        description,
        imageUrl,
        bannerUrl,
        visibility,
        createdBy: req.user._id,
      });

      res.status(201).json({
        message: "Group created successfully",
        group: grp,
      });
    } catch (err) {
      console.error("Error creating group:", err);
      res.status(500).json({ error: "Server error while creating group" });
    }
  }
);

router.patch("/groups/:id", async (req, res) => {
  const grp = await Group.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  if (!grp) return res.status(404).json({ error: "Not found" });
  res.json(grp);
});

router.delete("/groups/:id", async (req, res) => {
  await Group.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

/**
 * COMPETITIONS (Admin CRUD; AI-suggested omitted server-side; leaderboard endpoint) :contentReference[oaicite:26]{index=26}
 */
router.get("/competitions", async (_req, res) => {
  const comps = await Competition.find().sort({ createdAt: -1 });
  res.json(comps);
});

router.post("/competitions", async (req, res) => {
  const { title, description, start, end, category, status } = req.body;
  if (!title || !description || !start || !end)
    return res.status(400).json({ error: "Missing fields" });
  if (new Date(end) <= new Date(start))
    return res.status(400).json({ error: "End must be after start" });
  const c = await Competition.create({
    title,
    description,
    start,
    end, category,
    status: status || "upcoming",
    author: req.user._id,
  });
  res.status(201).json(c);
});

router.patch("/competitions/:id", async (req, res) => {
  const c = await Competition.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  if (!c) return res.status(404).json({ error: "Not found" });
  res.json(c);
});

router.delete("/competitions/:id", async (req, res) => {
  await Competition.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

router.get("/competitions/:id/leaderboard", async (req, res) => {
  const c = await Competition.findById(req.params.id).populate(
    "leaderboard.user",
    "username"
  );
  if (!c) return res.status(404).json({ error: "Not found" });
  res.json(c.leaderboard);
});

/**
 * EVENTS (Admin CRUD; AI-suggested omitted server-side; leaderboard endpoint) :contentReference[oaicite:26]{index=26}
 */
router.get("/events", async (_req, res) => {
  const comps = await Event.find().sort({ createdAt: -1 }).populate("author").select("-passwordHash");
  res.json(comps);
});

router.post("/events", async (req, res) => {
  try {
    const { title, location, date, ip } = req.body;

    // Validation
    if (!title || !location) {
      return res.status(400).json({ error: "Missing fields" });
    }

    // Create a new event instance
    const newEvent = new Event({
      title,
      location,
      date: date,
      ip,
      author: req.user._id,
    });

    // Save to database
    await newEvent.save();

    res.status(201).json({ message: "Event created successfully", event: newEvent });
  } catch (err) {
    console.error("Error creating event:", err);
    res.status(500).json({ error: "Server error while creating event" });
  }
});

// router.patch("/competitions/:id", async (req, res) => {
//   const c = await Competition.findByIdAndUpdate(req.params.id, req.body, {
//     new: true,
//   });
//   if (!c) return res.status(404).json({ error: "Not found" });
//   res.json(c);
// });

// router.delete("/competitions/:id", async (req, res) => {
//   await Competition.findByIdAndDelete(req.params.id);
//   res.json({ ok: true });
// });

// router.get("/competitions/:id/leaderboard", async (req, res) => {
//   const c = await Competition.findById(req.params.id).populate(
//     "leaderboard.user",
//     "username"
//   );
//   if (!c) return res.status(404).json({ error: "Not found" });
//   res.json(c.leaderboard);
// });

/**
 * SURVEYS (Admin creates; required/optional) :contentReference[oaicite:27]{index=27}
 */
router.get("/surveys", async (_req, res) => {
  const list = await Survey.find().sort({ createdAt: -1 });
  res.json(list);
});

router.post("/surveys", async (req, res) => {
  const {
    title,
    description,
    type,
    audience,
    dueDate,
    durationMin,
    questions,
  } = req.body;
  if (!title) return res.status(400).json({ error: "Missing title" });
  const survey = await Survey.create({
    title,
    description,
    type,
    audience,
    dueDate,
    durationMin,
    questions,
    createdBy: req.user._id,
  });
  res.status(201).json(survey);
});

router.patch("/surveys/:id", async (req, res) => {
  const survey = await Survey.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  if (!survey) return res.status(404).json({ error: "Not found" });
  res.json(survey);
});

router.delete("/surveys/:id", async (req, res) => {
  await Survey.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

module.exports = router;
