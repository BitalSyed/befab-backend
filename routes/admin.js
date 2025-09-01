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
const { Chat, Message } = require("../models/Message");
const Goal = require("../models/Goal");

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
  const logs = await Log.find({}).sort({ createdAt: -1 }).populate("user");

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
    .populate("author", "firstName lastName username role userId")
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

router.get("/newsletters/get/:id", async (req, res) => {
  const list = await Newsletter.findOne({ _id: req.params.id })
    .populate("author", "firstName lastName username role")
    .sort({ createdAt: -1 });
  res.json(list);
});

// Newsletter upload
router.post("/newsletters", uploadNews.single("picture"), async (req, res) => {
  try {
    const { title, description, status, scheduledAt, id } = req.body;
    if (!title || !description)
      return res.status(400).json({ error: "Missing title/description" });

    // Build relative URL
    const picture = req.file ? `/news/${req.file.filename}` : null;

    if (id) {
      if (!picture) {
        const doc = await Newsletter.findByIdAndUpdate(
          id,
          {
            title,
            description,
            status: status || "draft",
            scheduledAt,
          },
          { new: true }
        );
        if (!doc) return res.status(404).json({ error: "Not found" });
        return res
          .status(201)
          .json({ message: "Newsletter updated", newsletter: doc });
      } else {
        const doc = await Newsletter.findByIdAndUpdate(
          id,
          {
            title,
            description,
            picture: picture || undefined,
            status: status || "draft",
            scheduledAt,
          },
          { new: true }
        );
        if (!doc) return res.status(404).json({ error: "Not found" });
        return res
          .status(201)
          .json({ message: "Newsletter updated", newsletter: doc });
      }
    }

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
      const thumbnailPath = thumbnailFile
        ? `/videos/${thumbnailFile.filename}`
        : "";

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

router.post("/videos/:id/flag", async (req, res) => {
  try {
    const video = await Video.findByIdAndUpdate(
      req.params.id,
      { status: "flagged" }, // update field
      { new: true } // return updated doc
    ).populate("uploader", "username role");

    if (!video) {
      return res.status(404).json({ error: "Video not found" });
    }

    res.json({ message: "Video flagged for review", video });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/videos/:id/reject", async (req, res) => {
  try {
    const video = await Video.findByIdAndUpdate(
      req.params.id,
      { status: "rejected" }, // update field
      { new: true } // return updated doc
    ).populate("uploader", "username role");

    if (!video) {
      return res.status(404).json({ error: "Video not found" });
    }

    res.json({ message: "Video rejected after review", video });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/videos/:id/approve", async (req, res) => {
  try {
    const video = await Video.findByIdAndUpdate(
      req.params.id,
      { status: "published" }, // update field
      { new: true } // return updated doc
    ).populate("uploader", "username role");

    if (!video) {
      return res.status(404).json({ error: "Video not found" });
    }

    res.json({ message: "Video published after review", video });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.delete("/videos/:id", async (req, res) => {
  try {
    const video = await Video.findById(req.params.id);
    if (!video) return res.status(404).json({ error: "Video not found" });

    // resolve paths
    const deleteFile = (fileUrl) => {
      if (!fileUrl) return;

      // if stored like "/videos/filename.mp4"
      const filePath = path.join(process.cwd(), "public", fileUrl);

      fs.unlink(filePath, (err) => {
        if (err) {
          console.error(`Failed to delete ${fileUrl}:`, err.message);
        } else {
          console.log(`Deleted file: ${fileUrl}`);
        }
      });
    };

    // delete thumbnail + video file if exist
    deleteFile(video.thumbnailUrl);
    deleteFile(video.url);

    // finally delete db entry
    await Video.findByIdAndDelete(req.params.id);

    res.json({ ok: true, message: "Video and files deleted successfully" });
  } catch (err) {
    console.error("Delete failed:", err);
    res.status(500).json({ error: "Failed to delete video" });
  }
});

/**
 * GROUPS (Admin creates/edits; can toggle public/private) :contentReference[oaicite:25]{index=25}
 */
router.get("/groups", async (_req, res) => {
  const groups = await Group.find()
    .sort({ createdAt: -1 })
    .populate("createdBy", "-passwordHash");
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
      const imageUrl = req.files?.image
        ? `/groups/${req.files.image[0].filename}`
        : null;
      const bannerUrl = req.files?.banner
        ? `/groups/${req.files.banner[0].filename}`
        : null;

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
  try {
    const video = await Group.findById(req.params.id);
    if (!video) return res.status(404).json({ error: "Group not found" });

    // resolve paths
    const deleteFile = (fileUrl) => {
      if (!fileUrl) return;

      // if stored like "/videos/filename.mp4"
      const filePath = path.join(process.cwd(), "public", fileUrl);

      fs.unlink(filePath, (err) => {
        if (err) {
          console.error(`Failed to delete ${fileUrl}:`, err.message);
        } else {
          console.log(`Deleted file: ${fileUrl}`);
        }
      });
    };

    // delete thumbnail + video file if exist
    deleteFile(video.bannerUrl);
    deleteFile(video.imageUrl);

    // finally delete db entry
    await Group.findByIdAndDelete(req.params.id);

    res.json({ ok: true, message: "Video and files deleted successfully" });
  } catch (err) {
    console.error("Delete failed:", err);
    res.status(500).json({ error: "Failed to delete video" });
  }
});

/**
 * COMPETITIONS (Admin CRUD; AI-suggested omitted server-side; leaderboard endpoint) :contentReference[oaicite:26]{index=26}
 */
router.get("/competitions", async (_req, res) => {
  const comps = await Competition.find().sort({ createdAt: -1 });
  res.json(comps);
});

router.post("/competitions", async (req, res) => {
  const { title, description, start, end, category, status, type } = req.body;
  if (!title || !description || !start || !end)
    return res.status(400).json({ error: "Missing fields" });
  if (new Date(end) <= new Date(start))
    return res.status(400).json({ error: "End must be after start" });
  const c = await Competition.create({
    title,
    description,
    start,
    end,
    category,
    status: status || "upcoming",
    author: req.user._id,
    type: type,
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
  const comps = await Event.find()
    .sort({ createdAt: -1 })
    .populate("author")
    .select("-passwordHash");
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

    res
      .status(201)
      .json({ message: "Event created successfully", event: newEvent });
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
  const list = await Survey.find()
    .sort({ createdAt: -1 })
    .populate("createdBy", "-passwordHash");
  res.json(list);
});

router.get("/surveys/:id", async (req, res) => {
  const list = await Survey.findOne({ _id: req.params.id })
    .sort({ createdAt: -1 })
    .populate("createdBy", "-passwordHash") // populate createdBy excluding passwordHash
    .populate({
      path: "responses", // populate the responses array
      populate: {
        path: "user", // inside each response, populate the user field
        select: "-passwordHash", // exclude passwordHash
      },
    });
  res.json(list);
});

router.post("/surveys/:id/response", async (req, res) => {
  try {
    const Survey = require("../models/Survey");
    const { answers } = req.body;

    const s = await Survey.findById(req.params.id);
    if (!s) return res.status(404).json({ error: "Not found" });

    // ✅ check if user already responded
    const alreadyResponded = s.responses.some(
      (r) => r.user.toString() === req.user._id.toString()
    );

    if (alreadyResponded) {
      return res
        .status(200)
        .json({ error: "You have already submitted this survey." });
    }

    // ✅ add new response
    s.responses.push({ user: req.user._id, answers });
    await s.save();

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
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

router.get("/chats/get", async (req, res) => {
  const chats = await Chat.find({})
    .sort({ updatedAt: -1 })
    .populate("participants");
  res.json(chats);
});

router.get("/chats", async (req, res) => {
  const chats = await Chat.find({ participants: req.user._id })
    .sort({ updatedAt: -1 })
    .populate("participants");
  res.json(chats);
});

router.post("/chats", async (req, res) => {
  const { participantIds } = req.body;

  if (!Array.isArray(participantIds) || participantIds.length === 0) {
    return res.status(400).json({ error: "participantIds required" });
  }

  // Include the logged-in user automatically
  const allParticipants = [
    req.user._id.toString(),
    ...participantIds.map((id) => id.toString()),
  ];

  // Check if chat already exists with exactly these participants
  let chat = await Chat.findOne({
    participants: { $all: allParticipants, $size: allParticipants.length },
  });

  if (!chat) {
    chat = await Chat.create({ participants: allParticipants });
  }

  res.status(200).json(chat);
});

router.get("/chats/:id/messages", async (req, res) => {
  const msgs = await Message.find({ chatId: req.params.id }).sort({
    createdAt: 1,
  });
  res.json(msgs);
});

router.post("/chats/:id/messages", async (req, res) => {
  const { content, mediaUrl, mediaType } = req.body;
  const msg = await Message.create({
    chatId: req.params.id,
    sender: req.user._id,
    content,
    mediaUrl,
    mediaType: mediaType || "none",
  });
  await Chat.findByIdAndUpdate(req.params.id, { lastMessageAt: new Date() });
  res.status(201).json(msg);
});

router.get("/goals", async (req, res) => {
  try {
    // 2. Get all user goals
    const goals = await Goal.find({})
      .sort({
        createdAt: -1,
      })
      .populate("user", "-passwordHash");

    // 7. Send updated list
    res.status(200).json(goals);
  } catch (err) {
    console.error("Error fetching goals:", err);
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/goals/current", async (req, res) => {
  const list = await Goal.findOne({
    user: req.user._id,
    category: req.query.q,
  }).sort({ createdAt: -1 });

  res.json(list);
});

router.post("/goals", async (req, res) => {
  try {
    const { name, durationDays, milestones, category, user } = req.body;
    if (!name || !durationDays || !milestones || !category || !user) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Get last goal for this user (latest createdAt)
    const lastGoal = await Goal.findOne({
      user: req.user._id,
      category: category,
      status: { $in: ["expiired", "completed"] },
    }).sort({ createdAt: -1 });

    const un = await User.findOne({ username: user });

    if (lastGoal)
      return res.status(400).json({ error: "An uncompleted goal exist" });

    const goal = await Goal.create({
      user: un._id,
      name,
      category,
      durationDays,
      milestones,
      creator: "Admin",
    });

    res.status(201).json(goal);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

function readSampleJson(userId) {
  try {
    const p = path.join(__dirname, `../${userId}.json`);
    if (fs.existsSync(p)) {
      const raw = fs.readFileSync(p, "utf8");
      const data = JSON.parse(raw);
      // Accept either array or { data: [...] }
      return Array.isArray(data)
        ? data
        : Array.isArray(data?.data)
        ? data.data
        : [];
    }
  } catch (e) {
    console.error("Failed reading sample JSON:", e.message);
  }
  return [];
}

/**
 * Normalize a Fitness-like doc (from DB or sample JSON) into a consistent shape
 */
function normalizeEntry(e) {
  const date = new Date(e.date);
  const summary = e.summary || {};
  const vitals = e.vitals || {};
  const body = e.bodyMeasurements || e.body || {};

  // Activities array (manual workouts etc.)
  const activities = Array.isArray(e.activities) ? e.activities : [];

  // Attempt to infer "active minutes" from activities durations (sum of duration_min).
  const activeMin = activities.reduce(
    (acc, a) => acc + (Number(a.duration_min) || 0),
    0
  );

  // Try to map a few common name variants we might see in sample JSON.
  const hr =
    Number(summary.heartRate_bpm ?? e.heartRate_bpm ?? e.heartRate ?? 0) || 0;
  const steps = Number(summary.steps ?? e.steps ?? 0) || 0;
  const calories =
    Number(summary.calories_kcal ?? e.calories_kcal ?? e.calories ?? 0) || 0;

  const bmi = Number(body.bmi ?? e.bmi ?? 0) || 0;
  const bodyFatPct =
    Number(body.bodyFat_pct ?? e.bodyFat_pct ?? e.fat ?? 0) || 0;

  return {
    date,
    steps,
    calories,
    activeMin,
    heartRate_bpm: hr,
    bmi,
    bodyFat_pct: bodyFatPct,
    activities, // keep original to count types (type, duration_min, etc.)
  };
}

/**
 * Group by day key (YYYY-MM-DD)
 */
function dayKey(d) {
  const dt = new Date(d);
  const y = dt.getFullYear();
  const m = String(dt.getMonth() + 1).padStart(2, "0");
  const dd = String(dt.getDate()).padStart(2, "0");
  return `${y}-${m}-${dd}`;
}

/**
 * Group by ISO week (YYYY-Www). Uses Monday as week start.
 */
function weekKey(d) {
  const date = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const dayNum = (date.getUTCDay() + 6) % 7; // Mon=0..Sun=6
  date.setUTCDate(date.getUTCDate() - dayNum + 3); // move to Thu of current week
  const firstThu = new Date(Date.UTC(date.getUTCFullYear(), 0, 4));
  const weekNo =
    1 +
    Math.round(
      ((date - firstThu) / 86400000 - 3 + ((firstThu.getUTCDay() + 6) % 7)) / 7
    );
  return `${date.getUTCFullYear()}-W${String(weekNo).padStart(2, "0")}`;
}

/**
 * Compute percentage breakdown from a map of counts
 */
function percentageMap(counts) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const out = {};
  for (const [k, v] of Object.entries(counts)) {
    out[k] = +((v * 100) / total).toFixed(2);
  }
  return out;
}

/**
 * GET /analytics/:userId
 *
 * Response JSON:
 * {
 *   totals: { totalWorkouts, activeUsers, avgSteps, caloriesBurned, activityCompliancePct },
 *   charts: {
 *     sevenDay: {
 *       labels: [...7 dates...],
 *       steps: [...],
 *       calories: [...],
 *       activeMinutes: [...]
 *     },
 *     eightWeeks: {
 *       labels: ["YYYY-W##", ... up to 8],
 *       heartRateAvg: [...],
 *       bmiAvg: [...],
 *       bodyFatPctAvg: [...]
 *     }
 *   },
 *   workoutTypeTotals: { strength, cardio, other, hiit, yoga, pilates },
 *   activityPercentages: { running, weightTraining, yoga }
 * }
 */

/**
 * Normalize one fitness entry (adjust this to match your actual JSON schema!)
 */
function normalizeEntry(data) {
  const steps = (data["HealthDataType.STEPS"] || []).reduce(
    (sum, e) => sum + (e.value?.numericValue || 0),
    0
  );

  const calories = (data["HealthDataType.TOTAL_CALORIES_BURNED"] || []).reduce(
    (sum, e) => sum + (e.value?.numericValue || 0),
    0
  );

  const hrData = (data["HealthDataType.HEART_RATE"] || []).map(
    (e) => e.value?.numericValue || 0
  );
  const heartRate = hrData.length
    ? hrData.reduce((a, b) => a + b, 0) / hrData.length
    : 0;

  const bmiData = data["HealthDataType.BODY_MASS_INDEX"] || [];
  const bmi = bmiData.length
    ? bmiData[bmiData.length - 1].value.numericValue
    : 0;

  const fatData = data["HealthDataType.BODY_FAT_PERCENTAGE"] || [];
  const fat = fatData.length
    ? fatData[fatData.length - 1].value.numericValue
    : 0;

  const sleepMinutes = (data["HealthDataType.SLEEP_SESSION"] || []).reduce(
    (sum, e) => sum + (e.value?.numericValue || 0),
    0
  );

  const distanceMeters = (data["HealthDataType.DISTANCE_DELTA"] || []).reduce(
    (sum, e) => sum + (e.value?.numericValue || 0),
    0
  );
  const distanceKm = distanceMeters / 1000;

  // --- Activity Categories ---
  const totalActivityScore = steps + distanceKm * 1000 + calories;

  const cardio = totalActivityScore
    ? (steps + distanceKm * 1000 + calories) / totalActivityScore
    : 0;
  const strength = 0; // no clear data → leave 0 or approximate
  const yoga = 0; // no clear data → leave 0 or approximate
  const others = 1 - cardio - strength - yoga;

  return {
    steps,
    calories,
    heartRate,
    bmi,
    fat,
    sleepMinutes,
    distanceKm,
    categories: {
      cardio: +(cardio * 100).toFixed(1),
      strength: +(strength * 100).toFixed(1),
      yoga: +(yoga * 100).toFixed(1),
      others: +(others * 100).toFixed(1),
    },
  };
}

/**
 * Utility helpers
 */
function dayKey(d) {
  const dt = new Date(d);
  return dt.toISOString().split("T")[0]; // YYYY-MM-DD
}
function weekKey(d) {
  const date = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const dayNum = (date.getUTCDay() + 6) % 7;
  date.setUTCDate(date.getUTCDate() - dayNum + 3);
  const firstThu = new Date(Date.UTC(date.getUTCFullYear(), 0, 4));
  const weekNo =
    1 +
    Math.round(
      ((date - firstThu) / 86400000 - 3 + ((firstThu.getUTCDay() + 6) % 7)) / 7
    );
  return `${date.getUTCFullYear()}-W${String(weekNo).padStart(2, "0")}`;
}
function percentageMap(counts) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const out = {};
  for (const [k, v] of Object.entries(counts)) {
    out[k] = +((v * 100) / total).toFixed(2);
  }
  return out;
}

/**
 * GET /fitness
 * Aggregates all user JSON files in root dir
 */

function getTotalHealthDataForDate(jsonPath, dataType, targetDate) {
  // Fetch the JSON data
  const dataPath = path.join(__dirname, `../${jsonPath}.json`);
  const healthData = JSON.parse(fs.readFileSync(dataPath, "utf-8"));

  // Extract the data for the specified type
  const dataArray = healthData[dataType] || [];

  // Convert target date to match the format in the data (YYYY-MM-DD)
  const formattedTargetDate = new Date(targetDate).toISOString().split("T")[0];

  // Filter data for the target date and sum numeric values
  const total = dataArray.reduce((sum, entry) => {
    const entryDate = entry.dateFrom.split("T")[0];
    if (
      entryDate === formattedTargetDate &&
      entry.value &&
      entry.value.numericValue !== undefined
    ) {
      return sum + entry.value.numericValue;
    }
    return sum;
  }, 0);

  return total;
}

router.get("/fitness", async (req, res) => {
  try {
    console.log(
      getTotalHealthDataForDate(
        "68a8cf47ed7f637f5dafc1bc",
        "HealthDataType.STEPS",
        "2025-08-30"
      )
    );
    // Response
    res.json({});
  } catch (err) {
    console.error("Analytics error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
