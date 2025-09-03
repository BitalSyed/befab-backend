const express = require("express");
const router = express.Router();
const { requireAuth } = require("../middleware/auth");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");

const Newsletter = require("../models/Newsletter");
const Video = require("../models/Video");
const Group = require("../models/Group");
const Competition = require("../models/Competition");
const Goal = require("../models/Goal");
const DayNutrition = require("../models/Nutrition");
const Fitness = require("../models/Fitness");
const { Chat, Message } = require("../models/Message");
const Event = require("../models/events");
const User = require("../models/User");
const Food = require("../models/foods");
const Notifications = require("../models/Notifications");

// All app (user-facing) routes require auth
router.use(requireAuth);

/**
 * HOME content feed selections & notifications will be client-driven.
 * Below are concrete feature endpoints.
 */
router.get("/notifications", async (req, res) => {
  try {
    if (!req.user || !req.user._id) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const notifications = await Notifications.find({ user: req.user._id }).sort(
      { createdAt: -1 }
    ); // newest first

    res.json(notifications);
  } catch (err) {
    console.error("Error fetching notifications:", err);
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/get", async (req, res) => {
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

  console.log(u);

  return res.json(u);
});

// Configure Multer storage
const storage1 = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, "../files/profile");
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const uniqueName = `avatar_${Date.now()}${ext}`;
    cb(null, uniqueName);
  },
});

// ✅ Correct: use storage: storage1
const upload1 = multer({ storage: storage1 });

router.post("/updateProfile", upload1.single("avatar"), async (req, res) => {
  try {
    const email = req.user.email;

    // Find user
    const u = await User.findOne({ email: email });
    if (!u) {
      return res.status(401).json({ error: "User Not Found" });
    }

    // If file uploaded, update avatarUrl
    if (req.file) {
      // Delete old avatar file if exists
      if (u.avatarUrl) {
        const oldPath = path.join(__dirname, "..", u.avatarUrl);
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath);
        }
      }

      // Set new avatar path
      const relativePath = `/profile/${req.file.filename}`;
      u.avatarUrl = relativePath;
      await u.save();
    }

    return res.json(u);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Update First Name
router.post("/firstName", async (req, res) => {
  try {
    const { firstname } = req.body;
    console.log("a");
    if (!firstname)
      return res.status(400).json({ error: "firstName is required" });
    console.log("b");
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(401).json({ error: "User not found" });

    user.firstName = firstname;
    await user.save();

    return res.json(user);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Update Last Name
router.post("/lastName", async (req, res) => {
  try {
    const { lastname } = req.body;
    if (!lastname)
      return res.status(400).json({ error: "lastName is required" });

    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(401).json({ error: "User not found" });

    user.lastName = lastname;
    await user.save();

    return res.json(user);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Update Username
router.post("/username", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username)
      return res.status(400).json({ error: "username is required" });

    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(401).json({ error: "User not found" });

    // Optional: check if username already exists
    const existing = await User.findOne({ username });
    if (existing && existing._id.toString() !== user._id.toString()) {
      return res.status(400).json({ error: "Username already taken" });
    }

    user.username = username;
    await user.save();

    return res.json(user);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Update Email
router.post("/email", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "email is required" });

    const user = await User.findOne({ email: email });
    if (user) return res.status(401).json({ error: "Email already exists" });

    user.email = email;
    await user.save();

    return res.json(user);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Update Password
router.post("/password", async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword)
      return res
        .status(400)
        .json({ error: "Both oldPassword and newPassword are required" });

    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(401).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(oldPassword, user.passwordHash);
    if (!isMatch)
      return res.status(400).json({ error: "Old password is incorrect" });

    const hashed = await bcrypt.hash(newPassword, 10);
    user.passwordHash = hashed;
    await user.save();

    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Delete Account
router.post("/deleteAccount", async (req, res) => {
  try {
    const { id } = req.params;

    // Update nested arrays
    const surveys = await Survey.find({});
    await Promise.all(
      surveys.map((s) => {
        s.responses = s.responses?.filter((r) => r.user.toString() !== id);
        return s.save();
      })
    );

    const groups = await Group.find({});
    await Promise.all(
      groups.map((g) => {
        g.members = g.members?.filter((r) => r.toString() !== id);
        g.joinRequests = g.joinRequests?.filter((r) => r.toString() !== id);
        return g.save();
      })
    );

    const videos = await Video.find({});
    await Promise.all(
      videos.map((v) => {
        v.likes = v.likes?.filter((r) => r.toString() !== id);
        return v.save();
      })
    );

    const user = await User.findById(req.user._id);

    if (user.avatarUrl) {
      const oldPath = path.join(__dirname, "..", user.avatarUrl);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    // Delete related docs
    await Promise.all([
      Survey.deleteMany({ createdBy: id }),
      Notifications.deleteMany({ user: id }),
      Newsletter.deleteMany({ author: id }),
      Message.deleteMany({ sender: id }),
      Log.deleteMany({ user: id }),
      Group.deleteMany({ createdBy: id }),
      Goal.deleteMany({ user: id }),
      Event.deleteMany({ author: id }),
      Nutrition.deleteMany({ user: id }),
      Competition.deleteMany({ author: id }),
      Chat.deleteMany({ participants: { $in: [id] } }),
      Video.deleteMany({ uploader: id }),
    ]);

    await User.findByIdAndDelete(id);

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

router.get("/users", async (req, res) => {
  try {
    const query = req.query.query?.trim() || "";

    if (!query) {
      return res.json([]); // empty search returns empty list
    }

    // Search by firstName, lastName, username, or email but exclude logged-in user
    const users = await User.find({
      _id: { $ne: req.user._id }, // exclude current user
      $or: [
        { firstName: { $regex: query, $options: "i" } },
        { lastName: { $regex: query, $options: "i" } },
        { username: { $regex: query, $options: "i" } },
        { email: { $regex: query, $options: "i" } },
      ],
    })
      .select("_id firstName lastName username email") // return only safe fields
      .limit(20);

    return res.json(users);
  } catch (err) {
    console.error("Error searching users:", err);
    return res.status(500).json({ error: "Server Error" });
  }
});

router.get("/users/search", async (req, res) => {
  try {
    const query = req.query.q?.trim() || "";

    if (!query) {
      return res.json([]); // empty search returns empty list
    }

    // Search by firstName, lastName, username, or email but exclude logged-in user
    const users = await User.find({
      _id: { $ne: req.user._id }, // exclude current user
      $or: [
        { firstName: { $regex: query, $options: "i" } },
        { lastName: { $regex: query, $options: "i" } },
        { username: { $regex: query, $options: "i" } },
        { email: { $regex: query, $options: "i" } },
      ],
    })
      .select("_id firstName lastName username email")
      .limit(20);

    // For each user, find a chat that includes both req.user._id and user._id
    const usersWithChatId = await Promise.all(
      users.map(async (user) => {
        const chat = await Chat.findOne({
          participants: { $all: [req.user._id, user._id] },
        }).select("_id");

        return {
          ...user.toObject(),
          chatId: chat?._id || null, // add chatId field, null if no chat exists
        };
      })
    );

    return res.json(usersWithChatId);
  } catch (err) {
    console.error("Error searching users:", err);
    return res.status(500).json({ error: "Server Error" });
  }
});

/** NEWSLETTERS (read/list, like, comment, save) */
router.get("/newsletters", async (_req, res) => {
  const list = await Newsletter.find({ status: "published" })
    .sort({ createdAt: -1 })
    .populate("author")
    .select("-password");
  console.log(list);
  res.json(list);
});

router.get("/newsletters/:id", async (req, res) => {
  console.log(req.params);
  const list = await Newsletter.findOne({
    _id: req.params.id,
    status: "published",
  }).sort({ createdAt: -1 });
  res.json(list);
});

router.post("/newsletters/:id/like", async (req, res) => {
  const nl = await Newsletter.findById(req.params.id);
  if (!nl) return res.status(404).json({ error: "Not found" });
  const idx = nl.likes.findIndex(
    (u) => u.toString() === req.user._id.toString()
  );
  if (idx >= 0) nl.likes.splice(idx, 1);
  else nl.likes.push(req.user._id);
  await nl.save();
  res.json({ likes: nl.likes.length });
});

router.post("/newsletters/:id/comments", async (req, res) => {
  const { content, parent } = req.body;
  if (!content) return res.status(400).json({ error: "Missing content" });
  const nl = await Newsletter.findById(req.params.id);
  if (!nl) return res.status(404).json({ error: "Not found" });
  nl.comments.push({ author: req.user._id, content, parent: parent || null });
  await nl.save();
  res.status(201).json(nl.comments[nl.comments.length - 1]);
});

router.post("/newsletters/:id/save", async (req, res) => {
  const nl = await Newsletter.findById(req.params.id);
  if (!nl) return res.status(404).json({ error: "Not found" });
  const idx = nl.savedBy.findIndex(
    (u) => u.toString() === req.user._id.toString()
  );
  if (idx >= 0) nl.savedBy.splice(idx, 1);
  else nl.savedBy.push(req.user._id);
  await nl.save();
  res.json({ saved: idx < 0 });
});

/** VIDEOS (grid feed, post by users to Students tab; admin-only for other tabs) */
router.get("/videos", async (req, res) => {
  const { category } = req.query;
  const filter = { status: "published" };
  if (category) filter.category = category;
  const vids = await Video.find(filter)
    .sort({ createdAt: -1 })
    .populate("uploader");
  res.json(vids);
});

router.get("/videos/liked/get", async (req, res) => {
  try {
    const v = await Video.find({ likes: req.user._id })
      .sort({ createdAt: -1 })
      .distinct("_id"); // only return distinct IDs

    if (!v || v.length === 0) {
      return res.status(404).json({ error: "Not found" });
    }

    res.json(v.map((id) => id.toString())); // return as array of strings
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/videos/:id", async (req, res) => {
  const { category } = req.query;
  const filter = { status: "published", _id: req.params.id };
  if (category) filter.category = category;
  const vids = await Video.findOne(filter)
    .sort({ createdAt: -1 })
    .populate("uploader");
  res.json(vids);
});

// configure multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "../files/videos")); // make sure this folder exists
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

router.post(
  "/videos",
  upload.fields([
    { name: "url", maxCount: 1 }, // video file
    { name: "thumbnailUrl", maxCount: 1 }, // thumbnail file
  ]),
  async (req, res) => {
    try {
      const { title, caption, category, durationSec, type } = req.body;

      if (!title || !caption || !req.files?.url) {
        return res.status(400).json({ error: "Missing fields" });
      }

      // Enforce category rules
      const isStudents =
        category === "BeFAB NCCU" || category === "Mentor Meetup";
      if (isStudents && req.user.role !== "admin") {
        // console.log(isStudents, category)
        return res
          .status(403)
          .json({ error: "Only admins can post to this category" });
      }

      const videoFile = req.files.url[0];

      const videoPath = `/videos/${videoFile.filename}`;
      const thumbnailPath = req.files.thumbnailUrl
        ? `/videos/${req.files.thumbnailUrl[0].filename}`
        : null;

      const v = await Video.create({
        uploader: req.user._id,
        title,
        caption,
        category,
        url: videoPath,
        thumbnailUrl: thumbnailPath,
        durationSec,
        type,
        status: "published",
      });

      res.status(201).json(v);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

router.post("/videos/:id/like", async (req, res) => {
  try {
    const v = await Video.findById(req.params.id);
    if (!v) return res.status(404).json({ error: "Not found" });

    const userId = req.user._id;
    let update;

    if (v.likes.includes(userId)) {
      // If already liked → remove
      update = { $pull: { likes: userId } };
    } else {
      // If not liked → add
      update = { $addToSet: { likes: userId } };
    }

    const updated = await Video.findByIdAndUpdate(
      req.params.id,
      update,
      { new: true, select: "likes" } // return only likes array
    );

    res.json({ likes: updated.likes.length });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/videos/:id/comments", async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "Missing content" });
  const v = await Video.findById(req.params.id);
  if (!v) return res.status(404).json({ error: "Not found" });
  v.comments.push({ author: req.user._id, content });
  await v.save();
  res.status(201).json(v.comments[v.comments.length - 1]);
});

/** GROUPS (join, leave, request to join if private; posts/threads & comments) */
router.get("/groups", async (req, res) => {
  try {
    const groups = await Group.find().select(
      "name description imageUrl bannerUrl visibility members joinRequests"
    );

    const userId = req.user?._id?.toString(); // ensure string for comparison

    const formatted = groups.map((group) => {
      let state = "JOIN"; // default

      if (userId) {
        if (group.members.some((m) => m.toString() === userId)) {
          state = "LEAVE";
        } else if (group.joinRequests?.some((r) => r.toString() === userId)) {
          state = "REQUESTED";
        }
      }

      return {
        ...group.toObject(),
        state,
      };
    });

    res.json(formatted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/groups/:id", async (req, res) => {
  try {
    const group = await Group.findOne({ _id: req.params.id }).select(
      "name description imageUrl bannerUrl visibility members joinRequests posts"
    );

    if (!group) {
      return res.status(404).json({ error: "Group not found" });
    }

    const userId = req.user?._id?.toString(); // ensure string for comparison

    let state = "JOIN"; // default

    if (userId) {
      if (group.members.some((m) => m.toString() === userId)) {
        state = "LEAVE";
      } else if (group.joinRequests?.some((r) => r.toString() === userId)) {
        state = "REQUESTED";
      }
    }

    // create final response object
    const formatted = {
      ...group.toObject(),
      state,
    };

    res.json(formatted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/groups/:id/join", async (req, res) => {
  const g = await Group.findById(req.params.id);
  if (!g) return res.status(404).json({ error: "Not found" });

  const alreadyMember = g.members.some(
    (m) => m.toString() === req.user._id.toString()
  );
  if (alreadyMember) return res.json({ joined: true });

  if (g.visibility === "private") {
    if (!g.joinRequests.some((r) => r.toString() === req.user._id.toString()))
      g.joinRequests.push(req.user._id);
    await g.save();
    return res.json({ requested: true }); // admin must approve per spec :contentReference[oaicite:28]{index=28}
  } else {
    g.members.push(req.user._id);
    await g.save();
    return res.json({ joined: true });
  }
});

router.post("/groups/:id/leave", async (req, res) => {
  try {
    const g = await Group.findById(req.params.id);
    if (!g) return res.status(404).json({ error: "Not found" });

    const userId = req.user._id.toString();

    // remove from members
    g.members = g.members.filter((m) => m.toString() !== userId);

    // remove from joinRequests if present
    if (g.joinRequests && g.joinRequests.length > 0) {
      g.joinRequests = g.joinRequests.filter((r) => r.toString() !== userId);
    }

    await g.save();

    res.json({ joined: false, requested: false });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/groups/:id/posts", async (req, res) => {
  const { content, images } = req.body;
  const g = await Group.findById(req.params.id);
  if (!g) return res.status(404).json({ error: "Not found" });
  const isMember = g.members.some(
    (m) => m.toString() === req.user._id.toString()
  );
  if (!isMember) return res.status(403).json({ error: "Join the group first" });
  g.posts.push({ author: req.user._id, content, images });
  await g.save();
  res.status(201).json(g.posts[g.posts.length - 1]);
});

/** COMPETITIONS (list, join/leave, my progress, leaderboard) */
router.get("/competitions", async (req, res) => {
  try {
    const now = new Date();
    const competitions = await Competition.find({
      end: { $gte: new Date(now.getFullYear() - 1, 0, 1) },
      status: { $nin: ["draft", "completed", "paused"] },
    }).populate("participants.user");

    // Load user health JSON file
    const dataPath = path.join(__dirname, `../${req.user._id}.json`);
    let healthData = {};
    if (fs.existsSync(dataPath)) {
      healthData = JSON.parse(fs.readFileSync(dataPath, "utf8"));
    }

    // Nutrition DB data
    const nutritionData = await DayNutrition.find({ user: req.user._id });

    const list = [];

    for (let comp of competitions) {
      const joined = comp.participants.some(
        (p) => p.user._id.toString() === req.user._id.toString()
      );

      if (joined) {
        const participant = comp.participants.find(
          (p) => p.user._id.toString() === req.user._id.toString()
        );

        let score = 0;
        let progress = 0;

        switch (comp.category) {
          case "Fitness":
            const steps = (healthData["HealthDataType.STEPS"] || []).reduce(
              (a, b) => a + (b.value?.numericValue || 0),
              0
            );
            const distance = (
              healthData["HealthDataType.DISTANCE_DELTA"] || []
            ).reduce((a, b) => a + (b.value?.numericValue || 0), 0);
            score = steps + distance; // simple scoring
            progress = steps; // could normalize based on goal
            break;

          case "Nutrition":
            let water = nutritionData.reduce(
              (a, b) => a + (b.waterIntake_oz || 0),
              0
            );
            let calories = nutritionData.reduce((a, b) => {
              return (
                a +
                Object.values(b.meals || {})
                  .flat()
                  .reduce((sum, item) => sum + (item.calories || 0), 0)
              );
            }, 0);
            score = water + calories / 10;
            progress = water;
            break;

          case "Wellness":
            const sleep = (
              healthData["HealthDataType.SLEEP_ASLEEP"] || []
            ).reduce((a, b) => a + (b.value?.numericValue || 0), 0);
            const hr =
              (healthData["HealthDataType.HEART_RATE"] || [])[0]?.value
                ?.numericValue || 0;
            score = sleep + (70 - Math.abs(70 - hr)); // closer HR to 70 = better
            progress = sleep;
            break;

          case "Strength":
            // Example placeholder: use weight data
            const weight =
              (healthData["HealthDataType.WEIGHT"] || []).slice(-1)[0]?.value
                ?.numericValue || 0;
            score = weight * 2;
            progress = weight;
            break;

          case "Cardio":
            const runDist = (
              healthData["HealthDataType.DISTANCE_DELTA"] || []
            ).reduce((a, b) => a + (b.value?.numericValue || 0), 0);
            score = runDist;
            progress = runDist;
            break;

          case "Team":
            // Example: group steps total
            const teamSteps = comp.participants.reduce(
              (acc, p) => acc + (p.score || 0),
              0
            );
            score = teamSteps;
            progress = teamSteps;
            break;
        }

        participant.score = score;
        participant.progress = progress;
        participant.lastUpdated = new Date();
        await comp.save();

        // Update leaderboard (sort by score)
        comp.leaderboard = comp.participants
          .map((p) => ({ user: p.user._id, score: p.score }))
          .sort((a, b) => b.score - a.score)
          .map((p, i) => ({ ...p, rank: i + 1 }));
        await comp.save();
      }

      list.push({ ...comp.toObject(), joined });
    }
    res.json({ list });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/competitions/get", async (req, res) => {
  try {
    const now = new Date();

    const competitions = await Competition.find({
      end: { $gte: new Date(now.getFullYear() - 1, 0, 1) },
    }).populate("participants.user");

    const getUserId = (p) =>
      typeof p.user === "object" && p.user._id
        ? p.user._id.toString()
        : p.user.toString();

    const list = competitions.map((comp) => {
      const joined = comp.participants.some(
        (p) => getUserId(p) === req.user._id.toString()
      );
      return { ...comp.toObject(), joined };
    });

    // --- user-specific stats ---
    let totalWins = 0;
    let totalProgressPct = 0; // relative %
    let progressCount = 0;
    let rankSum = 0;
    let rankCount = 0;

    for (const comp of competitions) {
      const participant = comp.participants.find(
        (p) => getUserId(p) === req.user._id.toString()
      );

      if (participant) {
        // Sort leaderboard by score
        const sorted = [...comp.participants].sort(
          (a, b) => (b.score || 0) - (a.score || 0)
        );

        const rank =
          sorted.findIndex((p) => getUserId(p) === req.user._id.toString()) + 1;

        // ✅ Win = rank 1 when competition completed
        if (comp.status === "completed" && rank === 1) {
          totalWins++;
        }

        // ✅ For active competitions, normalize progress against leader
        if (
          !["draft", "upcoming", "completed", "paused"].includes(comp.status)
        ) {
          const leader = sorted[0];
          const leaderProgress = leader?.progress || 1; // avoid div/0
          const pct = ((participant.progress || 0) / leaderProgress) * 100;
          totalProgressPct += Math.min(pct, 100);
          progressCount++;
        }

        rankSum += rank;
        rankCount++;
      }
    }

    const avgProgress =
      progressCount > 0 ? totalProgressPct / progressCount : 0;
    const avgRank = rankCount > 0 ? rankSum / rankCount : null;

    res.json({
      competitions: list,
      stats: {
        totalWins,
        avgProgress, // % compared to leader
        avgRank,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/competitions/:id/join", async (req, res) => {
  const c = await Competition.findById(req.params.id);
  if (!c) return res.status(404).json({ error: "Not found" });
  const exists = c.participants.find(
    (p) => p.user.toString() === req.user._id.toString()
  );
  if (exists) return res.json({ joined: true });
  c.participants.push({ user: req.user._id, progress: 0, score: 0 });
  await c.save();
  res.json({ joined: true });
});

router.get("/competitions/:id/leaderboard", async (req, res) => {
  const c = await Competition.findById(req.params.id).populate(
    "leaderboard.user",
    "username"
  );
  if (!c) return res.status(404).json({ error: "Not found" });
  res.json(c.leaderboard);
});

router.post("/data", async (req, res) => {
  const filePath = path.join(__dirname, `../${req.user._id}.json`);
  const incomingData = req.body;

  if (!incomingData) {
    return res.status(400).json({ message: "No data provided" });
  }

  // Convert JSON to string
  const dataToWrite = JSON.stringify(incomingData) + "\n";

  // Append to txt file
  fs.writeFileSync(filePath, dataToWrite, (err) => {
    if (err) {
      console.error("❌ Error writing file:", err);
      return res.status(500).json({ message: "Error saving data" });
    }

    console.log("✅ Data saved:", incomingData);
    res.status(200).json({ message: "Data saved successfully" });
  });
});

/** GOALS (create, list, update progress) */
router.get("/goals", async (req, res) => {
  try {
    // 1. Load or create data.json
    const dataPath = path.join(__dirname, `../${req.user._id}.json`);
    if (!fs.existsSync(dataPath)) {
      fs.writeFileSync(dataPath, JSON.stringify({}, null, 2), "utf-8");
    }
    const healthData = JSON.parse(fs.readFileSync(dataPath, "utf-8"));

    // 2. Get all user goals
    const goals = await Goal.find({ user: req.user._id }).sort({
      createdAt: -1,
    });

    // 3. Get today's nutrition document
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const nutrition = await DayNutrition.findOne({
      user: req.user._id,
      date: { $gte: today, $lt: new Date(today.getTime() + 86400000) },
    });

    // 4. Helper: sum healthData
    const sumHealth = (key) =>
      (healthData[key] || []).reduce(
        (acc, entry) => acc + (entry.value?.numericValue || 0),
        0
      );

    // 5. Prepare nutrition totals
    let waterTotal = 0;
    let caloriesTakenTotal = 0;

    if (nutrition) {
      waterTotal = nutrition.waterIntake_oz || 0;

      const allMeals = [
        ...nutrition.meals.breakfast,
        ...nutrition.meals.lunch,
        ...nutrition.meals.dinner,
        ...nutrition.meals.snacks,
        ...nutrition.meals.other,
      ];

      caloriesTakenTotal = allMeals.reduce((acc, meal) => {
        const qty = meal.quantity || 1;
        return acc + (meal.calories || 0) * qty;
      }, 0);
    }

    // 6. Map over goals and update progress
    const updatedGoals = goals.map((goal) => {
      let progress = 0;

      switch (goal.category) {
        case "Steps":
          progress = sumHealth("HealthDataType.STEPS");
          break;
        case "Distance":
          progress = sumHealth("HealthDataType.DISTANCE_DELTA");
          break;
        case "Calories Burned":
          progress = sumHealth("HealthDataType.TOTAL_CALORIES_BURNED");
          break;
        case "Calories Taken":
          progress = caloriesTakenTotal;
          break;
        case "Water Intake":
          progress = waterTotal;
          break;
      }

      const percent = Math.min(100, (progress / goal.milestones) * 100);

      return {
        ...goal.toObject(),
        progressValue: progress,
        progressPercent: percent,
      };
    });

    // 7. Send updated list
    res.status(200).json(updatedGoals);
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
    const { name, durationDays, milestones, category } = req.body;
    if (!name || !durationDays || !milestones || !category) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Get last goal for this user (latest createdAt)
    const lastGoal = await Goal.findOne({
      user: req.user._id,
      category: category,
      status: { $in: ["expiired", "completed"] },
    }).sort({ createdAt: -1 });

    if (lastGoal)
      return res.status(400).json({ error: "An uncompleted goal exist" });

    const goal = await Goal.create({
      user: req.user._id,
      name,
      category,
      durationDays,
      milestones,
    });

    res.status(201).json(goal);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.patch("/goals/:id/progress", async (req, res) => {
  const { progressValue, progressPercent, status } = req.body;
  const g = await Goal.findOneAndUpdate(
    { _id: req.params.id, user: req.user._id },
    { progressValue, progressPercent, status },
    { new: true }
  );
  if (!g) return res.status(404).json({ error: "Not found" });
  res.json(g);
});

/** NUTRITION (meal logging, hydration tracker) */
router.get("/nutrition/:date", async (req, res) => {
  console.log(req.params.date);
  const date = new Date(req.params.date);
  const doc = await DayNutrition.findOne({ user: req.user._id, date });
  res.json(
    doc || {
      user: req.user._id,
      date,
      meals: { breakfast: [], lunch: [], dinner: [], snacks: [], other: [] },
      waterIntake_oz: 0,
    }
  );
});

router.get("/nutrition/get/foods", async (req, res) => {
  const doc = await Food.find({});
  res.json(doc);
});

router.post("/nutrition/:date/meal", async (req, res) => {
  try {
    const { bucket, item } = req.body;

    if (
      !["breakfast", "lunch", "dinner", "snacks", "other"].includes(
        bucket.toLowerCase()
      )
    ) {
      return res.status(400).json({ error: "Invalid bucket" });
    }

    const date = new Date(req.params.date);

    // ✅ Ensure quantity exists, default = 1
    item.quantity = item.quantity && item.quantity > 0 ? item.quantity : 1;

    // ✅ Ensure name exists
    if (!item.name || item.name.trim() === "") {
      return res.status(400).json({ error: "Food item must have a name" });
    }

    let doc = await DayNutrition.findOne({ user: req.user._id, date });
    if (!doc) {
      doc = new DayNutrition({
        user: req.user._id,
        date,
        meals: { [bucket]: [] },
      });
    }

    // ✅ Check if food already exists in the bucket (match by name + calories)
    const existing = doc.meals[bucket].find(
      (m) => m.name === item.name && m.calories === item.calories
    );

    if (existing) {
      console.log(bucket, item, existing);
      existing.quantity += item.quantity || 1;
      await doc.save();
    } else {
      doc.meals[bucket].push(item);
      await doc.save();
    }

    res.status(201).json(doc);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/nutrition/:date/hydration", async (req, res) => {
  const { water } = req.body; // positive or negative oz
  const date = new Date(req.params.date);
  const doc = await DayNutrition.findOneAndUpdate(
    { user: req.user._id, date },
    { $inc: { waterIntake_oz: water } },
    { upsert: true, new: true }
  );
  res.json({ waterIntake_oz: doc.waterIntake_oz });
});

/** Events (summary/vitals/workouts; manual add) */
router.get("/events", async (_req, res) => {
  const comps = await Event.find()
    .sort({ createdAt: -1 })
    .populate("author")
    .select("-passwordHash");
  res.json(comps);
});

/** FITNESS (summary/vitals/workouts; manual add) */
router.get("/fitness/:date", async (req, res) => {
  const date = new Date(req.params.date);
  const f = await Fitness.findOne({ user: req.user._id, date });
  res.json(f || null);
});

router.post("/fitness/:date/workouts", async (req, res) => {
  const date = new Date(req.params.date);
  const { type, duration_min, distance_mi, calories_kcal, notes } = req.body;
  const f = await Fitness.findOneAndUpdate(
    { user: req.user._id, date },
    {
      $push: {
        workouts: { type, duration_min, distance_mi, calories_kcal, notes },
      },
    },
    { upsert: true, new: true }
  );
  res.status(201).json(f);
});

/** MESSAGES (chats with text/image/video) */
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

/** SURVEYS (list & respond; tabs: required/optional/past are client filters) */
router.get("/surveys", async (req, res) => {
  try {
    const Survey = require("../models/Survey");
    const userId = req.user._id;

    const startOfToday = new Date();
    startOfToday.setHours(0, 0, 0, 0);

    const list = await Survey.find({
      "responses.user": { $ne: userId },
      exclude: { $ne: req.user.username }, // exclude if username is in exclude array
      $or: [
        { dueDate: { $gte: startOfToday } }, // today or later
        { dueDate: null }, // explicitly null
        { dueDate: { $exists: false } }, // missing
      ],
    })
      .select("-responses")
      .sort({ createdAt: -1 });

    res.json(list);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});
// router.get("/surveys", async (req, res) => {
//   try {
//     const Survey = require("../models/Survey");
//     const userId = req.user._id;

//     const list = await Survey.find({
//       // ✅ exclude surveys where responses.user contains this user
//       "responses.user": { $ne: userId },
//     })
//       .select("-responses")
//       .sort({ createdAt: -1 });

//     res.json(list);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

router.get("/surveys/:id", async (req, res) => {
  try {
    const Survey = require("../models/Survey");
    const userId = req.user._id;

    const survey = await Survey.findOne({
      _id: req.params.id,
      // ✅ exclude if user already responded
      responses: { $not: { $elemMatch: { user: userId } } },
    })
      .select("-responses")
      .sort({ createdAt: -1 });

    if (!survey) {
      return res
        .status(404)
        .json({ error: "Survey not found or already submitted" });
    }

    res.json(survey);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
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

module.exports = router;
