require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const http = require("http");
const fs = require("fs");
const { Server } = require("socket.io");

const appRoutes = require("./routes/app");
const adminRoutes = require("./routes/admin");
const authRoutes = require("./routes/authenticate");
const User = require("./models/User");
const { Chat, Message } = require("./models/Message"); // import your schemas
const Notifications = require("./models/Notifications");

const app = express();
const server = http.createServer(app); // wrap express with http server
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

// Middleware
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/", express.static(path.join(__dirname, "files/")));

// Health check
app.get("/health", (_req, res) => res.json({ ok: true }));

// Routes
app.use("/auth", authRoutes);
app.use("/app", appRoutes);
app.use("/admin", adminRoutes);

let interval = null;

app.post("/ping", async (req, res) => {
  try {
    const { userId } = req.body;
    const now = Date.now();

    const user = await User.findByIdAndUpdate(
      userId,
      { lastPing: now, isActive: true },
      { new: true }
    );

    if (!user) return res.status(404).json({ message: "User not found" });

    if (!interval) {
      interval = setInterval(async () => {
        try {
          await User.updateMany(
            { isActive: true, lastPing: { $lt: Date.now() - 5000 } },
            { $set: { isActive: false } }
          );
        } catch (err) {
          console.error("Error updating user activity:", err);
        }
      }, 5000);
    }

    res.json({ message: "pong", userId, active: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// POST /data endpoint

// ----------------- SOCKET.IO -----------------
io.on("connection", (socket) => {
  console.log("🔌 User connected:", socket.id);

  // Join chat room
  socket.on("joinChat", (chatId) => {
    socket.join(chatId);
    console.log(`User ${socket.id} joined chat ${chatId}`);
  });

  // Handle sending message
  socket.on(
    "sendMessage",
    async ({ chatId, senderId, content, mediaUrl, mediaType }) => {
      try {
        const msg = await Message.create({
          chatId,
          sender: senderId,
          content,
          mediaUrl,
          mediaType: mediaType || "none",
        });

        await Chat.findByIdAndUpdate(chatId, { lastMessageAt: new Date() });

        const user = await User.findById(senderId);

        if (!user?.isActive) {
          const chat = await Chat.findById(chatId);
          if (!chat) return;

          // find the other participant (not the sender)
          const otherId = chat.participants.find(
            (p) => p.toString() !== senderId.toString()
          );
          if (!otherId) return;

          const other = await User.findById(otherId);
          if (!other) return;

          await Notifications.create({
            user: senderId, // notify the other participant
            content: `${other.username} messaged you`, // sender’s username
          });
        }

        // emit to all participants in the chat room
        io.to(chatId).emit("newMessage", msg);
      } catch (err) {
        console.error("Error saving message:", err);
        socket.emit("errorMessage", { error: "Failed to send message" });
      }
    }
  );

  socket.on("disconnect", () => {
    console.log("❌ User disconnected:", socket.id);
  });
});
// ---------------------------------------------

// DB + Server
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/befab";

mongoose
  .connect(MONGO_URI, { autoIndex: true })
  .then(() => {
    console.log("MongoDB connected");
    server.listen(PORT, () =>
      console.log(`Server running on http://localhost:${PORT}`)
    );
  })
  .catch((err) => {
    console.error("Mongo connection error:", err);
    process.exit(1);
  });
