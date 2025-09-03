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
const user = require("../models/User.js");
const Log = require("../models/logs.js");
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

const uploadDir = path.resolve(__dirname, process.env.PROFILE_STORAGE);

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + file.originalname;
    cb(null, uniqueName);
  },
});
const upload = multer({ storage });

app.post("/signup", async (req, res) => {
  console.log(req.body);
  const { firstName, lastName, username, email, password, code, userId } = req.body;
  const tfa = req.body.tfa;

  // Collect missing required fields
  const missingFields = [];

  if (!firstName) missingFields.push("firstName");
  if (!lastName) missingFields.push("lastName");
  if (!username) missingFields.push("userName");
  if (!email) missingFields.push("emailAddress");
  if (!password) missingFields.push("password");
  if (!userId) missingFields.push("userId");

  if (missingFields.length > 0) {
    return res.status(400).send("Missing required fields");
  }

  // Check if user with verified OTP exists
  const tfaUser = await user.findOne({
    otp: code,
  });

  if (!tfaUser) {
    return res.status(403).send("Invalid OTP");
  }

  if (!tfaUser.otpExpiresAt || tfaUser.otpExpiresAt < new Date()) {
    return res.status(403).send("OTP Expired"); // Expired
  }

  const nameUser = await user.findOne({
    userName: username.toLowerCase()+'@befab',
  });

  const nameUser1 = await user.findOne({
    userId: userId,
  });

  if (nameUser) {
    return res.status(403).send("Username or Email Already Exists");
  }

  if (nameUser1) {
    return res.status(403).send("userId Already Exists");
  }

  tfaUser.firstName = firstName;
  tfaUser.lastName = lastName;
  tfaUser.username = username.toLowerCase()+'@befab';
  tfaUser.userId = userId;
  tfaUser.email = email;
  tfaUser.otp = null;
  tfaUser.otpExpiresAt = null;
  tfaUser.passwordHash = await bcrypt.hash(password, 10); // (Ideally hash this before saving)
  // Save the updated user
  const d = await tfaUser.save();
  fs.writeFileSync(path.join(__dirname, `../${d._id}.json`), JSON.stringify({}));

  return res.status(200).json({ message: "Account Created" });
});

// const configureSamlStrategy = require("./strategy");

app.get("/sign-up/sso/authenticate", (req, res, next) => {
  const university = req.query.university;
  if (!university)
    return res.status(400).json({ error: "University is required" });

  try {
    const samlStrategy = configureSamlStrategy(university);
    passport.use(`saml-${university}`, samlStrategy);

    // Trigger SAML Auth flow
    passport.authenticate(`saml-${university}`)(req, res, next);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Invalid University or SAML Config" });
  }
});

app.post("/sso/callback/:university", (req, res, next) => {
  const university = req.params.university?.toLowerCase();
  try {
    const samlStrategy = configureSamlStrategy(university);
    passport.use(`saml-${university}`, samlStrategy);

    passport.authenticate(`saml-${university}`, { failureRedirect: "/login" })(
      req,
      res,
      () => {
        // ✅ Success - user is authenticated via university
        console.log("User authenticated:", req.user);
        res.redirect("/dashboard"); // or send JSON or token
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).send("SSO Callback Error");
  }
});

app.post("/verify", async (req, res) => {
  try {
    const { data, code } = req.body;

    if (!data || !code) {
      return res.status(400).json({ error: "Invalid Email OR Phone" });
    }

    const validation = validateInput(data);
    if (!validation.valid) {
      return res.status(400).json({ error: "Invalid email or phone number" });
    }

    // Search by correct field
    const query =
      validation.type === "email" ? { email: data } : { phone: data };
    const user = await users.findOne(query);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // ✅ Check if OTP expired first
    if (user.otpExpiresAt && user.otpExpiresAt < new Date()) {
      return res.status(410).json({ error: "OTP expired" });
    }

    // ✅ Now check if OTP code matches
    if (user.otp !== code) {
      return res.status(401).json({ error: "Incorrect OTP" });
    }

    // ✅ OTP is valid, clear OTP fields
    user.otp = null;
    user.otpExpiresAt = null;
    user.tfa = validation.type === "email" ? "email" : "phone";
    await user.save();

    await createSystemLog(
      user._id,
      "Logged-in",
      `${user.firstName} Logged-in as Member`
    );

    res.status(200).json({
      data:
        validation.type === "email"
          ? "Email Verified"
          : "Phone Number Verified",
    });
  } catch (err) {
    console.error("OTP verification failed:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

const createSystemLog = async (
  idOrUser,
  eventType,
  description,
  retentionDays = 365,
  autoDelete = false
) => {
  try {
    let users;

    // Case 1: Full user object passed
    if (idOrUser && idOrUser._id && idOrUser.email) {
      users = idOrUser;
    } else {
      // Case 2: ID passed as string, Buffer, or ObjectId
      let objectId;

      if (
        typeof idOrUser === "string" &&
        mongoose.Types.ObjectId.isValid(idOrUser)
      ) {
        objectId = new mongoose.Types.ObjectId(idOrUser);
      } else if (Buffer.isBuffer(idOrUser)) {
        objectId = new mongoose.Types.ObjectId(idOrUser.toString("hex"));
      } else if (idOrUser instanceof mongoose.Types.ObjectId) {
        objectId = idOrUser;
      } else {
        throw new Error("Invalid user identifier passed to createSystemLog");
      }

      u = await user.findOne({ _id: objectId });
      if (!u) {
        console.warn("User not found for system log");
        return;
      }
    }

    const log = new Log({
      user: u._id,
      email: u.email,
      eventType,
      description,
      retentionDays,
      autoDelete,
      lastCleanup: null,
    });

    await log.save();
    console.log(`✅ Log created for ${u.email} - ${eventType}`);
  } catch (error) {
    console.error("❌ Failed to create system log:", error);
  }
};

app.post("/contact", async (req, res) => {
  try {
    const { data } = req.body;

    const mailOptions = {
      from: process.env.EMAIL,
      to: process.env.EMAIL,
      subject: "New Form",
      text: `Message is:\n${JSON.stringify(data, null, 2)}`, // pretty-printed JSON
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending email:", error);
      } else {
        console.log("Email sent:", info.response);
      }
    });

    res.status(200).json({
      data: "Submitted Successfully",
    });
  } catch (err) {
    console.error("OTP verification failed:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/forgot-password", async (req, res) => {
  try {
    const input = req.body.email;

    const validation = validateInput(input);
    if (!validation.valid) {
      return res.status(400).send("Invalid Email");
    }

    const isPhone = validation.type === "phone";
    const otp = await generateUniqueOtp();
    const query = { email: input };
    let existingUser = await user.findOne(query);

    if (existingUser) {
      // Update OTP and expiry
      existingUser.otp = otp;
      existingUser.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
      await existingUser.save();

      const sent = await email(
        otp,
        existingUser.email,
        `${process.env.URL}/reset-password?otp=${encodeURIComponent(otp)}`
      );

      if (sent) {
        return res.status(200).json({ message: "Verification Code Sent" });
      } else {
        throw Error(`Error Sending Email`);
      }
    }
    else{
      res.status(500).send("User not found");
    }
  } catch (err) {
    console.error("OTP verification failed:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/verify-forgot-password", async (req, res) => {
  try {
    const input = req.body.email;

    const validation = validateInput(input);
    if (!validation.valid) {
      return res.status(400).send("Invalid Email");
    }

    const query = { email: input };
    let existingUser = await user.findOne(query);

    if (existingUser) {
      // Update OTP and expiry
      existingUser.otp = otp;
      existingUser.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
      await existingUser.save();

      const sent = await email(
        otp,
        existingUser.email,
        `${process.env.URL}/reset-password?otp=${encodeURIComponent(otp)}`
      );

      if (sent) {
        return res.status(200).json({ message: "Verification Code Sent" });
      } else {
        throw Error(`Error Sending Email`);
      }
    }
  } catch (err) {
    console.error("OTP verification failed:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/reset-password", async (req, res) => {
  try {
    const input = req.query.otp;

    const query = { otp: input };
    let existingUser = await user.findOne(query);

    if (existingUser) {
      // Update OTP and expiry
      existingUser.otp = otp;
      existingUser.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
      await existingUser.save();

      const sent = await email(
        otp,
        existingUser.email,
        `${process.env.URL}/reset-password?otp=${encodeURIComponent(otp)}`
      );

      if (sent) {
        return res.status(200).json({ message: "Verification Code Sent" });
      } else {
        throw Error(`Error Sending Email`);
      }
    }
  } catch (err) {
    console.error("OTP verification failed:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/verify-resetPass", async (req, res) => {
  try {
    const { data, pass, code } = req.body;

    if (!data || !code || !pass) {
      return res.status(400).json({ error: "Invalid Data" });
    }

    // Search by correct field
    const user = await users.findOne({ email: data });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // ✅ Check if OTP expired first
    if (user.otpExpiresAt && user.otpExpiresAt < new Date()) {
      return res.status(410).json({ error: "OTP expired" });
    }

    // ✅ Now check if OTP code matches
    if (user.otp !== code) {
      return res.status(401).json({ error: "Incorrect OTP" });
    }

    // ✅ OTP is valid, clear OTP fields
    user.otp = null;
    user.otpExpiresAt = null;
    user.passwordHash = await bcrypt.hash(pass, 10);
    await user.save();

    res.status(200).json({
      data: "Password Reset",
    });
  } catch (err) {
    console.error("OTP verification failed:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/admin-login", async (req, res) => {
  const { email, pass } = req.body;

  if (!email || !pass) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  // Find user by email
  const u = await user.findOne({ email: email });
  if (!u) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  // Check if user has admin role
  if (!u.role || !u.role.includes("admin")) {
    return res.status(403).json({ error: "You do not have admin access." });
  }

  // Compare password
  const match = await bcrypt.compare(pass, u.passwordHash);
  if (!match) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  // Create JWT
  const token = jwt.sign(
    { id: u._id, email: u.email },
    process.env.JWT_SECRET || "SkillRex-Tech",
    { expiresIn: '30d' }
  );

  await createSystemLog(
    u._id,
    "Logged-in",
    `${u.firstName} Logged-in as Admin`
  );

  return res.json({
    token
  });
});

async function generateUniqueOtp(initialLength = 6) {
  let length = initialLength;

  while (true) {
    const max = Math.pow(10, length) - 1;
    const min = Math.pow(10, length - 1);

    const otp = Math.floor(min + Math.random() * (max - min + 1));

    // Check if OTP exists for any user
    const exists = await user.findOne({ otp });

    if (!exists) {
      return otp; // Unique OTP found
    }

    // Check if all possible OTPs of this length are taken
    const count = await user.countDocuments({
      otp: { $gte: min, $lte: max },
    });

    if (count >= max - min + 1) {
      // All possible codes of this length are used — increase length
      length++;
    }
  }
}

// Get Code for Email/Phone
app.post("/twofactor", async (req, res) => {
  try {
    const input = req.body.email;

    const validation = validateInput(input);
    if (!validation.valid) {
      return res.status(400).send("Invalid Email OR Phone Number");
    }

    const isPhone = validation.type === "phone";
    const otp = await generateUniqueOtp();
    const query = isPhone ? { phone: input } : { email: input };
    let existingUser = await user.findOne(query);

    if (existingUser) {
      if (existingUser.firstName || existingUser.passwordHash != null) {
        return res.status(409).send("User Already Exists");
      } else {
        // Update OTP and expiry
        existingUser.otp = otp;
        existingUser.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
        await existingUser.save();

        const sent = isPhone
          ? await sms(otp, existingUser.phone)
          : await email(otp, existingUser.email);

        if (sent) {
          return res.status(200).json({ message: "Verification Code Sent" });
        } else {
          throw Error(`Error Sending ${isPhone ? "SMS" : "Email"}`);
        }
      }
    } else {
      // Create new user
      const newUser = new user({
        [isPhone ? "phone" : "email"]: input,
        otp: otp,
        otpExpiresAt: new Date(Date.now() + 5 * 60 * 1000),
      });

      await newUser.save();

      const sent = isPhone
        ? await sms(otp, newUser.phone)
        : await email(otp, newUser.email);

      if (sent) {
        return res.status(200).json({ message: "Verification Code Sent" });
      } else {
        throw Error(`Error Sending ${isPhone ? "SMS" : "Email"}`);
      }
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/login", async (req, res) => {
  const users = await user.findOne({
    email: req.body.Email,
  });
  if (!users) {
    return res.status(404).send("User does not exist");
  }
  if(users.role=='admin'){
    return res.status(404).send("Access not authorized");
  }
  if (bcrypt.compareSync(req.body.password, users.passwordHash)) {
    const token = generateTokenWithoutExpiry(users.email);
    res.status(200).json({
      message: "Login Successful",
      token: token,
      id: users._id,
    });
    return;
  }
  return res.status(404).send("Incorrect Password");
});

app.post("/2facode", async (req, res) => {
  console.log(req.body);
  const user = await users.findOne({
    email: req.body.data,
  });
  if (!user) {
    return res.status(404).json({ error: "User does not exist" });
  }
  const isPhone = req.body.tfa;
  // if (user.otp !== enteredOtp || user.otpExpiresAt < new Date()) {
  //   return res.status(400).json({ message: "OTP expired or invalid." });
  // }
  const otp = Math.floor(100000 + Math.random() * 900000);
  user.otp = otp;
  user.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
  await user.save();
  const sent = isPhone
    ? await sms(otp, user.phone)
    : await email(otp, user.email);

  await createSystemLog(
    user._id,
    "Requested OTP",
    `${user.firstName} Requested OTP. OTP ${sent ? "Sent" : "Failed"}`
  );

  if (sent) res.status(200).json({ data: "Verification Code Sent" });
  else res.status(400).json({ error: "Error sending code" });
});

app.post("/verify2fa", async (req, res) => {
  try {
    const { data, password, remember, tfa, code } = req.body;

    if (!data || !code || !password || !tfa) {
      return res.status(400).json({ error: "Invalid Data" });
    }

    // Search by correct field
    const user = await users.findOne({ email: data, tfa: tfa });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // ✅ Check if OTP expired first
    if (user.otpExpiresAt && user.otpExpiresAt < new Date()) {
      return res.status(410).json({ error: "OTP expired" });
    }

    // ✅ Now check if OTP code matches
    if (user.otp !== code) {
      return res.status(401).json({ error: "Incorrect OTP" });
    }

    // ✅ Now check if Password matches
    if (!(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: "Incorrect Password" });
    }

    // ✅ OTP is valid, clear OTP fields
    user.otp = null;
    user.otpExpiresAt = null;
    await user.save();

    res.status(200).json({
      data: {
        message: "OTP Verified",
        session: {
          time: remember ? 30 : 1,
          token: generateToken(user.email, remember ? 30 : 1),
        },
      },
    });
  } catch (err) {
    console.error("OTP verification failed:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = app;
