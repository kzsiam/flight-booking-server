const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser')

app.use(cors({ origin: "http://localhost:5173", credentials: true }));
app.use(express.json());
app.use(cookieParser())

//  session setup 
app.use(
  session({
    secret: "x9#vB$k@7L!pQz8R^yTn3dF&gJ",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);

//  passport initialize
app.use(passport.initialize());
app.use(passport.session());

// pending users memory store
const pendingUsers = {};

const uri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@cluster0.pzjaifg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" })
  }
  jwt.verify(token.process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "unauthorized access" })
    }
    req.user = decoded;
    next()
  })
}

let usersCollections; // global scope এ declare

async function run() {
  try {
    await client.connect();
    usersCollections = client.db("FlightBooking").collection("userCollections");

    console.log("✅ MongoDB Connected!");
  } catch (err) {
    console.error(err);
  }
}
run().catch(console.dir);

// ✅ Local strategy
passport.use(
  new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
      const user = await usersCollections.findOne({ email });
      if (!user) return done(null, false, { message: "User not found" });
      if (!user.verified) return done(null, false, { message: "Email not verified" });

      const match = await bcrypt.compare(password, user.password);
      if (!match) return done(null, false, { message: "Wrong password" });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

//google strategy

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback", // backend callback
    },
    async (accessToken, refreshToken, profile, done) => {
      let user = await usersCollections.findOne({ email: profile.emails[0].value });
      if (!user) {
        user = {
          email: profile.emails[0].value,
          password: null,
          verified: true,
          provider: "google",
          googleId: profile.id,
        };
        await usersCollections.insertOne(user);
      }
      return done(null, user);
    }
  )
);

// ✅ serialize / deserialize
passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  const user = await usersCollections.findOne({ _id: new ObjectId(id) });
  done(null, user);
});

// ✅ Email sender
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// ✅ Signup
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const exist = await usersCollections.findOne({ email });
  if (exist) return res.json({ message: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const code = Math.floor(100000 + Math.random() * 900000); // OTP
  pendingUsers[email] = { email, password: hashed, code };

  await transporter.sendMail({
    from: "yourEmail@gmail.com",
    to: email,
    subject: "Verify your email",
    text: `Your verification code is: ${code}`,
  });

  res.json({ message: "Verification code sent to email" });
});

// ✅ Verify
app.post("/verify", async (req, res) => {
  const { email, code } = req.body;

  const pending = pendingUsers[email];
  if (!pending) return res.json({ message: "No signup request found" });

  if (String(pending.code) === String(code)) {
    const newUser = {
      email: pending.email,
      password: pending.password,
      verified: true,
    };
    const result = await usersCollections.insertOne(newUser);
    delete pendingUsers[email];

    // send back the created user
    res.json({ message: "Signup Successful", user: newUser });
  } else {
    res.json({ message: "Invalid code" });
  }

});

// ✅ Resend OTP
app.post("/resend-otp", async (req, res) => {
  const { email } = req.body;

  // Check if user has a pending signup
  const pending = pendingUsers[email];
  if (!pending) return res.json({ message: "No signup request found" });

  // Generate new OTP
  const newCode = Math.floor(100000 + Math.random() * 900000);
  pendingUsers[email].code = newCode; // update OTP

  try {
    await transporter.sendMail({
      from: "yourEmail@gmail.com",
      to: email,
      subject: "Your new verification code",
      text: `Your new verification code is: ${newCode}`,
    });

    res.json({ message: "OTP resent successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to resend OTP" });
  }
});


// 🔹 Login Route
app.post("/login", passport.authenticate("local"), (req, res) => {
  res.json({ message: "Login successful", user: req.user });
});

// 🔹 Google Auth Routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "http://localhost:5173/login",
    session: true,
  }),
  (req, res) => {
    // Redirect to frontend after success
    res.redirect("http://localhost:5173/?googleLogin=success");
  }
);

// Get current user
// Current logged in user
app.get("/auth/me", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ user: req.user });
  } else {
    res.status(401).json({ user: null });
  }
});

app.post('/jwt', async (req, res) => {
  const user = req.body;
  console.log(user)
  const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "1d" })
  res.cookie('token', token, {
    httpOnly: true,
    secure: false
  }).send({ success: true })
})

app.post("/logout", (req, res) => {
  res.clearCookie("token"); // cookie remove
  res.json({ message: "Logged out" });
});

// Forgot password request
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await usersCollections.findOne({ email });
  if (!user) return res.json({ message: "User not found" });

  // Generate reset token
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "15m" });

  const resetLink = `http://localhost:5173/reset-password/${token}`;
  const brand = {
    name: "MeghFly",
    url: "https://meghfly.com",
    logo: "https://meghfly.com/logo.png",
    supportPhone: "+88 09678 332211",
    supportEmail: "info@meghfly.com",
    messengerUrl: "https://m.me/MeghFly"
  };

  await transporter.sendMail({
    from: process.env.GMAIL_USER,
    to: email,
    subject: "Reset your password",
    // html: `<p>Click here to reset your password:</p>
    //        <a href="${resetLink}">${resetLink}</a>`,
    html: `
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password reset</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      .btn {
        background:#f7c51e;
        color:#0b2c5f;
        text-decoration:none;
        display:inline-block;
        padding:12px 22px;
        border-radius:8px;
        font-weight:700;
        font-size:14px
      }
      .muted {
        color:#6b7280;
        font-size:12px;
        line-height:18px
      }
      @media (prefers-color-scheme: dark) {
        body {background:#0b0f19!important;color:#e5e7eb!important}
        .card {background:#111827!important}
      }
    </style>
  </head>
  <body style="margin:0;background:#ffffff;font-family:Inter,Segoe UI,Arial,sans-serif;color:#0b2c5f;">
    <!-- Hidden preheader text -->
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;">
      Reset your ${brand.name} password
    </div>

    <!-- header -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
      <tr>
        <td style="padding:22px 24px;border-bottom:1px solid #eef2f7;">
          <a href="${brand.url}" target="_blank" style="text-decoration:none;">
            <img src="${brand.logo}" height="28" alt="${brand.name}" style="display:block">
          </a>
        </td>
      </tr>
    </table>

    <!-- body -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center" style="padding:36px 16px 24px;">
          <table role="presentation" width="560" cellpadding="0" cellspacing="0" class="card"
                 style="max-width:560px;background:#ffffff;border-radius:12px;">
            <tr>
              <td align="center" style="padding:32px 24px 8px;">
                <div style="background:#eef4ff;width:120px;height:120px;border-radius:60px;display:flex;align-items:center;justify-content:center;margin:0 auto;">
                  <svg width="58" height="58" viewBox="0 0 24 24" fill="none"
                       xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                    <rect x="5" y="10" width="14" height="10" rx="2" fill="#3b5b8f"/>
                    <path d="M8 10V8a4 4 0 1 1 8 0v2" stroke="#3b5b8f" stroke-width="2" stroke-linecap="round"/>
                    <circle cx="12" cy="15" r="1.3" fill="#1e3a8a"/>
                  </svg>
                </div>

                <h1 style="margin:24px 0 8px;font-size:18px;line-height:24px;color:#0b2c5f;">Hello</h1>
                <p style="margin:0 0 20px;font-size:14px;line-height:22px;color:#334155;">
                  You recently requested a password reset for your ${brand.name} account.
                  To complete the process, click the button below.
                </p>

                <a href="${resetLink}" class="btn" target="_blank">RESET NOW</a>

                <p class="muted" style="margin:24px 0 8px;">
                  If you didn’t request this, you can safely ignore this email.
                </p>
              </td>
            </tr>
          </table>

          <!-- footer -->
          <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;margin-top:28px;">
            <tr>
              <td align="center" style="padding:8px;">
                <p style="margin:0 0 6px;font-weight:600;color:#0b2c5f;">Need Help?</p>
                <table role="presentation" cellpadding="0" cellspacing="0" align="center">
                  <tr>
                    <td style="padding:6px 10px;font-size:13px;color:#0b2c5f;">
                      📞 ${brand.supportPhone}
                    </td>
                    <td style="padding:6px 10px;font-size:13px;">
                      ✉️ <a href="mailto:${brand.supportEmail}" style="color:#0b2c5f;text-decoration:none;">${brand.supportEmail}</a>
                    </td>
                    <td style="padding:6px 10px;font-size:13px;">
                      💬 <a href="${brand.messengerUrl}" style="color:#0b2c5f;text-decoration:none;">Messenger</a>
                    </td>
                  </tr>
                </table>
                <p class="muted" style="margin:14px 0 0;">© ${new Date().getFullYear()} ${brand.name}. All rights reserved.</p>
              </td>
            </tr>
          </table>

        </td>
      </tr>
    </table>
  </body>
</html>`,
  });

  res.json({ message: "Reset link sent to your email" });
});

// Reset password
app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(decoded)
    const hashed = await bcrypt.hash(password, 10);

    await usersCollections.updateOne(
      { _id: new ObjectId(decoded.id) },
      { $set: { password: hashed } }
    );

    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(400).json({ message: "Invalid or expired token" });
  }
});

app.get("/", (req, res) => res.send("Hello I am flight server"));
app.listen(port, () => console.log(` Server running on port ${port}`));
