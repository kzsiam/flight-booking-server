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

app.use(cors({ origin: "http://localhost:5173", credentials: true }));
app.use(express.json());

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
      clientID: "859334940084-n1rdmvpcochr819m5mlhcjpmb7gtf4ui.apps.googleusercontent.com",
      clientSecret: "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",
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
    user: "kazisiam248@gmail.com",
    pass: "xnrdegtebuvniwug",
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
// app.post("/verify", async (req, res) => {
//   const { email, code } = req.body;
//   console.log(code)
//   const pending = pendingUsers[email];
//   if (!pending) return res.json({ message: "No signup request found" });

//   if (String(pending.code) === String(code)) {
//     const newUser = {
//       email: pending.email,
//       password: pending.password,
//       verified: true,
//     };
//     const result = await usersCollections.insertOne(newUser);
//     delete pendingUsers[email];

//     // send back the created user
//     res.json({ message: "Signup Successful", user: newUser });
//   } else {
//     res.json({ message: "Invalid code" });
//   }

// });

// // ✅ Resend OTP
// app.post("/resend-otp", async (req, res) => {
//   const { email } = req.body;

//   // Check if user has a pending signup
//   const pending = pendingUsers[email];
//   if (!pending) return res.json({ message: "No signup request found" });

//   // Generate new OTP
//   const newCode = Math.floor(100000 + Math.random() * 900000);
//   pendingUsers[email].code = newCode; // update OTP

//   try {
//     await transporter.sendMail({
//       from: "yourEmail@gmail.com",
//       to: email,
//       subject: "Your new verification code",
//       text: `Your new verification code is: ${newCode}`,
//     });

//     res.json({ message: "OTP resent successfully" });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "Failed to resend OTP" });
//   }
// });


// // 🔹 Login Route
// app.post("/login", passport.authenticate("local"), (req, res) => {
//   res.json({ message: "Login successful", user: req.user });
// });

// // 🔹 Google Auth Routes
// app.get(
//   "/auth/google",
//   passport.authenticate("google", { scope: ["profile", "email"] })
// );

// app.get(
//   "/auth/google/callback",
//   passport.authenticate("google", {
//     failureRedirect: "http://localhost:5173/login",
//     session: true,
//   }),
//   (req, res) => {
//     // Redirect to frontend after success
//     res.redirect("http://localhost:5173/?googleLogin=success");
//   }
// );

// // Get current user
// // Current logged in user
// app.get("/auth/me", (req, res) => {
//   if (req.isAuthenticated()) {
//     res.json({ user: req.user });
//   } else {
//     res.status(401).json({ user: null });
//   }
// });

app.get("/", (req, res) => res.send("Hello I am flight server"));
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
