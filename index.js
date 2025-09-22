// CommonJS for simplicity (no "type":"module" needed)
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());

// CORS: allow your GitHub Pages origin + local dev
const ALLOWED_ORIGINS = new Set([
  "https://yahdeeez.github.io",
  "http://localhost:5173",
  "http://localhost:8080",
]);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || ALLOWED_ORIGINS.has(origin)) return cb(null, true);
      cb(new Error("CORS blocked: " + origin));
    },
    credentials: false, // set true only if you switch to cookie-based auth
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

const users = new Map(); // demo store; replace with a DB later
const JWT_SECRET = process.env.JWT_SECRET || "dev_only_change_me";

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });
  if (users.has(email)) return res.status(409).json({ error: "user exists" });
  const hash = await bcrypt.hash(password, 10);
  users.set(email, { email, hash });
  return res.status(201).json({ ok: true });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const u = users.get(email);
  if (!u) return res.status(401).json({ error: "invalid credentials" });
  const ok = await bcrypt.compare(password, u.hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });
  const token = jwt.sign({ sub: email }, JWT_SECRET, { expiresIn: "7d" });
  return res.json({ token });
});

app.get("/api/me", (req, res) => {
  const hdr = req.headers.authorization || "";
  const m = hdr.match(/^Bearer (.+)$/);
  if (!m) return res.status(401).json({ error: "missing token" });
  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    return res.json({ email: payload.sub });
  } catch {
    return res.status(401).json({ error: "bad token" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("API listening on :" + port));
