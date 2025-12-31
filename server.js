const express = require("express");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const USERS_FILE = "./users.json";
const APPOINTMENTS_FILE = "./appointments.json";
const JWT_SECRET = "super_secret_key_123";

// 🔒 FIXED ADMIN
const ADMIN_EMAIL = "admin@clinic.com";
const ADMIN_PASSWORD = "admin123";

/* ---------- HELPERS ---------- */
const readFile = (file) =>
  JSON.parse(fs.readFileSync(file, "utf8"));

const writeFile = (file, data) =>
  fs.writeFileSync(file, JSON.stringify(data, null, 2));

/* ---------- AUTH MIDDLEWARE ---------- */
const auth = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ message: "Invalid token" });
  }
};

/* ---------- REGISTER ---------- */
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const users = readFile(USERS_FILE);

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: "User exists" });
  }

  const hashed = await bcrypt.hash(password, 10);
  users.push({ id: Date.now(), name, email, password: hashed });
  writeFile(USERS_FILE, users);

  res.json({ message: "Registered successfully" });
});

/* ---------- USER LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const users = readFile(USERS_FILE);
  const user = users.find(u => u.email === email);

  if (!user) return res.status(401).json({ message: "Invalid login" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ message: "Invalid login" });

  const token = jwt.sign(
    { id: user.id, role: "user" },
    JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({ token, name: user.name });
});

/* ---------- ADMIN LOGIN ---------- */
app.post("/admin/login", (req, res) => {
  const { email, password } = req.body;

  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ message: "Admin denied" });
  }

  const token = jwt.sign(
    { role: "admin" },
    JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({ token });
});

/* ---------- CREATE APPOINTMENT ---------- */
app.post("/appointments", auth, (req, res) => {
  if (req.user.role !== "user") {
    return res.status(403).json({ message: "Forbidden" });
  }

  const appointments = readFile(APPOINTMENTS_FILE);
  appointments.push({
    id: Date.now(),
    userId: req.user.id,
    ...req.body,
    status: "Pending"
  });

  writeFile(APPOINTMENTS_FILE, appointments);
  res.json({ message: "Appointment booked" });
});

/* ---------- USER APPOINTMENTS ---------- */
app.get("/appointments/my", auth, (req, res) => {
  const appointments = readFile(APPOINTMENTS_FILE);
  res.json(
    appointments.filter(a => a.userId === req.user.id)
  );
});

/* ---------- ADMIN ALL APPOINTMENTS ---------- */
app.get("/appointments", auth, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin only" });
  }
  res.json(readFile(APPOINTMENTS_FILE));
});

/* ---------- ADMIN UPDATE STATUS ---------- */
app.put("/appointments/:id", auth, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin only" });
  }

  let appointments = readFile(APPOINTMENTS_FILE);
  appointments = appointments.map(a =>
    a.id == req.params.id ? { ...a, status: req.body.status } : a
  );

  writeFile(APPOINTMENTS_FILE, appointments);
  res.json({ message: "Status updated" });
});

/* ---------- ADMIN DELETE ---------- */
app.delete("/appointments/:id", auth, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin only" });
  }

  let appointments = readFile(APPOINTMENTS_FILE);
  appointments = appointments.filter(a => a.id != req.params.id);
  writeFile(APPOINTMENTS_FILE, appointments);

  res.json({ message: "Deleted" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running"));