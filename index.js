// index.js - FINAL VERSION

require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;

// Secure CORS Configuration
const whitelist = [
  // Add your dashboard's URL here when you deploy it
  // e.g., 'https://my-dashboard.onrender.com'
];
const corsOptions = {
  origin: function (origin, callback) {
    if (whitelist.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else if (origin && origin.startsWith("chrome-extension://")) {
      callback(null, true);
    } else {
      callback(new Error("This origin is not allowed by CORS"));
    }
  },
};
app.use(cors(corsOptions));
app.use(express.json());

// Database Pool with SSL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Test DB Connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log("Database connection successful! 🚀");
    connection.release();
  } catch (err) {
    console.error("Database connection failed:", err);
  }
}
testConnection();

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- API Routes ---

app.get("/", (req, res) =>
  res.send("Welcome to the Browser Wellbeing Tracker API!")
);

// ... your /register and /login routes remain the same ...
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }
  try {
    const [existingUser] = await pool.query(
      "SELECT id FROM users WHERE username = ?",
      [username]
    );
    if (existingUser.length > 0) {
      return res.status(409).json({ error: "Username already exists" });
    }
    const password_hash = await bcrypt.hash(password, saltRounds);
    const [result] = await pool.query(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [username, password_hash]
    );
    res.status(201).json({
      message: "User registered successfully",
      userId: result.insertId,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }
  try {
    const [users] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);
    const user = users[0];
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "700h",
    });
    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Final /track route with detailed logging
app.post("/track", authenticateToken, async (req, res) => {
  console.log("--- Received request for /track endpoint ---");
  try {
    const userId = req.user.userId;
    const { website_url, website_title, total_time_seconds } = req.body;
    const visit_date = new Date().toISOString().slice(0, 10);
    console.log("Data received from extension:", {
      userId,
      website_url,
      total_time_seconds,
    });
    if (!website_url || total_time_seconds === undefined) {
      console.log("Validation failed: Missing required data.");
      return res
        .status(400)
        .json({ error: "Missing website_url or total_time_seconds" });
    }
    const query = `
      INSERT INTO time_tracking (user_id, website_url, website_title, visit_date, total_time_seconds)
      VALUES (?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE total_time_seconds = total_time_seconds + VALUES(total_time_seconds)
    `;
    const values = [
      userId,
      website_url,
      website_title,
      visit_date,
      total_time_seconds,
    ];
    await pool.query(query, values);
    console.log("Query successful. Sending 200 OK response.");
    res.status(200).json({ message: "Data saved successfully" });
  } catch (error) {
    console.error("!!! ERROR IN /track ROUTE:", error);
    res.status(500).json({ error: "Internal server error during tracking." });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
