import Database from "better-sqlite3";
import express from "express";
import cors from "cors";
import multer from "multer";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";

/* ================= BASIC SETUP ================= */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors({ origin: "*"}));
app.use(express.json());
app.use(cookieParser());

const rootDir = path.join(__dirname, "..");
app.use(express.static(rootDir));
app.get("/", (req, res) => {
  res.sendFile(path.join(rootDir, "index.html"));
});
app.use("/admin", express.static(path.join(__dirname, "admin")));

/* ================= DATABASE ================= */
const db = new Database(path.join(__dirname, "db.sqlite"));

db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  balance REAL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

/* ================= AUTH APIs ================= */

// REGISTER
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const hash = bcrypt.hashSync(password, 10);

  try {
    db.prepare(`
      INSERT INTO users (username, balance)
      VALUES (?, ?)
    `).run(username, 0);

    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: "Username already exists" });
  }
});

// LOGIN
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  const user = db.prepare(
    "SELECT * FROM users WHERE username=?"
  ).get(username);

  if (!user) {
    return res.status(401).json({ error: "Invalid login" });
  }

  res.cookie("user", username, {
    httpOnly: true,
    sameSite: "lax"
  });

  res.json({ success: true });
});

// CURRENT USER
app.get("/api/me", (req, res) => {
  const username = req.cookies.user || req.headers['x-user'];
  if (!username) return res.json(null);

  const user = db.prepare(
    "SELECT id, username, balance FROM users WHERE username=?"
  ).get(username);

  res.json(user);
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  res.clearCookie("user");
  res.json({ success: true });
});

// TRADES TABLE
db.prepare(`
CREATE TABLE IF NOT EXISTS trades (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  symbol TEXT,
  side TEXT,
  amount REAL,
  profit REAL,
  result TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

// REAL NAME VERIFICATIONS
db.prepare(`
CREATE TABLE IF NOT EXISTS verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  kind TEXT, /* primary | advanced */
  first_name TEXT,
  last_name TEXT,
  document_type TEXT,
  document_number TEXT,
  front_image TEXT,
  back_image TEXT,
  selfie_image TEXT,
  status TEXT DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

// DEPOSITS TABLE
db.prepare(`
CREATE TABLE IF NOT EXISTS deposits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  currency TEXT,
  network TEXT,
  amount REAL,
  proof_image TEXT,
  status TEXT DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

// Check if proof_image column exists, if not add it (migration)
try {
  db.prepare("ALTER TABLE deposits ADD COLUMN proof_image TEXT").run();
} catch (e) {
  // Column likely exists
}


// WITHDRAWALS TABLE
db.prepare(`
CREATE TABLE IF NOT EXISTS withdrawals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  currency TEXT,
  network TEXT,
  amount REAL,
  status TEXT DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

/* ================== FILE STORAGE ================== */
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir)
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, file.fieldname + '-' + uniqueSuffix + ext)
  }
})

const upload = multer({ storage: storage });

// Serve uploads
app.use("/uploads", express.static(uploadsDir));

// SUBMIT DEPOSIT
app.post("/api/deposit", upload.single('voucher'), (req, res) => {
  const username = req.cookies.user || req.headers['x-user'];
  if (!username) return res.status(401).json({ error: "Unauthorized" });

  const { currency, network, amount, address } = req.body;
  const proof_image = req.file ? "/uploads/" + req.file.filename : null;

  try {
    const info = db.prepare(`
      INSERT INTO deposits (username, currency, network, amount, proof_image)
      VALUES (?, ?, ?, ?, ?)
    `).run(username, currency, network, amount, proof_image);
    
    res.json({ id: info.lastInsertRowid, status: "pending" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PRIMARY VERIFICATION
app.post("/api/verification/primary", (req, res) => {
  const username = req.cookies.user || req.headers['x-user'];
  if (!username) return res.status(401).json({ error: "Unauthorized" });
  const { first_name, last_name, document_type, document_number } = req.body;
  if (!first_name || !last_name || !document_type || !document_number) {
    return res.status(400).json({ error: "Missing fields" });
  }
  try {
    const info = db.prepare(`
      INSERT INTO verifications (username, kind, first_name, last_name, document_type, document_number, status)
      VALUES (?, 'primary', ?, ?, ?, ?, 'pending')
    `).run(username, first_name, last_name, document_type, document_number);
    res.json({ id: info.lastInsertRowid, status: "pending" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ADVANCED VERIFICATION WITH FILES
app.post("/api/verification/advanced", upload.fields([
  { name: 'front', maxCount: 1 },
  { name: 'back', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), (req, res) => {
  const username = req.cookies.user || req.headers['x-user'];
  if (!username) return res.status(401).json({ error: "Unauthorized" });
  const { document_type, document_number } = req.body;
  if (!document_type || !document_number) {
    return res.status(400).json({ error: "Missing fields" });
  }
  const front = req.files?.front?.[0] ? "/uploads/" + req.files.front[0].filename : null;
  const back = req.files?.back?.[0] ? "/uploads/" + req.files.back[0].filename : null;
  const selfie = req.files?.selfie?.[0] ? "/uploads/" + req.files.selfie[0].filename : null;
  if (!front || !back || !selfie) {
    return res.status(400).json({ error: "Missing images" });
  }
  try {
    const info = db.prepare(`
      INSERT INTO verifications (username, kind, document_type, document_number, front_image, back_image, selfie_image, status)
      VALUES (?, 'advanced', ?, ?, ?, ?, ?, 'pending')
    `).run(username, document_type, document_number, front, back, selfie);
    res.json({ id: info.lastInsertRowid, status: "pending" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// USER VERIFICATION STATUS
app.get("/api/verification/status", (req, res) => {
  const username = req.cookies.user || req.headers['x-user'];
  if (!username) return res.json({ primary: null, advanced: null });
  const primary = db.prepare(`SELECT status FROM verifications WHERE username=? AND kind='primary' ORDER BY id DESC LIMIT 1`).get(username);
  const advanced = db.prepare(`SELECT status FROM verifications WHERE username=? AND kind='advanced' ORDER BY id DESC LIMIT 1`).get(username);
  res.json({
    primary: primary?.status || null,
    advanced: advanced?.status || null
  });
});


/* ================== HEALTH ================== */
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

/* ================== MARKET PRICES (BINANCE) ================== */
app.get("/api/markets", async (req, res) => {
  try {
    const symbols = req.query.symbols
      ? JSON.parse(req.query.symbols)
      : [
          "BTCUSDT","ETHUSDT","BNBUSDT","XRPUSDT","ADAUSDT",
          "SOLUSDT","DOGEUSDT","TRXUSDT","LTCUSDT","DOTUSDT"
        ];

    const url =
      "https://api.binance.com/api/v3/ticker/24hr?symbols=" +
      encodeURIComponent(JSON.stringify(symbols));

    const r = await fetch(url);
    const data = await r.json();

    const markets = data.map(m => ({
      symbol: m.symbol,
      price: m.lastPrice,
      changePercent: m.priceChangePercent,
      high: m.highPrice,
      low: m.lowPrice,
      volume: m.volume
    }));

    res.json(markets);
  } catch (e) {
    res.status(500).json({ error: "market_fetch_failed" });
  }
});

/* ================== USERS (ADMIN) ================== */
app.get("/api/admin/users", (req, res) => {
  try {
    const users = db.prepare("SELECT * FROM users").all();
    res.json(users);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// CREATE USER (NO LOGIN FOR NOW)
app.post("/api/admin/users", (req, res) => {
  const { username, balance = 0 } = req.body;
  try {
    db.prepare(
      "INSERT INTO users (username, balance) VALUES (?, ?)"
    ).run(username, balance);
    res.json({ status: "created" });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// UPDATE BALANCE
app.post("/api/admin/users/balance", (req, res) => {
  const { username, balance } = req.body;
  // If balance is negative (e.g. -25), it will subtract.
  // If balance is positive (e.g. 25), it will add.
  db.prepare(
    "UPDATE users SET balance = balance + ? WHERE username=?"
  ).run(balance, username);
  res.json({ status: "updated" });
});

/* ================== DEMO TRADE ENGINE ================== */
// Admin decides winning side
let ADMIN_WIN_SIDE = "short"; // "long" or "short"

app.post("/api/trade", (req, res) => {
  let { username, symbol, side, amount, percent } = req.body;

  // Validate and parse inputs
  amount = parseFloat(amount);
  percent = parseFloat(percent);

  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: "Invalid amount" });
  }
  if (isNaN(percent)) {
    percent = 0; // Default to 0 if missing
  }

  const win = side === ADMIN_WIN_SIDE;
  const profit = win ? amount * (percent / 100) : -amount;

  console.log(`[TRADE] User: ${username}, Side: ${side}, Win: ${win}, Amount: ${amount}, Percent: ${percent}, Profit: ${profit}`);

  try {
    db.prepare(`
      INSERT INTO trades (username, symbol, side, amount, profit, result)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(username, symbol, side, amount, profit, win ? "win" : "lose");

    db.prepare(
      "UPDATE users SET balance = balance + ? WHERE username=?"
    ).run(profit, username);

    res.json({
      result: win ? "win" : "lose",
      profit
    });
  } catch (e) {
    console.error("Trade error:", e);
    res.status(500).json({ error: "Trade failed" });
  }
});

/* ================== ADMIN CONTROL ================== */
app.post("/api/admin/winside", (req, res) => {
  ADMIN_WIN_SIDE = req.body.side; // long / short
  res.json({ winSide: ADMIN_WIN_SIDE });
});

app.get("/api/admin/summary", (req, res) => {
  try {
    const orders = db.prepare("SELECT COUNT(*) as count FROM trades").get();
    const deposits = db.prepare("SELECT SUM(amount) as total FROM deposits WHERE status='approved'").get();
    const withdraws = db.prepare("SELECT SUM(amount) as total FROM withdrawals WHERE status='approved'").get();
    
    // Today's stats
    const today = new Date().toISOString().split('T')[0];
    const todayOrders = db.prepare("SELECT COUNT(*) as count FROM trades WHERE date(created_at) = ?").get(today);
    const todayDeposits = db.prepare("SELECT SUM(amount) as total FROM deposits WHERE status='approved' AND date(created_at) = ?").get(today);
    const todayWithdraws = db.prepare("SELECT SUM(amount) as total FROM withdrawals WHERE status='approved' AND date(created_at) = ?").get(today);

    res.json({
      platformOrders: orders.count || 0,
      platformRechargeUpDown: (deposits.total || 0) - (withdraws.total || 0),
      todayOrders: todayOrders.count || 0,
      todayRechargeUpDown: (todayDeposits.total || 0) - (todayWithdraws.total || 0)
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/deposits", (req, res) => {
  const rows = db.prepare("SELECT * FROM deposits ORDER BY id DESC").all();
  res.json(rows);
});

app.get("/api/withdrawals", (req, res) => {
  const rows = db.prepare("SELECT * FROM withdrawals ORDER BY id DESC").all();
  res.json(rows);
});

app.get("/api/trades", (req, res) => {
  const rows = db.prepare("SELECT * FROM trades ORDER BY id DESC").all();
  res.json(rows);
});

// ADMIN: VERIFICATIONS LIST
app.get("/api/admin/verifications", (req, res) => {
  try {
    const rows = db.prepare("SELECT * FROM verifications ORDER BY id DESC").all();
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ADMIN: VERIFICATION STATUS UPDATE
app.post("/api/admin/verification/:id/status", (req, res) => {
  const { status } = req.body;
  const { id } = req.params;
  db.prepare("UPDATE verifications SET status=? WHERE id=?").run(status, id);
  res.json({ success: true });
});

app.post("/api/deposit/:id/status", (req, res) => {
  const { status } = req.body;
  const { id } = req.params;
  db.prepare("UPDATE deposits SET status=? WHERE id=?").run(status, id);
  if (status === 'approved') {
    const dep = db.prepare("SELECT * FROM deposits WHERE id=?").get(id);
    if (dep) {
       db.prepare("UPDATE users SET balance = balance + ? WHERE username=?").run(dep.amount, dep.username);
    }
  }
  res.json({ success: true });
});

app.post("/api/withdraw/:id/status", (req, res) => {
  const { status } = req.body;
  const { id } = req.params;
  db.prepare("UPDATE withdrawals SET status=? WHERE id=?").run(status, id);
  // Balance deduction should ideally happen on request, but for now we just track status
  res.json({ success: true });
});

/* ================== START SERVER ================== */
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Bitsafe API running on port ${PORT}`);
});
