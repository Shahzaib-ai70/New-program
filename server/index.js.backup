import express from "express";
import cors from "cors";
import multer from "multer";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

/* =========================
   BASIC SETUP
========================= */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

/* =========================
   STORAGE DIRECTORIES
========================= */
const uploadsDir = path.join(__dirname, "uploads");
const dataDir = path.join(__dirname, "data");

fs.mkdirSync(uploadsDir, { recursive: true });
fs.mkdirSync(dataDir, { recursive: true });

const upload = multer({ dest: uploadsDir });

/* =========================
   SIMPLE JSON STORAGE
========================= */
function readStore(name) {
  const file = path.join(dataDir, `${name}.json`);
  if (!fs.existsSync(file)) return [];
  try {
    return JSON.parse(fs.readFileSync(file, "utf-8") || "[]");
  } catch {
    return [];
  }
}

function writeStore(name, data) {
  fs.writeFileSync(
    path.join(dataDir, `${name}.json`),
    JSON.stringify(data, null, 2)
  );
}

/* =========================
   STATIC SERVING
========================= */
app.use("/uploads", express.static(uploadsDir));
app.use("/admin", express.static(path.join(__dirname, "admin")));

/* =========================
   HEALTH CHECK
========================= */
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

/* =========================
   DEPOSIT
========================= */
app.post("/api/deposit", upload.single("voucher"), (req, res) => {
  const { currency, network, amount, address } = req.body;

  const record = {
    id: Date.now().toString(36),
    currency,
    network,
    amount: parseFloat(amount || "0"),
    address,
    voucher: req.file ? `/uploads/${req.file.filename}` : null,
    status: "pending",
    createdAt: new Date().toISOString()
  };

  const deposits = readStore("deposits");
  deposits.push(record);
  writeStore("deposits", deposits);

  res.json(record);
});

/* =========================
   WITHDRAW
========================= */
app.post("/api/withdraw", (req, res) => {
  const { currency, network, amount, address } = req.body;

  const record = {
    id: Date.now().toString(36),
    currency,
    network,
    amount: parseFloat(amount || "0"),
    address,
    status: "processing",
    createdAt: new Date().toISOString()
  };

  const withdrawals = readStore("withdrawals");
  withdrawals.push(record);
  writeStore("withdrawals", withdrawals);

  res.json(record);
});

/* =========================
   TRADING (MOCK ENGINE)
========================= */
app.post("/api/trade", (req, res) => {
  const { symbol, side, quantity, type, price } = req.body;

  const win = Math.random() < 0.5;
  const pnlValue = Math.random() * 0.01 * (parseFloat(quantity || "0") || 0);

  const record = {
    id: Date.now().toString(36),
    symbol,
    side,
    quantity: parseFloat(quantity || "0"),
    type,
    price: price ? parseFloat(price) : null,
    outcome: win ? "win" : "lose",
    pnl: win ? +pnlValue.toFixed(6) : -+pnlValue.toFixed(6),
    createdAt: new Date().toISOString()
  };

  const trades = readStore("trades");
  trades.push(record);
  writeStore("trades", trades);

  res.json(record);
});

/* =========================
   LIST APIS
========================= */
app.get("/api/deposits", (req, res) => res.json(readStore("deposits")));
app.get("/api/withdrawals", (req, res) => res.json(readStore("withdrawals")));
app.get("/api/trades", (req, res) => res.json(readStore("trades")));

/* =========================
   ADMIN STATUS UPDATES
========================= */
app.post("/api/deposit/:id/status", (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  const data = readStore("deposits");
  const index = data.findIndex(d => d.id === id);
  if (index === -1) return res.status(404).json({ error: "not_found" });

  data[index].status = status || data[index].status;
  writeStore("deposits", data);

  res.json(data[index]);
});

app.post("/api/withdraw/:id/status", (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  const data = readStore("withdrawals");
  const index = data.findIndex(d => d.id === id);
  if (index === -1) return res.status(404).json({ error: "not_found" });

  data[index].status = status || data[index].status;
  writeStore("withdrawals", data);

  res.json(data[index]);
});

/* =========================
   MARKET PRICES (BINANCE)
========================= */
app.get("/api/markets", async (req, res) => {
  try {
    const symbols = req.query.symbols
      ? JSON.parse(req.query.symbols)
      : ["BTCUSDT", "ETHUSDT", "XRPUSDT"];

    const url =
      "https://api.binance.com/api/v3/ticker/24hr?symbols=" +
      encodeURIComponent(JSON.stringify(symbols));

    const r = await fetch(url);
    const j = await r.json();
    res.json(j);
  } catch {
    res.status(500).json({ error: "failed_fetch" });
  }
});

/* =========================
   ADMIN DASHBOARD SUMMARY
========================= */
app.get("/api/admin/summary", (req, res) => {
  const deposits = readStore("deposits");
  const withdrawals = readStore("withdrawals");
  const trades = readStore("trades");

  const today = new Date().toISOString().slice(0, 10);
  const isToday = (d) => (d || "").startsWith(today);

  const sumAmount = (arr) =>
    arr.reduce((a, b) => a + (parseFloat(b.amount) || 0), 0);

  res.json({
    platformRechargeUpDown: sumAmount(deposits),
    platformOrders: trades.length,
    todayRechargeUpDown: sumAmount(deposits.filter(d => isToday(d.createdAt))),
    todayOrders: trades.filter(t => isToday(t.createdAt)).length,
    usersRegistered: 0,
    usersRealName: 0,
    usersVerified: 0
  });
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Bitsafe API running on port ${PORT}`);
});
