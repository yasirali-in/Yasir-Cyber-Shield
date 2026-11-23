require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.VT_API_KEY;
const MAX_FILE_SIZE = 32 * 1024 * 1024;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 60 * 1000, limit: 25, standardHeaders: "draft-7", legacyHeaders: false }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (_req, file, cb) => {
    // This project analyzes uploaded bytes; it never executes uploaded files.
    if (!file.originalname || file.originalname.length > 180) return cb(new Error("Invalid file name."));
    cb(null, true);
  }
});

const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");
const vtHeaders = { "x-apikey": API_KEY || "", "accept": "application/json" };

app.get("/api/status", (_req, res) => {
  res.json({ mode: API_KEY ? "virustotal" : "demo", apiConfigured: Boolean(API_KEY) });
});

app.post("/api/scan-file", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Choose a file first." });
    const file = req.file;
    const hash = sha256(file.buffer);
    const base = {
      fileName: path.basename(file.originalname),
      fileSize: file.size,
      mimeType: file.mimetype || "application/octet-stream",
      sha256: hash
    };

    if (!API_KEY) {
      return res.json({
        mode: "demo",
        ...base,
        verdict: "Demo analysis",
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        message: "No VirusTotal API key is configured. These are local file details only, not malware detection results."
      });
    }

    const form = new FormData();
    form.append("file", new Blob([file.buffer]), file.originalname);
    const vtResponse = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST", headers: vtHeaders, body: form
    });
    const vtData = await vtResponse.json();
    if (!vtResponse.ok) {
      return res.status(vtResponse.status).json({ error: vtData.error?.message || "VirusTotal upload failed." });
    }
    res.json({ mode: "virustotal", ...base, analysisId: vtData.data.id, message: "File submitted. Analysis may take a short time." });
  } catch (err) {
    res.status(500).json({ error: err.message || "Unable to analyze this file." });
  }
});

app.get("/api/analysis/:id", async (req, res) => {
  if (!API_KEY) return res.status(400).json({ error: "Configure VT_API_KEY to retrieve real analysis." });
  if (!/^[A-Za-z0-9_-]{8,300}$/.test(req.params.id)) return res.status(400).json({ error: "Invalid analysis ID." });
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(req.params.id)}`, { headers: vtHeaders });
    const data = await response.json();
    if (!response.ok) return res.status(response.status).json({ error: data.error?.message || "Could not retrieve analysis." });
    const a = data.data?.attributes || {};
    const s = a.stats || {};
    res.json({
      status: a.status || "queued",
      stats: { malicious: s.malicious || 0, suspicious: s.suspicious || 0, harmless: s.harmless || 0, undetected: s.undetected || 0 },
      results: a.results || {}
    });
  } catch {
    res.status(502).json({ error: "VirusTotal service could not be reached." });
  }
});

app.post("/api/scan-url", async (req, res) => {
  const raw = String(req.body?.url || "").trim();
  let parsed;
  try { parsed = new URL(raw); } catch { return res.status(400).json({ error: "Enter a valid URL including https:// or http://." }); }
  if (!["http:", "https:"].includes(parsed.protocol)) return res.status(400).json({ error: "Only HTTP and HTTPS URLs are accepted." });

  if (!API_KEY) {
    return res.json({ mode: "demo", url: parsed.href, host: parsed.hostname, verdict: "Demo only", message: "No API key configured. The URL format was checked, but its reputation was not scanned." });
  }
  try {
    const id = Buffer.from(parsed.href).toString("base64").replace(/=+$/g, "");
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, { headers: vtHeaders });
    const data = await response.json();
    if (!response.ok) return res.status(response.status).json({ error: data.error?.message || "URL report unavailable. Try submitting it through VirusTotal first." });
    const s = data.data?.attributes?.last_analysis_stats || {};
    res.json({ mode: "virustotal", url: parsed.href, host: parsed.hostname, stats: { malicious: s.malicious || 0, suspicious: s.suspicious || 0, harmless: s.harmless || 0, undetected: s.undetected || 0 } });
  } catch {
    res.status(502).json({ error: "VirusTotal service could not be reached." });
  }
});

app.get("/api/ip/:ip", async (req, res) => {
  const ip = req.params.ip;
  const net = require("net");
  if (!net.isIP(ip)) return res.status(400).json({ error: "Enter a valid IPv4 or IPv6 address." });
  if (!API_KEY) return res.json({ mode: "demo", ip, message: "IP format is valid. Reputation lookup requires a VirusTotal API key." });
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, { headers: vtHeaders });
    const data = await response.json();
    if (!response.ok) return res.status(response.status).json({ error: data.error?.message || "IP report unavailable." });
    const a = data.data?.attributes || {};
    const s = a.last_analysis_stats || {};
    res.json({ mode: "virustotal", ip, country: a.country || "Unknown", asOwner: a.as_owner || "Unknown", stats: { malicious: s.malicious || 0, suspicious: s.suspicious || 0, harmless: s.harmless || 0, undetected: s.undetected || 0 } });
  } catch {
    res.status(502).json({ error: "VirusTotal service could not be reached." });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: "File is too large. Maximum size is 32 MB." });
  res.status(400).json({ error: err.message || "Request could not be processed." });
});

app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.listen(PORT, () => console.log(`Yasir Cyber Shield running at http://localhost:${PORT}`));
