import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { WebSocketServer } from "ws";
import { nanoid } from "nanoid";
import bcrypt from "bcryptjs";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { openDB } from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json({ limit: "256kb" }));

const limiter = rateLimit({ windowMs: 5_000, max: 30 });
app.use("/api/", limiter);

const db = openDB(process.env.DB_PATH || "./data.sqlite");

const now = () => Date.now();
const SESSION_TTL_MS = (parseInt(process.env.SESSION_TTL_SEC || "2592000", 10) || 2592000) * 1000;

const OWNER_USER = process.env.OWNER_USER || "owner";
const OWNER_PASS = process.env.OWNER_PASS || "owner123";

function ensureOwner() {
  const ex = db.prepare(`SELECT id FROM users WHERE role='owner' LIMIT 1`).get();
  if (ex) return;
  const id = nanoid(24);
  const pass_hash = bcrypt.hashSync(OWNER_PASS, 10);
  db.prepare(`INSERT INTO users(id,username,pass_hash,role,created_at) VALUES(?,?,?,?,?)`)
    .run(id, OWNER_USER, pass_hash, "owner", now());
}
ensureOwner();

function newSession(user_id) {
  const token = nanoid(48);
  db.prepare(`INSERT INTO sessions(token,user_id,expires_at,created_at) VALUES(?,?,?,?)`)
    .run(token, user_id, now() + SESSION_TTL_MS, now());
  return token;
}

function getAuth(req) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return null;

  const row = db.prepare(`
    SELECT s.user_id as userId, s.expires_at as exp, u.username as username, u.role as role
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token=?
  `).get(token);

  if (!row) return null;
  if (row.exp <= now()) {
    db.prepare(`DELETE FROM sessions WHERE token=?`).run(token);
    return null;
  }

  const ban = db.prepare(`SELECT banned_until FROM bans WHERE user_id=?`).get(row.userId);
  if (ban && (ban.banned_until == null || ban.banned_until > now())) return null;

  return { token, userId: row.userId, username: row.username, role: row.role };
}

function isMuted(userId) {
  const m = db.prepare(`SELECT muted_until FROM mutes WHERE user_id=?`).get(userId);
  return m && m.muted_until > now() ? m.muted_until : 0;
}

function findUser(q) {
  const s = String(q || "").replace(/^@/, "").trim();
  let u = db.prepare(`SELECT id, username, role FROM users WHERE id=?`).get(s);
  if (u) return u;
  u = db.prepare(`SELECT id, username, role FROM users WHERE username=?`).get(s);
  return u || null;
}

// ---- realtime rooms ----
const rooms = new Map(); // room -> Set(ws)
function roomSet(room) {
  if (!rooms.has(room)) rooms.set(room, new Set());
  return rooms.get(room);
}
function broadcast(room, payload) {
  const set = roomSet(room);
  const data = JSON.stringify(payload);
  for (const ws of set) {
    try { ws.send(data); } catch {}
  }
}

// ---- API ----
app.post("/api/auth/guest", (req, res) => {
  const username = String(req.body?.username || `Guest${Math.floor(Math.random()*9000+1000)}`).slice(0, 18);
  const id = nanoid(24);
  try {
    db.prepare(`INSERT INTO users(id,username,pass_hash,role,created_at) VALUES(?,?,?,?,?)`)
      .run(id, username, null, "user", now());
  } catch {
    // nếu trùng username, thêm suffix
    const u2 = (username + "_" + Math.floor(Math.random()*999)).slice(0, 18);
    db.prepare(`INSERT INTO users(id,username,pass_hash,role,created_at) VALUES(?,?,?,?,?)`)
      .run(id, u2, null, "user", now());
  }
  const token = newSession(id);
  res.json({ ok: true, token, user: { id, username, role: "user" } });
});

app.post("/api/auth/register", (req, res) => {
  const username = String(req.body?.username || "").trim().slice(0, 18);
  const password = String(req.body?.password || "");
  if (username.length < 3 || password.length < 6) return res.status(400).json({ ok:false, err:"bad-input" });

  const id = nanoid(24);
  const pass_hash = bcrypt.hashSync(password, 10);
  try {
    db.prepare(`INSERT INTO users(id,username,pass_hash,role,created_at) VALUES(?,?,?,?,?)`)
      .run(id, username, pass_hash, "user", now());
  } catch {
    return res.status(409).json({ ok:false, err:"username-taken" });
  }
  const token = newSession(id);
  res.json({ ok:true, token, user:{ id, username, role:"user" } });
});

app.post("/api/auth/login", (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const u = db.prepare(`SELECT id, username, pass_hash, role FROM users WHERE username=?`).get(username);
  if (!u || !u.pass_hash) return res.status(401).json({ ok:false, err:"bad-cred" });
  if (!bcrypt.compareSync(password, u.pass_hash)) return res.status(401).json({ ok:false, err:"bad-cred" });

  const ban = db.prepare(`SELECT banned_until FROM bans WHERE user_id=?`).get(u.id);
  if (ban && (ban.banned_until == null || ban.banned_until > now())) return res.status(403).json({ ok:false, err:"banned" });

  const token = newSession(u.id);
  res.json({ ok:true, token, user:{ id:u.id, username:u.username, role:u.role } });
});

app.get("/api/me", (req, res) => {
  const me = getAuth(req);
  if (!me) return res.status(401).json({ ok:false });
  res.json({ ok:true, me:{ userId: me.userId, username: me.username, role: me.role } });
});

app.post("/api/room/:room/send", (req, res) => {
  const me = getAuth(req);
  if (!me) return res.status(401).json({ ok:false, err:"no-auth" });

  const room = String(req.params.room || "global");
  const mutedUntil = isMuted(me.userId);
  if (mutedUntil) return res.status(403).json({ ok:false, err:"muted", until: mutedUntil });

  let content = String(req.body?.content || "").trim();
  if (!content) return res.status(400).json({ ok:false, err:"empty" });
  if (content.length > 300) content = content.slice(0, 300);

  // owner commands
  if (content.startsWith("?")) {
    if (me.role !== "owner") return res.json({ ok:true, cmd:true });

    const [cmd, targetRaw, arg2] = content.trim().split(/\s+/);
    const target = targetRaw || "";
    if (!target) return res.json({ ok:true, cmd:true });

    const u = findUser(target);
    if (!u) {
      db.prepare(`INSERT INTO messages(room,user_id,username,content,created_at) VALUES(?,?,?,?,?)`)
        .run(room, "system", "SYSTEM", "Không thấy user.", now());
      broadcast(room, { t: now(), username:"SYSTEM", content:"Không thấy user." });
      return res.json({ ok:true, cmd:true });
    }
    if (u.role === "owner") return res.json({ ok:true, cmd:true });

    if (cmd === "?mute") {
      const sec = Math.max(5, Math.min(7*24*3600, parseInt(arg2 || "60",10) || 60));
      const until = now() + sec*1000;
      db.prepare(`
        INSERT INTO mutes(user_id,muted_until,reason,created_at) VALUES(?,?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET muted_until=excluded.muted_until, reason=excluded.reason
      `).run(u.id, until, "muted", now());

      const msg = `Đã mute ${u.username} ${sec}s.`;
      db.prepare(`INSERT INTO messages(room,user_id,username,content,created_at) VALUES(?,?,?,?,?)`)
        .run(room, "system", "SYSTEM", msg, now());
      broadcast(room, { t: now(), username:"SYSTEM", content: msg });
      return res.json({ ok:true, cmd:true });
    }

    if (cmd === "?unmute") {
      db.prepare(`DELETE FROM mutes WHERE user_id=?`).run(u.id);
      const msg = `Đã unmute ${u.username}.`;
      db.prepare(`INSERT INTO messages(room,user_id,username,content,created_at) VALUES(?,?,?,?,?)`)
        .run(room, "system", "SYSTEM", msg, now());
      broadcast(room, { t: now(), username:"SYSTEM", content: msg });
      return res.json({ ok:true, cmd:true });
    }

    if (cmd === "?ban") {
      const ua = req.headers["user-agent"] || "";
      db.prepare(`
        INSERT INTO bans(user_id,reason,banned_until,ban_ua,created_at) VALUES(?,?,?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason, banned_until=excluded.banned_until, ban_ua=excluded.ban_ua
      `).run(u.id, "banned", null, String(ua).slice(0, 200), now());

      db.prepare(`DELETE FROM sessions WHERE user_id=?`).run(u.id);

      const msg = `Đã ban ${u.username}.`;
      db.prepare(`INSERT INTO messages(room,user_id,username,content,created_at) VALUES(?,?,?,?,?)`)
        .run(room, "system", "SYSTEM", msg, now());
      broadcast(room, { t: now(), username:"SYSTEM", content: msg });
      return res.json({ ok:true, cmd:true });
    }

    if (cmd === "?unban") {
      db.prepare(`DELETE FROM bans WHERE user_id=?`).run(u.id);
      const msg = `Đã unban ${u.username}.`;
      db.prepare(`INSERT INTO messages(room,user_id,username,content,created_at) VALUES(?,?,?,?,?)`)
        .run(room, "system", "SYSTEM", msg, now());
      broadcast(room, { t: now(), username:"SYSTEM", content: msg });
      return res.json({ ok:true, cmd:true });
    }

    return res.json({ ok:true, cmd:true });
  }

  db.prepare(`INSERT INTO messages(room,user_id,username,content,created_at) VALUES(?,?,?,?,?)`)
    .run(room, me.userId, me.username, content, now());

  broadcast(room, { t: now(), username: me.username, content });
  res.json({ ok:true });
});

app.get("/api/room/:room/poll", (req, res) => {
  const me = getAuth(req);
  if (!me) return res.status(401).json({ ok:false, err:"no-auth" });

  const room = String(req.params.room || "global");
  const since = parseInt(String(req.query.since || "0"), 10) || 0;

  const rows = db.prepare(`
    SELECT id, username, content, created_at
    FROM messages
    WHERE room=? AND created_at>?
    ORDER BY created_at ASC
    LIMIT 50
  `).all(room, since);

  const last = rows.length ? rows[rows.length - 1].created_at : since;
  res.json({ ok:true, messages: rows, last });
});

// backup db file (owner)
app.get("/api/owner/download-db", (req, res) => {
  const me = getAuth(req);
  if (!me || me.role !== "owner") return res.status(403).json({ ok:false });

  const p = process.env.DB_PATH || "./data.sqlite";
  if (!fs.existsSync(p)) return res.status(404).json({ ok:false, err:"no-db" });
  res.download(p, "chat_data.sqlite");
});

// restore db file: POST raw base64 (owner)
app.post("/api/owner/upload-db", (req, res) => {
  const me = getAuth(req);
  if (!me || me.role !== "owner") return res.status(403).json({ ok:false });

  const b64 = String(req.body?.b64 || "");
  if (!b64) return res.status(400).json({ ok:false, err:"no-b64" });

  const buf = Buffer.from(b64, "base64");
  const p = process.env.DB_PATH || "./data.sqlite";
  fs.writeFileSync(p, buf);
  res.json({ ok:true, note:"Restart service to use new db." });
});

// static UI
app.use(express.static(path.join(__dirname, "public")));

const PORT = parseInt(process.env.PORT || "10000", 10);
const server = app.listen(PORT, () => console.log("listening", PORT));

// ws server
const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", (ws, req) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const room = (u.searchParams.get("room") || "global").slice(0, 32);
  const token = u.searchParams.get("token") || "";

  // auth token
  const row = db.prepare(`
    SELECT s.user_id as userId, s.expires_at as exp, u.username as username, u.role as role
    FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?
  `).get(token);

  if (!row || row.exp <= now()) {
    try { ws.close(); } catch {}
    return;
  }
  const ban = db.prepare(`SELECT banned_until FROM bans WHERE user_id=?`).get(row.userId);
  if (ban && (ban.banned_until == null || ban.banned_until > now())) {
    try { ws.close(); } catch {}
    return;
  }

  const set = roomSet(room);
  set.add(ws);

  ws.on("close", () => set.delete(ws));
  ws.on("error", () => set.delete(ws));
  ws.on("message", () => {}); // ignore
});
