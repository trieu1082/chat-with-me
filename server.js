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
app.use("/api/", rateLimit({ windowMs: 5000, max: 60 }));

const db = openDB(process.env.DB_PATH || "./data.sqlite");

const now = () => Date.now();
const SESSION_TTL_MS = (parseInt(process.env.SESSION_TTL_SEC || "2592000", 10) || 2592000) * 1000;
const OWNER_USER = process.env.OWNER_USER || "owner";
const OWNER_PASS = process.env.OWNER_PASS || "owner123";

const rooms = new Map();
const spam = new Map(); // userId -> { last, warnedUntil }

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

function rolesEnsure() {
  db.prepare(`INSERT OR IGNORE INTO roles(name,perms,created_at) VALUES(?,?,?)`).run("owner", "ban,mute,pin,addrole,giverole", now());
  db.prepare(`INSERT OR IGNORE INTO roles(name,perms,created_at) VALUES(?,?,?)`).run("admin", "ban,mute", now());
}
function ensureOwner() {
  rolesEnsure();
  let u = db.prepare(`SELECT id FROM users WHERE username=?`).get(OWNER_USER);
  if (!u) {
    const id = nanoid(24);
    const pass_hash = bcrypt.hashSync(OWNER_PASS, 10);
    db.prepare(`INSERT INTO users(id,username,pass_hash,created_at) VALUES(?,?,?,?)`).run(id, OWNER_USER, pass_hash, now());
    u = { id };
  }
  db.prepare(`INSERT OR IGNORE INTO user_roles(user_id,role_name,created_at) VALUES(?,?,?)`).run(u.id, "owner", now());
}
ensureOwner();

function newSession(user_id) {
  const token = nanoid(48);
  db.prepare(`INSERT INTO sessions(token,user_id,expires_at,created_at) VALUES(?,?,?,?)`)
    .run(token, user_id, now() + SESSION_TTL_MS, now());
  return token;
}

function getRolePerms(roleName) {
  const r = db.prepare(`SELECT perms FROM roles WHERE name=?`).get(roleName);
  const perms = new Set((r?.perms || "").split(",").map(s => s.trim()).filter(Boolean));
  return perms;
}

function getUserRoles(userId) {
  const rs = db.prepare(`SELECT role_name FROM user_roles WHERE user_id=?`).all(userId);
  return rs.map(x => x.role_name);
}

function getUserPerms(userId) {
  const roles = getUserRoles(userId);
  const perms = new Set();
  for (const rn of roles) for (const p of getRolePerms(rn)) perms.add(p);
  return { roles, perms };
}

function powerOf(permsSet) {
  const base = permsSet.size;
  const bonus =
    (permsSet.has("pin") ? 10 : 0) +
    (permsSet.has("giverole") ? 20 : 0) +
    (permsSet.has("addrole") ? 20 : 0);
  return base * 5 + bonus;
}

function getAuth(req) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return null;

  const row = db.prepare(`
    SELECT s.user_id as userId, s.expires_at as exp, u.username as username
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

  const { roles, perms } = getUserPerms(row.userId);
  return { token, userId: row.userId, username: row.username, roles, perms, power: powerOf(perms) };
}

function isMuted(userId) {
  const m = db.prepare(`SELECT muted_until FROM mutes WHERE user_id=?`).get(userId);
  return m && m.muted_until > now() ? m.muted_until : 0;
}

function findUser(q) {
  const s = String(q || "").replace(/^@/, "").trim();
  return (
    db.prepare(`SELECT id, username FROM users WHERE id=?`).get(s) ||
    db.prepare(`SELECT id, username FROM users WHERE username=?`).get(s) ||
    null
  );
}

function canAct(actor, targetId) {
  const tPerms = getUserPerms(targetId).perms;
  const tPower = powerOf(tPerms);
  const tIsOwner = getUserRoles(targetId).includes("owner");
  if (tIsOwner) return false;
  return actor.power > tPower;
}

function sys(room, text) {
  const created_at = now();
  const ins = db.prepare(`INSERT INTO messages(room,user_id,username,content,created_at) VALUES(?,?,?,?,?)`)
    .run(room, "system", "SYSTEM", text, created_at);
  broadcast(room, { type: "msg", id: Number(ins.lastInsertRowid), created_at, username: "SYSTEM", content: text });
}

function spamCheck(userId) {
  const t = now();
  const s = spam.get(userId) || { last: 0, warnedUntil: 0 };
  const dt = t - s.last;
  s.last = t;

  if (dt >= 1200) {
    spam.set(userId, s);
    return { ok: true };
  }

  if (s.warnedUntil > t) {
    spam.set(userId, s);
    return { ok: false, punish: "mute" };
  }

  s.warnedUntil = t + 20000;
  spam.set(userId, s);
  return { ok: false, punish: "warn" };
}

app.post("/api/auth/guest", (req, res) => {
  rolesEnsure();

  let username = String(req.body?.username || `Guest${Math.floor(Math.random() * 9000 + 1000)}`).slice(0, 18).trim();
  if (username.length < 3) username = `Guest${Math.floor(Math.random() * 9000 + 1000)}`;

  let deviceId = String(req.body?.deviceId || "").trim();
  if (deviceId.length < 8) deviceId = nanoid(24);

  const dev = db.prepare(`SELECT user_id FROM devices WHERE device_id=?`).get(deviceId);

  if (dev?.user_id) {
    const ban = db.prepare(`SELECT banned_until FROM bans WHERE user_id=?`).get(dev.user_id);
    if (ban && (ban.banned_until == null || ban.banned_until > now())) return res.status(403).json({ ok: false, err: "banned" });

    const u = db.prepare(`SELECT id, username FROM users WHERE id=?`).get(dev.user_id);
    const token = newSession(dev.user_id);
    return res.json({ ok: true, token, deviceId, user: { id: u.id, username: u.username } });
  }

  const id = nanoid(24);
  try {
    db.prepare(`INSERT INTO users(id,username,pass_hash,created_at) VALUES(?,?,?,?)`)
      .run(id, username, null, now());
  } catch {
    username = (username + "_" + Math.floor(Math.random() * 999)).slice(0, 18);
    db.prepare(`INSERT INTO users(id,username,pass_hash,created_at) VALUES(?,?,?,?)`)
      .run(id, username, null, now());
  }

  db.prepare(`INSERT INTO devices(device_id,user_id,created_at) VALUES(?,?,?)`).run(deviceId, id, now());
  const token = newSession(id);
  res.json({ ok: true, token, deviceId, user: { id, username } });
});

app.post("/api/auth/register", (req, res) => {
  const username = String(req.body?.username || "").trim().slice(0, 18);
  const password = String(req.body?.password || "");
  if (username.length < 3 || password.length < 6) return res.status(400).json({ ok: false, err: "bad-input" });

  const id = nanoid(24);
  const pass_hash = bcrypt.hashSync(password, 10);
  try {
    db.prepare(`INSERT INTO users(id,username,pass_hash,created_at) VALUES(?,?,?,?)`)
      .run(id, username, pass_hash, now());
  } catch {
    return res.status(409).json({ ok: false, err: "username-taken" });
  }

  const token = newSession(id);
  res.json({ ok: true, token, user: { id, username } });
});

app.post("/api/auth/login", (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const u = db.prepare(`SELECT id, username, pass_hash FROM users WHERE username=?`).get(username);
  if (!u || !u.pass_hash) return res.status(401).json({ ok: false, err: "bad-cred" });
  if (!bcrypt.compareSync(password, u.pass_hash)) return res.status(401).json({ ok: false, err: "bad-cred" });

  const ban = db.prepare(`SELECT banned_until FROM bans WHERE user_id=?`).get(u.id);
  if (ban && (ban.banned_until == null || ban.banned_until > now())) return res.status(403).json({ ok: false, err: "banned" });

  const token = newSession(u.id);
  res.json({ ok: true, token, user: { id: u.id, username: u.username } });
});

app.get("/api/me", (req, res) => {
  const me = getAuth(req);
  if (!me) return res.status(401).json({ ok: false, err: "no-auth" });
  res.json({ ok: true, me: { userId: me.userId, username: me.username, roles: me.roles, perms: [...me.perms] } });
});

app.get("/api/room/:room/pinned", (req, res) => {
  const me = getAuth(req);
  if (!me) return res.status(401).json({ ok: false, err: "no-auth" });

  const room = String(req.params.room || "global").slice(0, 32);
  const pin = db.prepare(`SELECT room, message_id, content, username, pinned_at FROM pins WHERE room=?`).get(room) || null;
  res.json({ ok: true, pin });
});

function doBan(room, actor, targetId, reason = "banned") {
  if (!actor.perms.has("ban")) return { ok: false, err: "no-perm" };
  if (!canAct(actor, targetId)) return { ok: false, err: "no-power" };
  db.prepare(`INSERT INTO bans(user_id,reason,banned_until,created_at) VALUES(?,?,?,?)
              ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason, banned_until=excluded.banned_until`)
    .run(targetId, reason, null, now());
  db.prepare(`DELETE FROM sessions WHERE user_id=?`).run(targetId);
  return { ok: true };
}

function doMute(room, actor, targetId, sec, reason = "muted") {
  if (!actor.perms.has("mute")) return { ok: false, err: "no-perm" };
  if (!canAct(actor, targetId)) return { ok: false, err: "no-power" };
  const until = now() + sec * 1000;
  db.prepare(`INSERT INTO mutes(user_id,muted_until,reason,created_at) VALUES(?,?,?,?)
              ON CONFLICT(user_id) DO UPDATE SET muted_until=excluded.muted_until, reason=excluded.reason`)
    .run(targetId, until, reason, now());
  return { ok: true, until };
}

app.post("/api/mod/ban", (req, res) => {
  const me = getAuth(req);
  if (!me) return res.status(401).json({ ok: false, err: "no-auth" });

  const room = String(req.body?.room || "global").slice(0, 32);
  const target = String(req.body?.targetId || "").trim();
  if (!target) return res.status(400).json({ ok: false, err: "bad-target" });

  const r = doBan(room, me, target);
  if (!r.ok) return res.status(403).json(r);

  sys(room, `Đã ban ${target}.`);
  res.json({ ok: true });
});

app.post("/api/mod/mute", (req, res) => {
  const me = getAuth(req);
  if (!me) return res.status(401).json({ ok: false, err: "no-auth" });

  const room = String(req.body?.room || "global").slice(0, 32);
  const target = String(req.body?.targetId || "").trim();
  const sec = Math.max(5, Math.min(7 * 24 * 3600, parseInt(req.body?.sec || "60", 10) || 60));
  if (!target) return res.status(400).json({ ok: false, err: "bad-target" });

  const r = doMute(room, me, target, sec);
  if (!r.ok) return res.status(403).json(r);

  sys(room, `Đã mute ${target} ${sec}s.`);
  res.json({ ok: true, until: r.until });
});

app.post("/api/room/:room/send", (req, res) => {
  const me = getAuth(req);
  if (!me) return res.status(401).json({ ok: false, err: "no-auth" });

  const room = String(req.params.room || "global").slice(0, 32);

  const mutedUntil = isMuted(me.userId);
  if (mutedUntil) return res.status(403).json({ ok: false, err: "muted", until: mutedUntil });

  let content = String(req.body?.content || "").trim();
  if (!content) return res.status(400).json({ ok: false, err: "empty" });
  if (content.length > 300) content = content.slice(0, 300);

  if (!content.startsWith("?")) {
    const sc = spamCheck(me.userId);
    if (!sc.ok) {
      if (sc.punish === "warn") return res.status(429).json({ ok: false, err: "slow", msg: "Đừng spam. Lần nữa ăn mute 15p." });
      if (sc.punish === "mute") {
        db.prepare(`INSERT INTO mutes(user_id,muted_until,reason,created_at) VALUES(?,?,?,?)
                    ON CONFLICT(user_id) DO UPDATE SET muted_until=excluded.muted_until, reason=excluded.reason`)
          .run(me.userId, now() + 15 * 60 * 1000, "spam", now());
        return res.status(403).json({ ok: false, err: "muted", until: now() + 15 * 60 * 1000 });
      }
    }
  }

  if (content.startsWith("?")) {
    const parts = content.trim().split(/\s+/);
    const cmd = (parts[0] || "").toLowerCase();
    const a1 = parts[1] || "";
    const a2 = parts[2] || "";

    if (cmd === "?pin") {
      if (!me.perms.has("pin")) return res.status(403).json({ ok: false, err: "no-perm" });
      const id = parseInt(a1 || "0", 10);
      if (!id) return res.json({ ok: true, cmd: true });

      const m = db.prepare(`SELECT id, username, content FROM messages WHERE room=? AND id=?`).get(room, id);
      if (!m) return res.json({ ok: true, cmd: true });

      const p = { room, message_id: m.id, content: m.content, username: m.username, pinned_at: now() };
      db.prepare(`INSERT INTO pins(room,message_id,content,username,pinned_at) VALUES(?,?,?,?,?)
                  ON CONFLICT(room) DO UPDATE SET message_id=excluded.message_id,content=excluded.content,username=excluded.username,pinned_at=excluded.pinned_at`)
        .run(p.room, p.message_id, p.content, p.username, p.pinned_at);

      broadcast(room, { type: "pin", pin: p });
      return res.json({ ok: true, cmd: true });
    }

    if (cmd === "?unpin") {
      if (!me.perms.has("pin")) return res.status(403).json({ ok: false, err: "no-perm" });
      db.prepare(`DELETE FROM pins WHERE room=?`).run(room);
      broadcast(room, { type: "pin", pin: null });
      return res.json({ ok: true, cmd: true });
    }

    if (cmd === "?addrole") {
      if (!me.perms.has("addrole")) return res.status(403).json({ ok: false, err: "no-perm" });
      const role = String(a1 || "").toLowerCase();
      const perms = parts.slice(2).map(x => x.toLowerCase()).filter(Boolean);
      if (!role || role.length < 2 || perms.length === 0) return res.json({ ok: true, cmd: true });
      if (role === "owner") return res.json({ ok: true, cmd: true });

      db.prepare(`INSERT INTO roles(name,perms,created_at) VALUES(?,?,?)
                  ON CONFLICT(name) DO UPDATE SET perms=excluded.perms`)
        .run(role, perms.join(","), now());

      sys(room, `Role ${role} = ${perms.join(",")}`);
      return res.json({ ok: true, cmd: true });
    }

    if (cmd === "?giverole") {
      if (!me.perms.has("giverole")) return res.status(403).json({ ok: false, err: "no-perm" });
      const u = findUser(a1);
      const role = String(a2 || "").toLowerCase();
      if (!u || !role) return res.json({ ok: true, cmd: true });

      const r = db.prepare(`SELECT name FROM roles WHERE name=?`).get(role);
      if (!r) return res.json({ ok: true, cmd: true });
      if (role === "owner" && !me.roles.includes("owner")) return res.json({ ok: true, cmd: true });

      const targetPerms = getUserPerms(u.id).perms;
      const targetPower = powerOf(targetPerms);
      if (targetPower >= me.power && !me.roles.includes("owner")) return res.json({ ok: true, cmd: true });

      db.prepare(`INSERT OR IGNORE INTO user_roles(user_id,role_name,created_at) VALUES(?,?,?)`).run(u.id, role, now());
      sys(room, `Đã cấp role ${role} cho ${u.username}.`);
      return res.json({ ok: true, cmd: true });
    }

    if (cmd === "?ban") {
      const u = findUser(a1);
      if (!u) return res.json({ ok: true, cmd: true });
      const r = doBan(room, me, u.id);
      if (!r.ok) return res.status(403).json(r);
      sys(room, `Đã ban ${u.username}.`);
      return res.json({ ok: true, cmd: true });
    }

    if (cmd === "?mute") {
      const u = findUser(a1);
      const sec = Math.max(5, Math.min(7 * 24 * 3600, parseInt(a2 || "60", 10) || 60));
      if (!u) return res.json({ ok: true, cmd: true });
      const r = doMute(room, me, u.id, sec);
      if (!r.ok) return res.status(403).json(r);
      sys(room, `Đã mute ${u.username} ${sec}s.`);
      return res.json({ ok: true, cmd: true });
    }

    if (cmd === "?unmute") {
      const u = findUser(a1);
      if (!me.perms.has("mute")) return res.status(403).json({ ok: false, err: "no-perm" });
      if (!u) return res.json({ ok: true, cmd: true });
      if (!canAct(me, u.id)) return res.status(403).json({ ok: false, err: "no-power" });
      db.prepare(`DELETE FROM mutes WHERE user_id=?`).run(u.id);
      sys(room, `Đã unmute ${u.username}.`);
      return res.json({ ok: true, cmd: true });
    }

    if (cmd === "?unban") {
      const u = findUser(a1);
      if (!me.perms.has("ban")) return res.status(403).json({ ok: false, err: "no-perm" });
      if (!u) return res.json({ ok: true, cmd: true });
      if (!canAct(me, u.id)) return res.status(403).json({ ok: false, err: "no-power" });
      db.prepare(`DELETE FROM bans WHERE user_id=?`).run(u.id);
      sys(room, `Đã unban ${u.username}.`);
      return res.json({ ok: true, cmd: true });
    }

    return res.json({ ok: true, cmd: true });
  }

  const created_at = now();
  const ins = db.prepare(`INSERT INTO messages(room,user_id,username,content,created_at) VALUES(?,?,?,?,?)`)
    .run(room, me.userId, me.username, content, created_at);

  const id = Number(ins.lastInsertRowid);
  broadcast(room, { type: "msg", id, created_at, user_id: me.userId, username: me.username, content });
  res.json({ ok: true, id });
});

app.get("/api/room/:room/poll", (req, res) => {
  const me = getAuth(req);
  if (!me) return res.status(401).json({ ok: false, err: "no-auth" });

  const room = String(req.params.room || "global").slice(0, 32);
  const since = parseInt(String(req.query.since || "0"), 10) || 0;

  const rows = db.prepare(`
    SELECT id, user_id, username, content, created_at
    FROM messages
    WHERE room=? AND created_at>?
    ORDER BY created_at ASC
    LIMIT 50
  `).all(room, since);

  const last = rows.length ? rows[rows.length - 1].created_at : since;
  res.json({ ok: true, messages: rows, last });
});

app.get("/api/owner/download-db", (req, res) => {
  const me = getAuth(req);
  if (!me || !me.roles.includes("owner")) return res.status(403).json({ ok: false, err: "no-perm" });

  const p = process.env.DB_PATH || "./data.sqlite";
  if (!fs.existsSync(p)) return res.status(404).json({ ok: false, err: "no-db" });
  res.download(p, "chat_data.sqlite");
});

app.use(express.static(path.join(__dirname, "public")));

const PORT = parseInt(process.env.PORT || "10000", 10);
const server = app.listen(PORT);

const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", (ws, req) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const room = (u.searchParams.get("room") || "global").slice(0, 32);
  const token = u.searchParams.get("token") || "";

  const row = db.prepare(`SELECT user_id, expires_at FROM sessions WHERE token=?`).get(token);
  if (!row || row.expires_at <= now()) { try { ws.close(); } catch {} return; }

  const ban = db.prepare(`SELECT banned_until FROM bans WHERE user_id=?`).get(row.user_id);
  if (ban && (ban.banned_until == null || ban.banned_until > now())) { try { ws.close(); } catch {} return; }

  const set = roomSet(room);
  set.add(ws);
  ws.on("close", () => set.delete(ws));
  ws.on("error", () => set.delete(ws));
  ws.on("message", () => {});
});
