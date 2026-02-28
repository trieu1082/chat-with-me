import Database from "better-sqlite3";

export function openDB(path = process.env.DB_PATH || "./data.sqlite") {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS users(
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pass_hash TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS devices(
      device_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bans(
      user_id TEXT PRIMARY KEY,
      reason TEXT,
      banned_until INTEGER,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS mutes(
      user_id TEXT PRIMARY KEY,
      muted_until INTEGER NOT NULL,
      reason TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS pins(
      room TEXT PRIMARY KEY,
      message_id INTEGER,
      content TEXT,
      username TEXT,
      pinned_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS roles(
      name TEXT PRIMARY KEY,
      perms TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_roles(
      user_id TEXT NOT NULL,
      role_name TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, role_name)
    );

    CREATE INDEX IF NOT EXISTS idx_msg_room_time ON messages(room, created_at);
    CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
  `);
  return db;
}
