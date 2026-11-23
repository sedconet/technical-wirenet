'use strict';
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const dataDir = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });

const db = new Database(path.join(dataDir, 'technical.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id              INTEGER PRIMARY KEY,
  username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name    TEXT NOT NULL,
  password_hash   TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('admin','editor','viewer')),
  totp_secret_enc TEXT,
  totp_last_step  INTEGER DEFAULT 0,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until    INTEGER NOT NULL DEFAULT 0,
  disabled        INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  last_login_at   INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash      TEXT PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stage        TEXT NOT NULL CHECK (stage IN ('mfa','enroll','full')),
  csrf_token   TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  ip           TEXT,
  user_agent   TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
  id            INTEGER PRIMARY KEY,
  title         TEXT NOT NULL,
  category      TEXT NOT NULL,
  client        TEXT,
  show_client   INTEGER NOT NULL DEFAULT 0,
  location      TEXT,
  summary       TEXT NOT NULL,
  technologies  TEXT,
  completed_on  TEXT NOT NULL,
  published     INTEGER NOT NULL DEFAULT 1,
  created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_completed ON tasks(completed_on DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id       INTEGER PRIMARY KEY,
  at       INTEGER NOT NULL,
  user_id  INTEGER,
  username TEXT,
  action   TEXT NOT NULL,
  detail   TEXT,
  ip       TEXT
);
`);

function audit(req, action, detail, user) {
  const u = user || (req && req.user) || {};
  db.prepare('INSERT INTO audit_log (at,user_id,username,action,detail,ip) VALUES (?,?,?,?,?,?)')
    .run(Date.now(), u.id || null, u.username || null, action, detail ? String(detail).slice(0, 500) : null, req ? req.ip : null);
}

module.exports = { db, audit };
