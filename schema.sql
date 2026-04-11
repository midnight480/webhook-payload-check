-- ===================================================
-- Webhook Payload Check — D1 Schema
-- ===================================================

-- 認証ユーザー管理
CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at   TEXT DEFAULT (datetime('now')),
  updated_at   TEXT DEFAULT (datetime('now'))
);

-- セッション管理（SESSION_SECRET不要、DBで管理）
CREATE TABLE IF NOT EXISTS sessions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  session_token TEXT NOT NULL UNIQUE,
  username      TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  created_at    TEXT DEFAULT (datetime('now'))
);

-- Webhookエンドポイントトークン（払い出したURL管理）
CREATE TABLE IF NOT EXISTS tokens (
  id         TEXT PRIMARY KEY,       -- UUID
  name       TEXT NOT NULL DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
);

-- 受信Webhookデータ
CREATE TABLE IF NOT EXISTS payloads (
  id         TEXT PRIMARY KEY,       -- UUID
  token_id   TEXT NOT NULL,
  method     TEXT NOT NULL,
  url        TEXT NOT NULL,
  headers    TEXT NOT NULL,          -- JSON文字列
  body       TEXT,
  query      TEXT,                   -- JSON文字列
  ip         TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_payloads_token_id   ON payloads(token_id);
CREATE INDEX IF NOT EXISTS idx_payloads_created_at ON payloads(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_token      ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires    ON sessions(expires_at);
