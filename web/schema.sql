-- What the server knows about a secret. There is no IP address and no creation time on
-- purpose, and the only thing related to the key is a hash of a value derived from it.
CREATE TABLE IF NOT EXISTS secrets (
  id         TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  iv         TEXT NOT NULL,
  ct         TEXT NOT NULL,
  salt       TEXT,
  pw         INTEGER NOT NULL,
  size       INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS secrets_expires_at ON secrets (expires_at);

-- Bytes in use, so a flood fails cleanly instead of filling the database.
CREATE TABLE IF NOT EXISTS usage (
  id    INTEGER PRIMARY KEY CHECK (id = 1),
  bytes INTEGER NOT NULL,
  large INTEGER NOT NULL
);
INSERT OR IGNORE INTO usage (id, bytes, large) VALUES (1, 0, 0);

-- Daily counts only. Nothing per person.
CREATE TABLE IF NOT EXISTS daily (
  day     TEXT PRIMARY KEY,
  created INTEGER NOT NULL DEFAULT 0,
  opened  INTEGER NOT NULL DEFAULT 0,
  tool_loads INTEGER NOT NULL DEFAULT 0
);
