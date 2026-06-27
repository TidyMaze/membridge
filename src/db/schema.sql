CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  github_id  TEXT UNIQUE NOT NULL,
  username   TEXT NOT NULL,
  email      TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
  key_hash   TEXT UNIQUE NOT NULL,
  name       TEXT DEFAULT 'default',
  last_used  TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS contexts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  ciphertext  BYTEA NOT NULL,
  size_bytes  INT,
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rate_limits (
  user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
  window_start TIMESTAMPTZ NOT NULL,
  count        INT DEFAULT 1,
  PRIMARY KEY  (user_id, window_start)
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code                  TEXT PRIMARY KEY,
  user_id               UUID REFERENCES users(id) ON DELETE CASCADE,
  client_id             TEXT NOT NULL,
  redirect_uri          TEXT NOT NULL,
  code_challenge        TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  used                  BOOLEAN DEFAULT FALSE,
  expires_at            TIMESTAMPTZ NOT NULL,
  created_at            TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id     TEXT PRIMARY KEY,
  client_name   TEXT,
  redirect_uris JSONB NOT NULL DEFAULT '[]',
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mcp_authorize_requests (
  id                    TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  redirect_uri          TEXT NOT NULL,
  mcp_state             TEXT,
  code_challenge        TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  expires_at            TIMESTAMPTZ NOT NULL,
  created_at            TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS done_tokens (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  raw_key    TEXT NOT NULL,
  username   TEXT NOT NULL,
  expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '2 minutes'
);

CREATE TABLE IF NOT EXISTS sessions (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event      TEXT NOT NULL,
  ip         TEXT,
  user_id    UUID,
  detail     TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_rate_limits_user ON rate_limits(user_id, window_start);
CREATE INDEX IF NOT EXISTS idx_audit_log_event ON audit_log(event, created_at DESC);
