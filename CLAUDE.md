# MemBridge — project spec

## What
SaaS that bridges memory between Claude Code (local) and Claude.ai (web).
One encrypted context file per user, synced bidirectionally via CLI + MCP.

## Core flow
1. User signs up via GitHub OAuth → receives API key (shown once)
2. Claude Code session ends → hook runs `memory push` → encrypts locally → uploads ciphertext
3. Claude.ai web → connects MCP server → decrypts in memory → reads context
4. User runs `memory pull` → downloads + decrypts locally

## Server never sees plaintext. Ever.

## Stack
- Runtime: Bun
- Framework: Hono
- DB: Postgres 16 + pgcrypto extension
- Auth: GitHub OAuth 2.0 → UUID API key (sha256 hashed in DB)
- Encryption: age (client-side, E2E)
- CLI: bash script (curl + age, zero npm deps)
- MCP: Hono route, SSE transport, OAuth 2.1 PKCE
- Deploy: Docker Compose + Caddy on Hetzner VPS

## Repo structure
```
membridge/
├── src/
│   ├── index.ts              # Hono app entry, port from env
│   ├── routes/
│   │   ├── auth.ts           # GitHub OAuth + /auth/done
│   │   ├── context.ts        # push/pull ciphertext
│   │   ├── mcp.ts            # MCP endpoint (SSE)
│   │   └── oauth-meta.ts     # /.well-known/* for MCP OAuth
│   ├── middleware/
│   │   ├── auth.ts           # Bearer key → userId
│   │   └── ratelimit.ts      # Postgres row count, 100 req/hr
│   └── db/
│       ├── client.ts         # postgres npm client, pool 10
│       └── schema.sql        # all tables
├── cli/
│   └── memory.sh             # bash CLI
├── docker-compose.yml
├── Caddyfile
└── .env.example
```

## Database schema
```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  github_id  TEXT UNIQUE NOT NULL,
  username   TEXT NOT NULL,
  email      TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE api_keys (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
  key_hash   TEXT UNIQUE NOT NULL,
  name       TEXT DEFAULT 'default',
  last_used  TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE contexts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  ciphertext  BYTEA NOT NULL,
  size_bytes  INT,
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE rate_limits (
  user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
  window_start TIMESTAMPTZ NOT NULL,
  count        INT DEFAULT 1,
  PRIMARY KEY  (user_id, window_start)
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_rate_limits_user ON rate_limits(user_id, window_start);
```

## API routes

### Auth
```
GET /auth/github
  → redirect to github.com/login/oauth/authorize
  → params: client_id, scope=read:user user:email, state=random16hex
  → set HttpOnly cookie: oauth_state=<state>

GET /auth/callback?code=&state=
  → validate state vs cookie
  → POST github.com/login/oauth/access_token → get access_token
  → GET api.github.com/user → get github_id, login, email
  → upsert users table
  → generate raw key: `mem_` + 32 random bytes hex
  → store sha256(raw_key) in api_keys
  → redirect /auth/done?key=<raw>&user=<username>

GET /auth/done?key=&user=
  → return plain HTML showing key once
  → instruction: "run: memory configure <key>"
  → no JS, no framework
```

### Context
```
POST /api/context
  headers: Authorization: Bearer <key>
  body:    raw bytes (age ciphertext)
  limits:  500KB max
  → auth middleware → get userId
  → rate limit check (100/hr)
  → upsert contexts table (ciphertext, size_bytes, updated_at)
  → 200 {ok: true}

GET /api/context
  headers: Authorization: Bearer <key>
  → auth middleware → get userId
  → fetch ciphertext from contexts
  → 404 if not found
  → 200 Content-Type: application/octet-stream, raw bytes
```

### MCP
```
GET /mcp (SSE transport)
  headers:
    Authorization: Bearer <key>     # API key auth
    X-Age-Key: <age-secret-key>     # decryption key, never stored
  → validate API key → get userId
  → fetch ciphertext
  → decrypt in memory using X-Age-Key
  → expose MCP tools:
      get_context()    → returns plaintext markdown
      add_note(text)   → appends to ## Notes section, re-encrypts, stores
      search(query)    → ripgrep-style search in plaintext

GET /.well-known/oauth-protected-resource
  → returns JSON per RFC 9396
  → authorization_servers: [BASE_URL]

GET /.well-known/oauth-authorization-server
  → returns OAuth 2.1 server metadata
  → authorization_endpoint: /oauth/authorize
  → token_endpoint: /oauth/token
  → code_challenge_methods_supported: [S256]

GET /oauth/authorize?client_id=&redirect_uri=&state=&code_challenge=&code_challenge_method=S256
  → if user not logged in: redirect /auth/github (passing through)
  → if logged in: show consent screen
  → on approve: redirect to redirect_uri with code=<random> + state

POST /oauth/token
  body: grant_type=authorization_code, code=, code_verifier=
  → validate PKCE: sha256(code_verifier) == code_challenge stored
  → return {access_token, token_type: bearer}
  → access_token = API key (reuse same system)
```

### Auth middleware
```
Input:  Authorization: Bearer <raw_key>
Steps:
  1. strip "Bearer "
  2. sha256(raw_key) → hash
  3. SELECT user_id FROM api_keys WHERE key_hash = hash LIMIT 1
  4. if not found → 401
  5. fire-and-forget: UPDATE api_keys SET last_used = NOW()
  6. c.set('userId', user_id)
```

### Rate limit middleware
```
Input:  userId from context
Steps:
  1. window_start = date_trunc('hour', NOW())
  2. INSERT INTO rate_limits (user_id, window_start, count)
     VALUES (userId, window_start, 1)
     ON CONFLICT (user_id, window_start)
     DO UPDATE SET count = rate_limits.count + 1
     RETURNING count
  3. if count > 100 → 429 {error: rate_limited}
  4. else → next()
```

## Context format (plaintext, before encryption)
```markdown
## Rules
- Use Resource[IO] not try-finally
- Kafka: sync commit on partition revoke

## Decisions
- 2025-06-20: chose fs2-kafka over Alpakka

## Notes
- catalog stats: trigger-side > stream-side
- iAgo RAG: Recall@5 at 40%, needs temporal boosting
```
3 sections, fixed headers. `add_note` appends to `## Notes`. Push replaces entire file.

## CLI (memory.sh)
```bash
# commands:
memory configure <api_key>   # saves key + endpoint to ~/.memory/config
memory login                 # opens browser → OAuth flow
memory push                  # encrypt local file → POST /api/context
memory pull                  # GET /api/context → decrypt → write local file
memory edit                  # $EDITOR ~/.memory/context.md then push
memory status                # show last sync time + remote updated_at

# config file: ~/.memory/config
MEMORY_KEY=mem_xxx
MEMORY_ENDPOINT=https://yourdomain.com
MEMORY_AGE_KEY=~/.memory/key.txt    # age private key path

# local file: ~/.memory/context.md (plaintext, only on user's machine)

# push flow:
#   1. read ~/.memory/context.md
#   2. age -R <pubkey from key.txt> context.md | curl -X POST /api/context
#      (encrypt with own public key so only private key can decrypt)

# pull flow:
#   1. curl GET /api/context → /tmp/membridge.age
#   2. age -d -i ~/.memory/key.txt /tmp/membridge.age > ~/.memory/context.md
#   3. rm /tmp/membridge.age

# deps: curl, age (apt install age / brew install age)
```

## Claude Code hook (auto-push)
```json
// .claude/settings.json (user's project)
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "memory push --silent" }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          { "type": "command", "command": "memory push --silent 2>/dev/null || true" }
        ]
      }
    ]
  }
}
```

## Docker Compose
```yaml
services:
  app:
    build: .
    restart: unless-stopped
    env_file: .env
    networks: [caddy, internal]
    labels:
      caddy: yourdomain.com
      caddy.reverse_proxy: "{{upstreams 3000}}"
    depends_on: [postgres]

  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    env_file: .env
    volumes: [pgdata:/var/lib/postgresql/data]
    networks: [internal]

networks:
  caddy:
    external: true
  internal:

volumes:
  pgdata:
```

## Dockerfile
```dockerfile
FROM oven/bun:1-alpine
WORKDIR /app
COPY package.json bun.lockb ./
RUN bun install --frozen-lockfile --production
COPY src/ ./src/
EXPOSE 3000
CMD ["bun", "run", "src/index.ts"]
```

## .env.example
```bash
# Postgres
DATABASE_URL=postgres://membridge:password@postgres:5432/membridge
POSTGRES_USER=membridge
POSTGRES_PASSWORD=password
POSTGRES_DB=membridge

# GitHub OAuth
GH_CLIENT_ID=
GH_CLIENT_SECRET=

# App
BASE_URL=https://yourdomain.com
PORT=3000
NODE_ENV=production
```

## Constraints
- Bun native APIs only (no Node crypto — use Bun.CryptoHasher or Web Crypto)
- No ORMs. Raw SQL via postgres npm package only.
- No session storage. Stateless API key auth on every request.
- No frontend framework. /auth/done = plain HTML string in route handler.
- age encryption happens CLI-side only. Server receives/returns raw bytes.
- MCP decryption: call age binary as subprocess (Bun.spawn). Key from header, never logged.
- All errors: {error: string} JSON, correct HTTP status.
- No console.log in production (use Hono logger middleware only).
- Rate limit table: prune rows older than 2 hours via DELETE in same transaction.
- 500KB context size limit enforced server-side.
- CORS: allow * on /api/* and /mcp only.

## Acceptance criteria
- D1: schema applied, /health 200, GitHub OAuth round-trip works, key stored hashed
- D2: POST /api/context stores bytes, GET returns bytes, auth middleware rejects bad keys
- D3: rate limiting works (101st req → 429), pruning works
- D4: MCP /mcp SSE connects, get_context decrypts + returns, add_note works
- D5: OAuth 2.1 /.well-known routes return valid JSON, authorize/token flow works
- D6: CLI memory.sh push/pull round-trip works end-to-end with real age encryption
- D7: Docker Compose up → all services healthy, Caddy TLS, Claude.ai MCP connector works
