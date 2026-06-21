# MemBridge

Encrypted memory bridge between Claude Code (local) and Claude.ai (web), exposed as an MCP server.

The bash CLI (`push`/`pull`) is genuinely end-to-end encrypted — your age key never leaves your machine.
MCP tool calls (used by both Claude Code and Claude.ai web) send the key as a call argument over TLS so the
server can decrypt on your behalf; this is necessary because Claude.ai web has no local shell to run `age`
itself. The key is never persisted server-side, but for MCP calls it is *not* zero-knowledge.

- 🌐 Landing page / overview: https://tidymaze.github.io/membridge/
- 🚀 Deployment guide: [DEPLOYMENT.md](./DEPLOYMENT.md)
- 📋 Full spec: [CLAUDE.md](./CLAUDE.md)

## Quickstart

```bash
cp .env.example .env   # set GH_CLIENT_ID / GH_CLIENT_SECRET / BASE_URL
docker compose up -d --build
curl http://localhost:3000/health
```

## Tests

```bash
bun run test
```
