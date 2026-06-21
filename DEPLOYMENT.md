# Deployment

## Current production setup

- One VPS (Hetzner) running Docker Compose: `app` (Bun/Hono, built from the repo `Dockerfile`) + `postgres`.
- The `app` container only binds `127.0.0.1:3000` — it is never exposed directly to the internet.
- A **native** Caddy instance on the host (not the Docker-managed `caddy` service from `docker-compose.yml`,
  since this VPS already runs Caddy for other unrelated sites) terminates TLS and reverse-proxies
  `membridge.<domain>` to `127.0.0.1:3000`. Caddy gets free, automatic HTTPS via Let's Encrypt.
- Secrets (`DATABASE_URL`, `GH_CLIENT_ID`, `GH_CLIENT_SECRET`, `BASE_URL`) live only in a `chmod 600` `.env`
  file on the server, never committed.

```
Internet → :443 Caddy (native, host) → 127.0.0.1:3000 app (docker) → postgres (docker, internal network only)
```

### How a deploy actually happens right now

The server doesn't have a git checkout (files were placed there once via `scp`), so the loop is:

```bash
# from a local checkout, after committing + pushing to GitHub
scp src/routes/mcp.ts root@<host>:/opt/membridge/src/routes/mcp.ts
ssh root@<host> "cd /opt/membridge && docker compose up -d --build"
```

This works, but it's manual and easy to get wrong (e.g. scp-ing a file into the wrong directory). It's fine
for a single-maintainer project; it is **not** what you'd want for a team.

## A cleaner alternative: point Docker Compose at the remote host directly

Docker Compose doesn't have to run *on* the server — the Docker CLI can target any remote daemon via
`DOCKER_HOST`, and Compose respects that transparently. This removes the manual `scp` step entirely: the
build context goes straight to the remote daemon over SSH.

```bash
# one-time: register a context that tunnels over SSH
docker context create membridge-prod --docker "host=ssh://deploy@membridge.example.com"
docker context use membridge-prod

# every deploy after that:
docker compose up -d --build
```

Or without switching the default context:

```bash
DOCKER_HOST=ssh://deploy@membridge.example.com docker compose up -d --build
```

Either form builds the image and starts the containers *on the remote host*, using your local
`docker-compose.yml` and `.env` — no manual file copying, no SSH heredocs.

### ⚠️ Use SSH, never an unauthenticated TCP socket

`DOCKER_HOST` also accepts `tcp://host:2375`, but **do not do this** unless it's wrapped in mutual TLS
(`tcp://host:2376` with `--tlsverify`). The plain `2375` TCP socket has no authentication at all — anyone who
can reach that port gets unrestricted root-equivalent control of the host (it's the Docker daemon API, which
can mount the host filesystem into a container). The `ssh://` transport reuses your existing SSH key auth and
is the only form that should be used over the network:

- `ssh://user@host` — safe, uses your SSH keys/agent, no extra config.
- `tcp://host:2376` with TLS client certs — safe, but more setup (cert generation/rotation) than this
  project needs.
- `tcp://host:2375` — **never**. No auth, no encryption, full host compromise if reachable.

If you set this up, also keep the daemon's TCP port (if enabled at all) firewalled to nothing — only the SSH
port needs to be reachable; Compose tunnels everything else through it.
