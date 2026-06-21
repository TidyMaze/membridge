import { Hono } from "hono";
import { sql } from "../db/client";

export const oauthMeta = new Hono();

function randomHex(bytes: number) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("hex");
}

async function sha256Hex(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex");
}

function base64UrlSha256(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("base64url");
}

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]!));
}

oauthMeta.get("/.well-known/oauth-protected-resource", (c) => {
  return c.json({
    resource: process.env.BASE_URL,
    authorization_servers: [process.env.BASE_URL],
  });
});

oauthMeta.get("/.well-known/oauth-authorization-server", (c) => {
  const base = process.env.BASE_URL;
  return c.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  });
});

oauthMeta.post("/oauth/register", async (c) => {
  const body = await c.req.json().catch(() => ({}) as Record<string, unknown>);
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];

  const clientId = randomHex(16);
  await sql`
    INSERT INTO oauth_clients (client_id, client_name, redirect_uris)
    VALUES (${clientId}, ${String(body.client_name ?? "")}, ${JSON.stringify(redirectUris)})
  `;

  return c.json(
    {
      client_id: clientId,
      client_name: body.client_name ?? "",
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
    },
    201,
  );
});

oauthMeta.get("/oauth/authorize", async (c) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method } = c.req.query();
  if (!client_id || !redirect_uri || !code_challenge || code_challenge_method !== "S256") {
    return c.json({ error: "invalid_request" }, 400);
  }

  const continuationId = randomHex(16);
  await sql`
    INSERT INTO mcp_authorize_requests (id, client_id, redirect_uri, mcp_state, code_challenge, code_challenge_method, expires_at)
    VALUES (${continuationId}, ${client_id}, ${redirect_uri}, ${state ?? null}, ${code_challenge}, ${code_challenge_method}, NOW() + INTERVAL '10 minutes')
  `;
  const githubUrl = `/auth/github?continuation=${continuationId}`;

  const html = `<!doctype html>
<html><body>
<h1>Authorize MemBridge access for ${escapeHtml(client_id)}</h1>
<p><a href="${githubUrl}"><button type="button">Continue with GitHub</button></a></p>
<p>Already have an API key?</p>
<form method="POST" action="/oauth/authorize">
  <input type="hidden" name="client_id" value="${escapeHtml(client_id)}">
  <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
  <input type="hidden" name="state" value="${escapeHtml(state ?? "")}">
  <input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge)}">
  <input type="hidden" name="code_challenge_method" value="${escapeHtml(code_challenge_method)}">
  <label>API key: <input type="password" name="api_key" required></label>
  <button type="submit">Approve</button>
</form>
</body></html>`;
  return c.html(html);
});

oauthMeta.post("/oauth/authorize", async (c) => {
  const body = await c.req.parseBody();
  const apiKey = String(body.api_key ?? "");
  const clientId = String(body.client_id ?? "");
  const redirectUri = String(body.redirect_uri ?? "");
  const state = String(body.state ?? "");
  const codeChallenge = String(body.code_challenge ?? "");
  const codeChallengeMethod = String(body.code_challenge_method ?? "");

  const keyHash = await sha256Hex(apiKey);
  const [row] = await sql`SELECT user_id FROM api_keys WHERE key_hash = ${keyHash} LIMIT 1`;
  if (!row) return c.json({ error: "invalid_api_key" }, 401);

  const code = randomHex(24);
  await sql`
    INSERT INTO oauth_codes (code, user_id, client_id, redirect_uri, code_challenge, code_challenge_method, expires_at)
    VALUES (${code}, ${row.user_id}, ${clientId}, ${redirectUri}, ${codeChallenge}, ${codeChallengeMethod}, NOW() + INTERVAL '5 minutes')
  `;

  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);
  return c.redirect(redirect.toString());
});

oauthMeta.post("/oauth/token", async (c) => {
  const body = await c.req.parseBody();
  const grantType = String(body.grant_type ?? "");
  const code = String(body.code ?? "");
  const codeVerifier = String(body.code_verifier ?? "");

  if (grantType !== "authorization_code") return c.json({ error: "unsupported_grant_type" }, 400);

  const [row] = await sql`SELECT * FROM oauth_codes WHERE code = ${code} LIMIT 1`;
  if (!row || row.used || new Date(row.expires_at) < new Date()) {
    return c.json({ error: "invalid_grant" }, 400);
  }

  const expectedChallenge = base64UrlSha256(codeVerifier);
  if (expectedChallenge !== row.code_challenge) return c.json({ error: "invalid_grant" }, 400);

  await sql`UPDATE oauth_codes SET used = TRUE WHERE code = ${code}`;

  const rawKey = `mem_${randomHex(32)}`;
  const newKeyHash = await sha256Hex(rawKey);
  await sql`INSERT INTO api_keys (user_id, key_hash, name) VALUES (${row.user_id}, ${newKeyHash}, 'mcp-oauth')`;

  return c.json({ access_token: rawKey, token_type: "bearer" });
});
