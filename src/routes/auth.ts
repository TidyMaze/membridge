import { Hono } from "hono";
import { setCookie, getCookie } from "hono/cookie";
import { sql } from "../db/client";

export const auth = new Hono();

function randomHex(bytes: number) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("hex");
}

async function sha256Hex(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex");
}

auth.get("/auth/github", (c) => {
  const state = randomHex(16);
  setCookie(c, "oauth_state", state, { httpOnly: true, path: "/", maxAge: 600 });
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", process.env.GH_CLIENT_ID!);
  url.searchParams.set("scope", "read:user user:email");
  url.searchParams.set("state", state);
  url.searchParams.set("redirect_uri", `${process.env.BASE_URL}/auth/callback`);
  return c.redirect(url.toString());
});

auth.get("/auth/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  const cookieState = getCookie(c, "oauth_state");
  if (!code || !state || state !== cookieState) {
    return c.json({ error: "invalid_state" }, 400);
  }

  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      client_id: process.env.GH_CLIENT_ID,
      client_secret: process.env.GH_CLIENT_SECRET,
      code,
    }),
  });
  const tokenJson = await tokenRes.json();
  const accessToken = tokenJson.access_token;
  if (!accessToken) return c.json({ error: "github_token_exchange_failed" }, 502);

  const userRes = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "membridge" },
  });
  const ghUser = await userRes.json();
  if (!ghUser?.id) return c.json({ error: "github_user_fetch_failed" }, 502);

  const githubId = String(ghUser.id);
  const username = ghUser.login as string;
  const email = (ghUser.email as string | null) ?? null;

  const [user] = await sql`
    INSERT INTO users (github_id, username, email)
    VALUES (${githubId}, ${username}, ${email})
    ON CONFLICT (github_id) DO UPDATE SET username = EXCLUDED.username, email = EXCLUDED.email
    RETURNING id
  `;

  const rawKey = `mem_${randomHex(32)}`;
  const keyHash = await sha256Hex(rawKey);
  await sql`
    INSERT INTO api_keys (user_id, key_hash) VALUES (${user.id}, ${keyHash})
  `;

  const doneUrl = new URL("/auth/done", process.env.BASE_URL);
  doneUrl.searchParams.set("key", rawKey);
  doneUrl.searchParams.set("user", username);
  return c.redirect(doneUrl.toString());
});

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]!));
}

auth.get("/auth/done", (c) => {
  const key = escapeHtml(c.req.query("key") ?? "");
  const user = escapeHtml(c.req.query("user") ?? "");
  const html = `<!doctype html>
<html><body>
<h1>MemBridge — signed in as ${user}</h1>
<p>Your API key (shown once, save it now):</p>
<pre>${key}</pre>
<p>Run: <code>memory configure ${key}</code></p>
</body></html>`;
  return c.html(html);
});
