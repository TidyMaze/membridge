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
  setCookie(c, "oauth_state", state, { httpOnly: true, path: "/", maxAge: 600, sameSite: "Lax" });

  const continuation = c.req.query("continuation");
  if (continuation) {
    setCookie(c, "mcp_continuation", continuation, { httpOnly: true, path: "/", maxAge: 600, sameSite: "Lax" });
  }

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
    signal: AbortSignal.timeout(5000),
  });
  const tokenJson = await tokenRes.json();
  const accessToken = tokenJson.access_token;
  if (!accessToken) return c.json({ error: "github_token_exchange_failed" }, 502);

  const userRes = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "membridge" },
    signal: AbortSignal.timeout(5000),
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

  const continuationId = getCookie(c, "mcp_continuation");
  if (continuationId) {
    setCookie(c, "mcp_continuation", "", { httpOnly: true, path: "/", maxAge: 0, sameSite: "Lax" });

    const [pending] = await sql`
      SELECT * FROM mcp_authorize_requests WHERE id = ${continuationId} AND expires_at > NOW() LIMIT 1
    `;
    if (pending) {
      await sql`DELETE FROM mcp_authorize_requests WHERE id = ${continuationId}`;

      const authCode = randomHex(24);
      await sql`
        INSERT INTO oauth_codes (code, user_id, client_id, redirect_uri, code_challenge, code_challenge_method, expires_at)
        VALUES (${authCode}, ${user.id}, ${pending.client_id}, ${pending.redirect_uri}, ${pending.code_challenge}, ${pending.code_challenge_method}, NOW() + INTERVAL '5 minutes')
      `;

      const redirect = new URL(pending.redirect_uri);
      redirect.searchParams.set("code", authCode);
      if (pending.mcp_state) redirect.searchParams.set("state", pending.mcp_state);
      return c.redirect(redirect.toString());
    }
  }

  const [token] = await sql`
    INSERT INTO done_tokens (raw_key, username) VALUES (${rawKey}, ${username}) RETURNING id
  `;

  const sessionExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
  const [session] = await sql`
    INSERT INTO sessions (user_id, expires_at)
    VALUES (${user.id}, ${sessionExpiresAt})
    RETURNING id
  `;
  setCookie(c, "membridge_session", session.id, {
    httpOnly: true,
    path: "/",
    expires: sessionExpiresAt,
    sameSite: "Lax",
    secure: process.env.NODE_ENV === "production",
  });

  return c.redirect(`/dashboard?token=${token.id}`);
});

auth.post("/auth/logout", async (c) => {
  const sessionId = getCookie(c, "membridge_session");
  if (sessionId) {
    await sql`DELETE FROM sessions WHERE id = ${sessionId}`;
    setCookie(c, "membridge_session", "", { httpOnly: true, path: "/", maxAge: 0, sameSite: "Lax" });
  }
  return c.redirect("https://tidymaze.github.io/membridge/");
});
