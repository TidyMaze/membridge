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

  const continuation = c.req.query("continuation");
  if (continuation) {
    setCookie(c, "mcp_continuation", continuation, { httpOnly: true, path: "/", maxAge: 600 });
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

  const continuationId = getCookie(c, "mcp_continuation");
  if (continuationId) {
    setCookie(c, "mcp_continuation", "", { httpOnly: true, path: "/", maxAge: 0 });

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
  const configCmd = `memb configure ${key}`;
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MemBridge — connected</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0b0d10;
    --bg-soft: #11151a;
    --border: #1f2630;
    --text: #e6edf3;
    --text-dim: #8b97a5;
    --accent: #7c5cff;
    --accent-2: #34e2c4;
    --mono: 'JetBrains Mono', 'Fira Code', monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  html, body {
    height: 100%;
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
  }
  body {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 24px;
  }
  .card {
    width: 100%;
    max-width: 560px;
    background: var(--bg-soft);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 40px;
    box-shadow: 0 40px 100px -40px rgba(124,92,255,0.2);
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 32px;
  }
  .logo .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    box-shadow: 0 0 16px var(--accent);
  }
  .logo span { font-weight: 700; font-size: 1rem; }
  .check-icon {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    background: linear-gradient(135deg, rgba(52,226,196,0.15), rgba(124,92,255,0.15));
    border: 1px solid rgba(52,226,196,0.3);
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 20px;
    font-size: 22px;
  }
  h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 6px; }
  .subtitle { color: var(--text-dim); font-size: 0.92rem; margin-bottom: 32px; }
  .subtitle strong { color: var(--accent-2); }
  .label {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 8px;
  }
  .key-box {
    position: relative;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 24px;
  }
  .key-value {
    font-family: var(--mono);
    font-size: 0.82rem;
    color: var(--accent-2);
    word-break: break-all;
    padding-right: 72px;
    line-height: 1.5;
  }
  .copy-btn {
    position: absolute;
    top: 50%;
    right: 12px;
    transform: translateY(-50%);
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-dim);
    font-size: 0.72rem;
    font-family: var(--mono);
    padding: 4px 10px;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }
  .copy-btn:hover { border-color: var(--accent-2); color: var(--accent-2); }
  .copy-btn.copied { border-color: var(--accent-2); color: var(--accent-2); }
  .cmd-box {
    position: relative;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 28px;
  }
  .cmd-bar {
    background: rgba(31,38,48,0.6);
    border-bottom: 1px solid var(--border);
    padding: 8px 14px;
    font-size: 0.72rem;
    color: var(--text-dim);
    font-family: var(--mono);
  }
  .cmd-body {
    padding: 14px 16px;
    font-family: var(--mono);
    font-size: 0.84rem;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 10px;
    padding-right: 80px;
  }
  .cmd-prompt { color: var(--accent); }
  .cmd-copy {
    position: absolute;
    top: 50%;
    right: 12px;
    transform: translateY(-20%);
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-dim);
    font-size: 0.72rem;
    font-family: var(--mono);
    padding: 4px 10px;
    cursor: pointer;
    transition: all 0.15s;
  }
  .cmd-copy:hover { border-color: var(--accent-2); color: var(--accent-2); }
  .cmd-copy.copied { border-color: var(--accent-2); color: var(--accent-2); }
  .warning {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    background: rgba(255,189,46,0.06);
    border: 1px solid rgba(255,189,46,0.2);
    border-radius: 8px;
    padding: 12px 14px;
    font-size: 0.82rem;
    color: #e8c76a;
    line-height: 1.5;
  }
  .warning-icon { flex-shrink: 0; margin-top: 1px; }
  .footer-link {
    margin-top: 24px;
    text-align: center;
    font-size: 0.8rem;
    color: var(--text-dim);
  }
  .footer-link a { color: var(--accent-2); text-decoration: none; }
  .footer-link a:hover { text-decoration: underline; }
  .logout-btn {
    margin-top: 20px;
    width: 100%;
    padding: 10px;
    background: transparent;
    border: 1px solid rgba(255,80,80,0.25);
    border-radius: 8px;
    color: #ff6b6b;
    font-size: 0.82rem;
    font-family: var(--sans);
    cursor: pointer;
    transition: all 0.15s;
  }
  .logout-btn:hover { background: rgba(255,80,80,0.08); border-color: rgba(255,80,80,0.5); }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="dot"></div>
    <span>MemBridge</span>
  </div>

  <div class="check-icon">&#10003;</div>
  <h1>You're connected</h1>
  <p class="subtitle">Signed in as <strong>${user}</strong>. Save your API key — it won't be shown again.</p>

  <p class="label">API Key</p>
  <div class="key-box">
    <div class="key-value" id="key-val">${key}</div>
    <button class="copy-btn" onclick="copyText('key-val', this)">copy</button>
  </div>

  <p class="label">Configure CLI</p>
  <div class="cmd-box">
    <div class="cmd-bar">terminal</div>
    <div class="cmd-body">
      <span class="cmd-prompt">$</span>
      <span id="cmd-val">${configCmd}</span>
    </div>
    <button class="cmd-copy" onclick="copyText('cmd-val', this)">copy</button>
  </div>

  <div class="warning">
    <span class="warning-icon">&#9888;</span>
    <span>This key is shown <strong>once</strong> and not stored by MemBridge. If lost, generate a new one via <code>memb login</code>.</span>
  </div>

  <form method="POST" action="/auth/revoke" onsubmit="return confirm('Revoke this API key? You will need to login again.')">
    <input type="hidden" name="key" value="${key}">
    <button type="submit" class="logout-btn">Revoke key &amp; logout</button>
  </form>

  <div class="footer-link">
    <a href="https://github.com/yrolland/membridge">GitHub</a> &middot; <a href="/">Docs</a>
  </div>
</div>
<script>
function copyText(id, btn) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 2000);
  });
}
</script>
</body>
</html>`;
  return c.html(html);
});

auth.post("/auth/revoke", async (c) => {
  const body = await c.req.parseBody();
  const key = (body["key"] as string) ?? "";
  if (key) {
    const keyHash = await sha256Hex(key);
    await sql`DELETE FROM api_keys WHERE key_hash = ${keyHash}`;
  }
  return c.redirect("/?revoked=1");
});
