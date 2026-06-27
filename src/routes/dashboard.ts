import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { sql } from "../db/client";

export const dashboard = new Hono();

function randomHex(bytes: number) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("hex");
}

async function sha256Hex(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex");
}

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]!));
}

dashboard.get("/dashboard", async (c) => {
  const tokenId = c.req.query("token");
  let userId: string | null = null;
  let newRawKey: string | null = null;
  let loggedInUsername: string | null = null;
  let loggedInGithubId: string | null = null;

  if (tokenId) {
    const [doneToken] = await sql`
      DELETE FROM done_tokens WHERE id = ${tokenId} AND expires_at > NOW() RETURNING raw_key, username
    `;
    if (doneToken) {
      newRawKey = doneToken.raw_key as string;
      const keyHash = await sha256Hex(newRawKey);
      const [apiKey] = await sql`
        SELECT user_id FROM api_keys WHERE key_hash = ${keyHash} LIMIT 1
      `;
      if (apiKey) {
        userId = apiKey.user_id as string;
        
        // Fetch user info
        const [user] = await sql`
          SELECT username, github_id FROM users WHERE id = ${userId} LIMIT 1
        `;
        if (user) {
          loggedInUsername = user.username as string;
          loggedInGithubId = user.github_id as string;

          // Set session cookie
          const sessionExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
          const [session] = await sql`
            INSERT INTO sessions (user_id, expires_at)
            VALUES (${userId}, ${sessionExpiresAt})
            RETURNING id
          `;
          setCookie(c, "membridge_session", session.id as string, {
            httpOnly: true,
            path: "/",
            expires: sessionExpiresAt,
            sameSite: "Lax",
            secure: process.env.NODE_ENV === "production",
          });
        }
      }
    } else {
      // Token provided but invalid/expired
      return c.redirect("/auth/github");
    }
  }

  if (!userId) {
    const sessionId = getCookie(c, "membridge_session");
    if (!sessionId) {
      return c.redirect("/auth/github");
    }
    const [session] = await sql`
      SELECT s.user_id, u.username, u.github_id FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.id = ${sessionId} AND s.expires_at > NOW() LIMIT 1
    `;
    if (!session) {
      return c.redirect("/auth/github");
    }
    userId = session.user_id as string;
    loggedInUsername = session.username as string;
    loggedInGithubId = session.github_id as string;
  }

  // Admin authorization checks
  const adminGithubId = process.env.ADMIN_GITHUB_ID;
  const adminUsername = process.env.ADMIN_USERNAME;
  const hasAdminRestriction = adminGithubId || adminUsername;
  
  const isUserAdmin = 
    (adminGithubId && loggedInGithubId === adminGithubId) ||
    (adminUsername && loggedInUsername === adminUsername);

  if (hasAdminRestriction && !isUserAdmin) {
    return c.text("Forbidden", 403);
  }

  // CSRF token generation
  const csrfToken = randomHex(16);
  setCookie(c, "csrf_token", csrfToken, {
    httpOnly: true,
    path: "/",
    maxAge: 600,
    sameSite: "Lax",
    secure: process.env.NODE_ENV === "production",
  });

  // Fetch API keys
  const keys = await sql`
    SELECT id, name, created_at, last_used FROM api_keys
    WHERE user_id = ${userId}
    ORDER BY created_at DESC
  `;

  // Fetch context sync details
  const [ctx] = await sql`
    SELECT size_bytes, updated_at FROM contexts
    WHERE user_id = ${userId} LIMIT 1
  `;

  // Render components
  let newKeyAlertHtml = "";
  if (newRawKey) {
    newKeyAlertHtml = `
      <div class="alert-box">
        <div class="alert-title">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"></path><path d="m9 12 2 2 4-4"></path></svg>
          Your new API Key has been generated!
        </div>
        <div class="alert-desc">Copy this key now. It will never be shown to you again.</div>
        <div class="key-display">
          <span style="user-select: all;">${escapeHtml(newRawKey)}</span>
          <button class="copy-btn" onclick="copyKey(this, '${escapeHtml(newRawKey)}')">Copy Key</button>
        </div>
        <div class="cmd-box">memb configure ${escapeHtml(newRawKey)}</div>
      </div>
    `;
  }

  let statusClass = "status-inactive";
  let statusText = "Not Synced";
  let lastSyncTime = "Never";
  let contextSize = "0 bytes";

  if (ctx) {
    statusClass = "status-active";
    statusText = "Synchronized";
    lastSyncTime = new Date(ctx.updated_at as string).toLocaleString();
    const bytes = Number(ctx.size_bytes);
    contextSize = bytes >= 1024 ? `${(bytes / 1024).toFixed(2)} KB` : `${bytes} bytes`;
  }

  let keysRowsHtml = "";
  if (keys.length > 0) {
    keysRowsHtml = keys
      .map(
        (key) => `
      <tr>
        <td class="mono-val">${escapeHtml(key.name as string)}</td>
        <td>${new Date(key.created_at as string).toLocaleDateString()}</td>
        <td>${key.last_used ? new Date(key.last_used as string).toLocaleString() : "Never"}</td>
        <td style="text-align: right;">
          <form action="/dashboard/key/revoke" method="POST" style="display:inline;" onsubmit="return confirm('Revoke this key? All devices using it will be logged out.');">
            <input type="hidden" name="csrf_token" value="${csrfToken}">
            <input type="hidden" name="id" value="${key.id}">
            <button type="submit" class="btn btn-sm btn-danger">Revoke</button>
          </form>
        </td>
      </tr>
    `
      )
      .join("");
  } else {
    keysRowsHtml = `<tr><td colspan="4" style="text-align:center; color:var(--text-dim);">No active keys. Generate one above.</td></tr>`;
  }

  // Admin Section rendering
  let adminSectionHtml = "";
  // Since we already did 403 checks, if we reach here we are either admin or there is no restriction.
  // We can show the system metrics and audit logs.
  const [usersCountRow] = await sql`SELECT count(*) FROM users`;
  const [contextsCountRow] = await sql`SELECT count(*) FROM contexts`;
  const [activeKeysRow] = await sql`SELECT count(*) FROM api_keys WHERE last_used > NOW() - INTERVAL '24 hours'`;

  const logs = await sql`
    SELECT a.event, a.ip, a.detail, a.created_at, u.username
    FROM audit_log a
    LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.created_at DESC
    LIMIT 50
  `;

  let auditRowsHtml = "";
  if (logs.length > 0) {
    auditRowsHtml = logs
      .map((log) => {
        let logClass = "";
        const event = String(log.event);
        if (event.includes("failed") || event.includes("failure") || event.includes("error")) {
          logClass = "auth_fail";
        } else if (event.includes("exceeded") || event.includes("limit")) {
          logClass = "ratelimit";
        } else {
          logClass = "success";
        }

        return `
        <tr>
          <td class="mono-val log-event ${logClass}">${escapeHtml(event)}</td>
          <td>${log.username ? escapeHtml(log.username as string) : "System/Guest"}</td>
          <td>${escapeHtml((log.ip as string) || "N/A")}</td>
          <td>${escapeHtml((log.detail as string) || "")}</td>
          <td>${new Date(log.created_at as string).toLocaleString()}</td>
        </tr>
      `;
      })
      .join("");
  } else {
    auditRowsHtml = `<tr><td colspan="5" style="text-align:center; color:var(--text-dim);">No audit logs.</td></tr>`;
  }

  adminSectionHtml = `
    <hr>
    <div style="font-size: 1.1rem; font-weight: 600; color: var(--text-dim); margin-bottom: 15px;">System Metrics</div>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-count">${usersCountRow.count}</div>
        <div class="stat-label">Total Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-count">${contextsCountRow.count}</div>
        <div class="stat-label">Total Synced Contexts</div>
      </div>
      <div class="stat-card">
        <div class="stat-count">${activeKeysRow.count}</div>
        <div class="stat-label">Active Keys (24h)</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">System Audit Log (Last 50 Events)</div>
      <div class="audit-card">
        <table class="audit-log-table">
          <thead>
            <tr>
              <th>Event</th>
              <th>User</th>
              <th>IP</th>
              <th>Detail</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            ${auditRowsHtml}
          </tbody>
        </table>
      </div>
    </div>
  `;

  // Render view
  const template = await Bun.file(new URL("../views/dashboard.html", import.meta.url)).text();
  const html = template
    .replaceAll("{{user}}", escapeHtml(loggedInUsername || ""))
    .replaceAll("{{csrfToken}}", csrfToken)
    .replaceAll("{{newKeyAlert}}", newKeyAlertHtml)
    .replaceAll("{{statusClass}}", statusClass)
    .replaceAll("{{statusText}}", statusText)
    .replaceAll("{{lastSyncTime}}", lastSyncTime)
    .replaceAll("{{contextSize}}", contextSize)
    .replaceAll("{{keysRows}}", keysRowsHtml)
    .replaceAll("{{adminSection}}", adminSectionHtml);

  return c.html(html);
});

dashboard.post("/dashboard/key/new", async (c) => {
  const sessionId = getCookie(c, "membridge_session");
  if (!sessionId) {
    return c.redirect("/auth/github");
  }

  const [session] = await sql`
    SELECT user_id FROM sessions WHERE id = ${sessionId} AND expires_at > NOW() LIMIT 1
  `;
  if (!session) {
    return c.redirect("/auth/github");
  }
  const userId = session.user_id as string;

  const body = await c.req.parseBody();
  const csrfCookie = getCookie(c, "csrf_token");
  const csrfInput = (body["csrf_token"] as string) ?? "";
  if (!csrfCookie || csrfCookie !== csrfInput) {
    return c.text("Forbidden", 403);
  }

  const rawKey = `mem_${randomHex(32)}`;
  const keyHash = await sha256Hex(rawKey);
  
  // Add key
  await sql`
    INSERT INTO api_keys (user_id, key_hash, name)
    VALUES (${userId}, ${keyHash}, 'dashboard-generated')
  `;

  // Fetch username
  const [userRow] = await sql`SELECT username FROM users WHERE id = ${userId} LIMIT 1`;
  const username = userRow ? (userRow.username as string) : "user";

  // Store in done_tokens for one-time display
  const [token] = await sql`
    INSERT INTO done_tokens (raw_key, username)
    VALUES (${rawKey}, ${username})
    RETURNING id
  `;

  return c.redirect(`/dashboard?token=${token.id}`);
});

dashboard.post("/dashboard/key/revoke", async (c) => {
  const sessionId = getCookie(c, "membridge_session");
  if (!sessionId) {
    return c.redirect("/auth/github");
  }

  const [session] = await sql`
    SELECT user_id FROM sessions WHERE id = ${sessionId} AND expires_at > NOW() LIMIT 1
  `;
  if (!session) {
    return c.redirect("/auth/github");
  }
  const userId = session.user_id as string;

  const body = await c.req.parseBody();
  const csrfCookie = getCookie(c, "csrf_token");
  const csrfInput = (body["csrf_token"] as string) ?? "";
  if (!csrfCookie || csrfCookie !== csrfInput) {
    return c.text("Forbidden", 403);
  }

  const keyId = (body["id"] as string) ?? "";
  if (!keyId) {
    return c.text("Bad Request", 400);
  }

  const [deletedKey] = await sql`
    DELETE FROM api_keys
    WHERE id = ${keyId} AND user_id = ${userId}
    RETURNING id
  `;

  if (!deletedKey) {
    return c.text("Not Found", 404);
  }

  return c.redirect("/dashboard");
});
