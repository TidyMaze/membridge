import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { app } from "../src/app";
import { sql } from "../src/db/client";
import { createApiKey, createTestUser, resetDb, getCsrfTokenAndCookie } from "./helpers";

function base64UrlSha256(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("base64url");
}

describe("Security: C2 — done token (key never in URL)", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("/dashboard without session redirects to login", async () => {
    const res = await app.request("/dashboard", { redirect: "manual" });
    expect(res.status).toBe(302);
  });

  test("/dashboard?token=<valid> shows key and is consumed", async () => {
    const userId = await createTestUser("899", "alice");
    await createApiKey(userId, "mem_test_key_123");
    const [row] = await sql`
      INSERT INTO done_tokens (raw_key, username) VALUES ('mem_test_key_123', 'alice') RETURNING id
    `;
    const tokenId = row.id as string;

    const res = await app.request(`/dashboard?token=${tokenId}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("mem_test_key_123");
    expect(html).toContain("alice");

    // Token is single-use — second request must redirect to login because token is consumed
    const res2 = await app.request(`/dashboard?token=${tokenId}`, { redirect: "manual" });
    expect(res2.status).toBe(302);
  });

  test("/dashboard?token=<expired> redirects to login", async () => {
    const [row] = await sql`
      INSERT INTO done_tokens (raw_key, username, expires_at)
      VALUES ('mem_expired', 'bob', NOW() - INTERVAL '1 second')
      RETURNING id
    `;
    const res = await app.request(`/dashboard?token=${row.id}`, { redirect: "manual" });
    expect(res.status).toBe(302);
  });
});

describe("Security: C3 — OAuth redirect_uri validated against registered client", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("POST /oauth/authorize rejects redirect_uri not in registered list", async () => {
    const userId = await createTestUser("600", "redirect-test");
    await createApiKey(userId, "mem_redirect_key");

    // Register client with specific redirect URI
    await sql`
      INSERT INTO oauth_clients (client_id, redirect_uris)
      VALUES ('safe-client', '["https://good.example/cb"]')
    `;

    const verifier = "e".repeat(64);
    const challenge = base64UrlSha256(verifier);

    const { token, cookie } = await getCsrfTokenAndCookie("safe-client", "https://good.example/cb", challenge);

    const res = await app.request("/oauth/authorize", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": cookie,
      },
      body: new URLSearchParams({
        csrf_token: token,
        client_id: "safe-client",
        redirect_uri: "https://evil.example/steal",
        code_challenge: challenge,
        code_challenge_method: "S256",
        api_key: "mem_redirect_key",
      }),
    });
    expect(res.status).toBe(400);
  });

  test("POST /oauth/authorize accepts redirect_uri matching registered list", async () => {
    const userId = await createTestUser("601", "redirect-ok");
    await createApiKey(userId, "mem_redirect_ok_key");

    await sql`
      INSERT INTO oauth_clients (client_id, redirect_uris)
      VALUES ('legit-client', '["http://localhost:9999/callback"]')
    `;

    const verifier = "f".repeat(64);
    const challenge = base64UrlSha256(verifier);

    const { token, cookie } = await getCsrfTokenAndCookie("legit-client", "http://localhost:9999/callback", challenge);

    const res = await app.request("/oauth/authorize", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": cookie,
      },
      body: new URLSearchParams({
        csrf_token: token,
        client_id: "legit-client",
        redirect_uri: "http://localhost:9999/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        api_key: "mem_redirect_ok_key",
      }),
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("location")!).searchParams.get("code")).toBeTruthy();
  });

  test("POST /oauth/authorize rejects unknown client_id", async () => {
    const userId = await createTestUser("602", "redirect-noclient");
    await createApiKey(userId, "mem_redirect_noclient_key");

    await sql`
      INSERT INTO oauth_clients (client_id, redirect_uris)
      VALUES ('legit-client', '["http://localhost:9999/callback"]')
    `;

    const verifier = "g".repeat(64);
    const challenge = base64UrlSha256(verifier);

    const { token, cookie } = await getCsrfTokenAndCookie("legit-client", "http://localhost:9999/callback", challenge);

    const res = await app.request("/oauth/authorize", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": cookie,
      },
      body: new URLSearchParams({
        csrf_token: token,
        client_id: "ghost-client",
        redirect_uri: "http://localhost:9999/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        api_key: "mem_redirect_noclient_key",
      }),
    });
    expect(res.status).toBe(400);
  });
});

describe("Security: H1 — CSRF / SameSite cookies", () => {
  test("GET /auth/github sets SameSite=Lax on oauth_state cookie", async () => {
    // Redirect without real GitHub — just check Set-Cookie header
    const res = await app.request("/auth/github", { redirect: "manual" });
    expect(res.status).toBe(302);
    const cookie = res.headers.get("set-cookie") ?? "";
    expect(cookie.toLowerCase()).toContain("samesite=lax");
  });
});

describe("Security: H2 — MCP rate limiting", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("MCP POST returns 429 after 100 requests in the same hour", async () => {
    const userId = await createTestUser("700", "mcp-ratelimit");
    await createApiKey(userId, "mem_mcp_rl_key");

    // Exhaust rate limit via the context API (same userId, same window)
    await sql`
      INSERT INTO rate_limits (user_id, window_start, count)
      VALUES (${userId}, date_trunc('hour', NOW()), 100)
      ON CONFLICT (user_id, window_start) DO UPDATE SET count = 100
    `;

    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        Authorization: "Bearer mem_mcp_rl_key",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    expect(res.status).toBe(429);
  });
});

describe("Security: C1 — age key temp file cleanup", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("no membridge-age-* files linger in /tmp after ageDecrypt error", async () => {
    const userId = await createTestUser("800", "age-cleanup");
    await createApiKey(userId, "mem_age_cleanup_key");

    const before = (await Array.fromAsync(
      (await import("node:fs/promises")).readdir("/tmp")
    )).filter((f) => f.startsWith("membridge-"));

    // Call decrypt with wrong key → should fail but still clean up
    await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer mem_age_cleanup_key", "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "get_context", arguments: { age_key: "AGE-SECRET-KEY-FAKE" } },
      }),
    });

    const after = (await Array.fromAsync(
      (await import("node:fs/promises")).readdir("/tmp")
    )).filter((f) => f.startsWith("membridge-"));

    expect(after.length).toBe(before.length);
  });
});

describe("Security: CSRF & REGISTRATION_TOKEN TDD", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("POST /dashboard/key/revoke rejects without valid CSRF", async () => {
    const userId = await createTestUser("850", "csrf-test");
    const sessionId = crypto.randomUUID();
    await sql`
      INSERT INTO sessions (id, user_id, expires_at)
      VALUES (${sessionId}, ${userId}, NOW() + INTERVAL '1 hour')
    `;

    const res = await app.request("/dashboard/key/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": `membridge_session=${sessionId}`
      },
      body: new URLSearchParams({ id: "some-key-id", csrf_token: "wrong" }),
    });
    expect(res.status).toBe(403);
  });

  test("POST /oauth/authorize rejects without valid CSRF", async () => {
    const res = await app.request("/oauth/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ api_key: "mem_key", client_id: "safe-client", csrf_token: "wrong" }),
    });
    expect(res.status).toBe(403);
  });

  test("POST /oauth/register rejects if REGISTRATION_TOKEN env is set and unauthorized", async () => {
    process.env.REGISTRATION_TOKEN = "secret-reg-token";
    try {
      const res = await app.request("/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_name: "test", redirect_uris: [] }),
      });
      expect(res.status).toBe(401);
    } finally {
      delete process.env.REGISTRATION_TOKEN;
    }
  });

  test("POST /oauth/register accepts if REGISTRATION_TOKEN env is set and authorized", async () => {
    process.env.REGISTRATION_TOKEN = "secret-reg-token";
    try {
      const res = await app.request("/oauth/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer secret-reg-token",
        },
        body: JSON.stringify({ client_name: "test", redirect_uris: [] }),
      });
      expect(res.status).toBe(201);
    } finally {
      delete process.env.REGISTRATION_TOKEN;
    }
  });
});

