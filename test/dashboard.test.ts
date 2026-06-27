import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { app } from "../src/app";
import { sql } from "../src/db/client";
import { createApiKey, createTestUser, resetDb, sha256Hex } from "./helpers";

async function createTestSession(userId: string, expiresAt = new Date(Date.now() + 3600000)) {
  const [session] = await sql`
    INSERT INTO sessions (user_id, expires_at)
    VALUES (${userId}, ${expiresAt})
    RETURNING id
  `;
  return session.id as string;
}

describe("Dashboard: Authentication & Redirects", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("GET /dashboard without session redirects to /auth/github", async () => {
    const res = await app.request("/dashboard", { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/auth/github");
  });

  test("GET /dashboard with invalid session redirects to /auth/github", async () => {
    const res = await app.request("/dashboard", {
      headers: { Cookie: "membridge_session=00000000-0000-0000-0000-000000000000" },
      redirect: "manual"
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/auth/github");
  });

  test("GET /dashboard with expired session redirects to /auth/github", async () => {
    const userId = await createTestUser("100", "test-user");
    const sessionId = await createTestSession(userId, new Date(Date.now() - 1000)); // expired 1s ago

    const res = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${sessionId}` },
      redirect: "manual"
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/auth/github");
  });

  test("GET /dashboard with valid session returns 200 and loads page", async () => {
    const userId = await createTestUser("100", "test-user");
    const sessionId = await createTestSession(userId);

    const res = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${sessionId}` }
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("MemBridge Control Panel");
    expect(html).toContain("test-user");
  });
});

describe("Dashboard: Done Token / OTP Authentication", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("GET /dashboard?token=<valid> sets session cookie, displays raw key, and deletes token", async () => {
    const userId = await createTestUser("101", "alice");
    const rawKey = "mem_otp_test_123";
    await createApiKey(userId, rawKey);

    const [doneToken] = await sql`
      INSERT INTO done_tokens (raw_key, username)
      VALUES (${rawKey}, 'alice')
      RETURNING id
    `;

    const res = await app.request(`/dashboard?token=${doneToken.id}`);
    expect(res.status).toBe(200);

    const html = await res.text();
    expect(html).toContain("alice");
    expect(html).toContain("mem_otp_test_123");
    
    // Cookie must be set
    const setCookieHeader = res.headers.get("set-cookie") ?? "";
    expect(setCookieHeader).toContain("membridge_session=");

    // Token must be consumed
    const res2 = await app.request(`/dashboard?token=${doneToken.id}`);
    expect(res2.status).toBe(302); // Redirects to GitHub because token is consumed and no session cookie is sent this time
  });
});

describe("Dashboard: Super Admin Restrictions", () => {
  beforeEach(resetDb);
  afterEach(async () => {
    delete process.env.ADMIN_GITHUB_ID;
    delete process.env.ADMIN_USERNAME;
    await resetDb();
  });

  test("Allows access if no admin env variable is set", async () => {
    const userId = await createTestUser("102", "regular-user");
    const sessionId = await createTestSession(userId);

    const res = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${sessionId}` }
    });
    expect(res.status).toBe(200);
  });

  test("Restricts to matching ADMIN_GITHUB_ID", async () => {
    process.env.ADMIN_GITHUB_ID = "999";

    const adminUserId = await createTestUser("999", "admin-user");
    const regularUserId = await createTestUser("103", "regular-user");

    const adminSessionId = await createTestSession(adminUserId);
    const regularSessionId = await createTestSession(regularUserId);

    // Admin passes
    const adminRes = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${adminSessionId}` }
    });
    expect(adminRes.status).toBe(200);
    const adminHtml = await adminRes.text();
    expect(adminHtml).toContain("System Metrics");

    // Regular fails
    const regularRes = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${regularSessionId}` }
    });
    expect(regularRes.status).toBe(403);
  });

  test("Restricts to matching ADMIN_USERNAME", async () => {
    process.env.ADMIN_USERNAME = "my-admin-name";

    const adminUserId = await createTestUser("104", "my-admin-name");
    const regularUserId = await createTestUser("105", "regular-user");

    const adminSessionId = await createTestSession(adminUserId);
    const regularSessionId = await createTestSession(regularUserId);

    // Admin passes
    const adminRes = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${adminSessionId}` }
    });
    expect(adminRes.status).toBe(200);

    // Regular fails
    const regularRes = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${regularSessionId}` }
    });
    expect(regularRes.status).toBe(403);
  });
});

describe("Dashboard: Key Operations", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("POST /dashboard/key/new generates a new key and redirects to show it once", async () => {
    const userId = await createTestUser("106", "key-generator");
    const sessionId = await createTestSession(userId);

    // Get CSRF token
    const resGet = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${sessionId}` }
    });
    const cookieHeader = resGet.headers.get("set-cookie") ?? "";
    const csrfToken = cookieHeader.match(/csrf_token=([^;]+)/)?.[1] ?? "";

    const resPost = await app.request("/dashboard/key/new", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": `membridge_session=${sessionId}; csrf_token=${csrfToken}`
      },
      body: new URLSearchParams({ csrf_token: csrfToken }),
      redirect: "manual"
    });

    expect(resPost.status).toBe(302);
    const location = resPost.headers.get("location") ?? "";
    expect(location).toContain("/dashboard?token=");

    // Verify key was stored
    const apiKeys = await sql`SELECT * FROM api_keys WHERE user_id = ${userId}`;
    expect(apiKeys.length).toBe(1); // The generated key
  });

  test("POST /dashboard/key/revoke deletes key", async () => {
    const userId = await createTestUser("107", "key-revoker");
    const sessionId = await createTestSession(userId);

    await createApiKey(userId, "mem_to_be_deleted");
    const [keyRow] = await sql`SELECT id FROM api_keys WHERE user_id = ${userId} LIMIT 1`;
    const keyId = keyRow.id as string;

    // Get CSRF token
    const resGet = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${sessionId}` }
    });
    const cookieHeader = resGet.headers.get("set-cookie") ?? "";
    const csrfToken = cookieHeader.match(/csrf_token=([^;]+)/)?.[1] ?? "";

    const resPost = await app.request("/dashboard/key/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": `membridge_session=${sessionId}; csrf_token=${csrfToken}`
      },
      body: new URLSearchParams({ csrf_token: csrfToken, id: keyId }),
      redirect: "manual"
    });

    expect(resPost.status).toBe(302);
    
    // Verify key is deleted
    const apiKeys = await sql`SELECT * FROM api_keys WHERE id = ${keyId}`;
    expect(apiKeys.length).toBe(0);
  });

  test("POST /dashboard/key/revoke doesn't delete other user's key", async () => {
    const aliceId = await createTestUser("108", "alice");
    const bobId = await createTestUser("109", "bob");
    const aliceSessionId = await createTestSession(aliceId);

    await createApiKey(bobId, "mem_bobs_key");
    const [bobsKeyRow] = await sql`SELECT id FROM api_keys WHERE user_id = ${bobId} LIMIT 1`;
    const bobsKeyId = bobsKeyRow.id as string;

    // Get CSRF token for Alice
    const resGet = await app.request("/dashboard", {
      headers: { Cookie: `membridge_session=${aliceSessionId}` }
    });
    const cookieHeader = resGet.headers.get("set-cookie") ?? "";
    const csrfToken = cookieHeader.match(/csrf_token=([^;]+)/)?.[1] ?? "";

    const resPost = await app.request("/dashboard/key/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": `membridge_session=${aliceSessionId}; csrf_token=${csrfToken}`
      },
      body: new URLSearchParams({ csrf_token: csrfToken, id: bobsKeyId }),
      redirect: "manual"
    });

    expect(resPost.status).toBe(404); // Not Alice's key

    // Verify Bob's key still exists
    const bobsKeys = await sql`SELECT * FROM api_keys WHERE id = ${bobsKeyId}`;
    expect(bobsKeys.length).toBe(1);
  });
});
