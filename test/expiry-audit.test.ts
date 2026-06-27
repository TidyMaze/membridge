import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { app } from "../src/app";
import { sql } from "../src/db/client";
import { createApiKey, createTestUser, resetDb, sha256Hex } from "./helpers";

describe("Security: key expiry + audit log TDD", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  // ── API key expiry ─────────────────────────────────────────────────────────

  test("expired key returns 401", async () => {
    const userId = await createTestUser("900", "expiry-user");
    const keyHash = await sha256Hex("mem_expired_key");
    await sql`
      INSERT INTO api_keys (user_id, key_hash, expires_at)
      VALUES (${userId}, ${keyHash}, NOW() - INTERVAL '1 second')
    `;
    const res = await app.request("/api/context", {
      headers: { Authorization: "Bearer mem_expired_key" },
    });
    expect(res.status).toBe(401);
  });

  test("non-expired key still works", async () => {
    const userId = await createTestUser("901", "expiry-ok");
    const keyHash = await sha256Hex("mem_valid_key");
    await sql`
      INSERT INTO api_keys (user_id, key_hash, expires_at)
      VALUES (${userId}, ${keyHash}, NOW() + INTERVAL '1 year')
    `;
    const res = await app.request("/api/context", {
      headers: { Authorization: "Bearer mem_valid_key" },
    });
    expect(res.status).toBe(404); // no context yet, but auth passed
  });

  test("key with NULL expires_at never expires", async () => {
    const userId = await createTestUser("902", "expiry-null");
    await createApiKey(userId, "mem_no_expiry_key");
    const res = await app.request("/api/context", {
      headers: { Authorization: "Bearer mem_no_expiry_key" },
    });
    expect(res.status).toBe(404); // auth passed
  });

  // ── Audit log ──────────────────────────────────────────────────────────────

  test("failed auth writes audit_log row", async () => {
    const before = await sql`SELECT COUNT(*) FROM audit_log WHERE event = 'auth_failed'`;
    await app.request("/api/context", {
      headers: { Authorization: "Bearer mem_badkey_xxx" },
    });
    const after = await sql`SELECT COUNT(*) FROM audit_log WHERE event = 'auth_failed'`;
    expect(Number(after[0].count)).toBeGreaterThan(Number(before[0].count));
  });

  test("rate limit exceeded writes audit_log row", async () => {
    const userId = await createTestUser("903", "audit-rl");
    await createApiKey(userId, "mem_audit_rl_key");
    await sql`
      INSERT INTO rate_limits (user_id, window_start, count)
      VALUES (${userId}, date_trunc('hour', NOW()), 100)
      ON CONFLICT (user_id, window_start) DO UPDATE SET count = 100
    `;
    const before = await sql`SELECT COUNT(*) FROM audit_log WHERE event = 'rate_limited'`;
    await app.request("/api/context", {
      method: "POST",
      headers: { Authorization: "Bearer mem_audit_rl_key", "Content-Type": "application/octet-stream" },
      body: "x",
    });
    const after = await sql`SELECT COUNT(*) FROM audit_log WHERE event = 'rate_limited'`;
    expect(Number(after[0].count)).toBeGreaterThan(Number(before[0].count));
  });

  test("cleanExpiredEntries deletes expired entries", async () => {
    const { cleanExpiredEntries } = await import("../src/db/cleanup");

    // Insert expired done_token
    await sql`
      INSERT INTO done_tokens (id, raw_key, username, expires_at)
      VALUES ('10000000-0000-0000-0000-000000000001', 'mem_expired', 'user', NOW() - INTERVAL '1 second')
    `;
    // Insert non-expired done_token
    await sql`
      INSERT INTO done_tokens (id, raw_key, username, expires_at)
      VALUES ('10000000-0000-0000-0000-000000000002', 'mem_valid', 'user', NOW() + INTERVAL '1 hour')
    `;

    await cleanExpiredEntries();

    const expired = await sql`SELECT * FROM done_tokens WHERE id = '10000000-0000-0000-0000-000000000001'`;
    const valid = await sql`SELECT * FROM done_tokens WHERE id = '10000000-0000-0000-0000-000000000002'`;

    expect(expired.length).toBe(0);
    expect(valid.length).toBe(1);
  });
});
