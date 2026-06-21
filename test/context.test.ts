import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { app } from "../src/app";
import { sql } from "../src/db/client";
import { createApiKey, createTestUser, resetDb } from "./helpers";

describe("D2: context push/pull + auth middleware", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("rejects requests without a valid API key", async () => {
    const res = await app.request("/api/context", {
      headers: { Authorization: "Bearer not-a-real-key" },
    });
    expect(res.status).toBe(401);
  });

  test("rejects requests with no Authorization header", async () => {
    const res = await app.request("/api/context");
    expect(res.status).toBe(401);
  });

  test("push then pull round-trips the exact bytes", async () => {
    const userId = await createTestUser("100", "alice");
    await createApiKey(userId, "mem_alice_key");

    const payload = new TextEncoder().encode("some ciphertext bytes");
    const pushRes = await app.request("/api/context", {
      method: "POST",
      headers: { Authorization: "Bearer mem_alice_key" },
      body: payload,
    });
    expect(pushRes.status).toBe(200);
    expect(await pushRes.json()).toEqual({ ok: true });

    const pullRes = await app.request("/api/context", {
      headers: { Authorization: "Bearer mem_alice_key" },
    });
    expect(pullRes.status).toBe(200);
    const body = new Uint8Array(await pullRes.arrayBuffer());
    expect(body).toEqual(payload);
  });

  test("pull returns 404 when no context exists yet", async () => {
    const userId = await createTestUser("101", "bob");
    await createApiKey(userId, "mem_bob_key");

    const res = await app.request("/api/context", {
      headers: { Authorization: "Bearer mem_bob_key" },
    });
    expect(res.status).toBe(404);
  });

  test("rejects payloads over 500KB", async () => {
    const userId = await createTestUser("102", "carl");
    await createApiKey(userId, "mem_carl_key");

    const big = new Uint8Array(500 * 1024 + 1);
    const res = await app.request("/api/context", {
      method: "POST",
      headers: { Authorization: "Bearer mem_carl_key" },
      body: big,
    });
    expect(res.status).toBe(413);
  });

  test("push updates last_used on the api key", async () => {
    const userId = await createTestUser("103", "dana");
    await createApiKey(userId, "mem_dana_key");

    await app.request("/api/context", {
      method: "POST",
      headers: { Authorization: "Bearer mem_dana_key" },
      body: new TextEncoder().encode("x"),
    });

    // last_used update is fire-and-forget; give it a tick to land
    await new Promise((r) => setTimeout(r, 50));
    const [row] = await sql`SELECT last_used FROM api_keys WHERE user_id = ${userId}`;
    expect(row.last_used).not.toBeNull();
  });
});
