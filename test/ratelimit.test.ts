import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { app } from "../src/app";
import { createApiKey, createTestUser, resetDb } from "./helpers";

describe("D3: rate limiting", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("allows up to 100 requests per hour, then 429s on the 101st", async () => {
    const userId = await createTestUser("200", "ratelimited");
    await createApiKey(userId, "mem_rl_key");

    let lastStatus = 0;
    for (let i = 0; i < 101; i++) {
      const res = await app.request("/api/context", {
        method: "POST",
        headers: { Authorization: "Bearer mem_rl_key" },
        body: new TextEncoder().encode("x"),
      });
      lastStatus = res.status;
      if (i < 100) expect(res.status).toBe(200);
    }
    expect(lastStatus).toBe(429);
  }, 30000);

  test("rate limits are scoped per user", async () => {
    const userA = await createTestUser("201", "user-a");
    await createApiKey(userA, "mem_a_key");
    const userB = await createTestUser("202", "user-b");
    await createApiKey(userB, "mem_b_key");

    for (let i = 0; i < 100; i++) {
      await app.request("/api/context", {
        method: "POST",
        headers: { Authorization: "Bearer mem_a_key" },
        body: new TextEncoder().encode("x"),
      });
    }

    const res = await app.request("/api/context", {
      method: "POST",
      headers: { Authorization: "Bearer mem_b_key" },
      body: new TextEncoder().encode("x"),
    });
    expect(res.status).toBe(200);
  }, 30000);
});
