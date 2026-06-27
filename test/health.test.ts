import { describe, expect, test } from "bun:test";
import { app } from "../src/app";

describe("D1: health", () => {
  test("GET /health returns ok", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, deployment: "automated-registry-flow-v1" });
  });
});

describe("D1: GitHub OAuth redirect", () => {
  test("GET /auth/github redirects to GitHub with state cookie", async () => {
    const res = await app.request("/auth/github", { redirect: "manual" });
    expect(res.status).toBe(302);
    const location = res.headers.get("location")!;
    expect(location).toStartWith("https://github.com/login/oauth/authorize");
    expect(location).toContain("client_id=");
    expect(location).toContain("state=");
    expect(res.headers.get("set-cookie")).toContain("oauth_state=");
  });
});
