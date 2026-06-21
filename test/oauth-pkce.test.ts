import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { app } from "../src/app";
import { createApiKey, createTestUser, resetDb } from "./helpers";

function base64UrlSha256(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("base64url");
}

describe("D5: OAuth 2.1 PKCE for MCP", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("well-known endpoints return valid metadata", async () => {
    const res1 = await app.request("/.well-known/oauth-authorization-server");
    expect(res1.status).toBe(200);
    const meta = await res1.json();
    expect(meta.authorization_endpoint).toContain("/oauth/authorize");
    expect(meta.code_challenge_methods_supported).toEqual(["S256"]);

    const res2 = await app.request("/.well-known/oauth-protected-resource");
    expect(res2.status).toBe(200);
  });

  test("authorize rejects missing PKCE params", async () => {
    const res = await app.request("/oauth/authorize?client_id=x&redirect_uri=http://x/cb");
    expect(res.status).toBe(400);
  });

  test("full PKCE round trip: authorize -> code -> token", async () => {
    const userId = await createTestUser("400", "pkce-user");
    await createApiKey(userId, "mem_pkce_key");

    const verifier = "a".repeat(64);
    const challenge = base64UrlSha256(verifier);

    const authRes = await app.request("/oauth/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "test-client",
        redirect_uri: "http://localhost:9999/callback",
        state: "xyz",
        code_challenge: challenge,
        code_challenge_method: "S256",
        api_key: "mem_pkce_key",
      }),
      redirect: "manual",
    });
    expect(authRes.status).toBe(302);
    const location = new URL(authRes.headers.get("location")!);
    const code = location.searchParams.get("code")!;
    expect(location.searchParams.get("state")).toBe("xyz");
    expect(code).toBeTruthy();

    const tokenRes = await app.request("/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier }),
    });
    expect(tokenRes.status).toBe(200);
    const tokenBody = await tokenRes.json();
    expect(tokenBody.access_token).toStartWith("mem_");
    expect(tokenBody.token_type).toBe("bearer");
  });

  test("authorize rejects an invalid API key", async () => {
    const verifier = "b".repeat(64);
    const challenge = base64UrlSha256(verifier);

    const res = await app.request("/oauth/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "test-client",
        redirect_uri: "http://localhost:9999/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        api_key: "mem_not_a_real_key",
      }),
    });
    expect(res.status).toBe(401);
  });

  test("token exchange rejects a wrong code_verifier", async () => {
    const userId = await createTestUser("401", "pkce-bad-verifier");
    await createApiKey(userId, "mem_pkce_bad_key");

    const verifier = "c".repeat(64);
    const challenge = base64UrlSha256(verifier);

    const authRes = await app.request("/oauth/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "test-client",
        redirect_uri: "http://localhost:9999/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        api_key: "mem_pkce_bad_key",
      }),
      redirect: "manual",
    });
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await app.request("/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: "wrong-verifier" }),
    });
    expect(tokenRes.status).toBe(400);
  });

  test("a used code cannot be exchanged twice", async () => {
    const userId = await createTestUser("402", "pkce-replay");
    await createApiKey(userId, "mem_pkce_replay_key");

    const verifier = "d".repeat(64);
    const challenge = base64UrlSha256(verifier);

    const authRes = await app.request("/oauth/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "test-client",
        redirect_uri: "http://localhost:9999/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        api_key: "mem_pkce_replay_key",
      }),
      redirect: "manual",
    });
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;

    const first = await app.request("/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier }),
    });
    expect(first.status).toBe(200);

    const second = await app.request("/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier }),
    });
    expect(second.status).toBe(400);
  });
});
