import { sql } from "../src/db/client";

export async function sha256Hex(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex");
}

export async function resetDb() {
  await sql`TRUNCATE done_tokens, oauth_codes, mcp_authorize_requests, oauth_clients, rate_limits, contexts, api_keys, users, audit_log CASCADE`;
}

export async function createTestUser(githubId: string, username: string) {
  const [user] = await sql`
    INSERT INTO users (github_id, username) VALUES (${githubId}, ${username}) RETURNING id
  `;
  return user.id as string;
}

export async function createApiKey(userId: string, rawKey: string, name = "default") {
  const keyHash = await sha256Hex(rawKey);
  await sql`INSERT INTO api_keys (user_id, key_hash, name) VALUES (${userId}, ${keyHash}, ${name})`;
}

export function randomAgeKeyPaths() {
  return `/tmp/membridge-test-age-${crypto.randomUUID()}.key`;
}

export async function getCsrfTokenAndCookie(clientId: string, redirectUri: string, challenge: string): Promise<{ token: string; cookie: string }> {
  const { app } = await import("../src/app");
  const res = await app.request(
    `/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256`
  );
  const cookieHeader = res.headers.get("set-cookie") ?? "";
  const match = cookieHeader.match(/csrf_token=([^;]+)/);
  const token = match ? match[1] : "";
  return { token, cookie: `csrf_token=${token}` };
}
