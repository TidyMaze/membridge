import { sql } from "../src/db/client";

export async function sha256Hex(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex");
}

export async function resetDb() {
  await sql`TRUNCATE oauth_codes, mcp_authorize_requests, oauth_clients, rate_limits, contexts, api_keys, users CASCADE`;
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
