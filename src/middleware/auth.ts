import type { Context, Next } from "hono";
import { sql } from "../db/client";

async function sha256Hex(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex");
}

function getIp(c: Context): string {
  return c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
}

export async function authMiddleware(c: Context, next: Next) {
  const header = c.req.header("Authorization") ?? "";
  if (!header.startsWith("Bearer ")) {
    await sql`INSERT INTO audit_log (event, ip, detail) VALUES ('auth_failed', ${getIp(c)}, 'missing bearer')`;
    return c.json({ error: "unauthorized" }, 401);
  }
  const rawKey = header.slice("Bearer ".length);
  const keyHash = await sha256Hex(rawKey);

  const [row] = await sql`
    SELECT user_id, expires_at FROM api_keys WHERE key_hash = ${keyHash} LIMIT 1
  `;
  if (!row) {
    await sql`INSERT INTO audit_log (event, ip, detail) VALUES ('auth_failed', ${getIp(c)}, 'invalid key')`;
    return c.json({ error: "unauthorized" }, 401);
  }
  if (row.expires_at && new Date(row.expires_at) < new Date()) {
    await sql`INSERT INTO audit_log (event, ip, user_id, detail) VALUES ('auth_failed', ${getIp(c)}, ${row.user_id}, 'expired key')`;
    return c.json({ error: "unauthorized" }, 401);
  }

  sql`UPDATE api_keys SET last_used = NOW() WHERE key_hash = ${keyHash}`.catch(() => {});

  c.set("userId", row.user_id);
  await next();
}
