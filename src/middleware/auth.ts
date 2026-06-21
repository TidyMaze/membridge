import type { Context, Next } from "hono";
import { sql } from "../db/client";

async function sha256Hex(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex");
}

export async function authMiddleware(c: Context, next: Next) {
  const header = c.req.header("Authorization") ?? "";
  if (!header.startsWith("Bearer ")) return c.json({ error: "unauthorized" }, 401);
  const rawKey = header.slice("Bearer ".length);
  const keyHash = await sha256Hex(rawKey);

  const [row] = await sql`SELECT user_id FROM api_keys WHERE key_hash = ${keyHash} LIMIT 1`;
  if (!row) return c.json({ error: "unauthorized" }, 401);

  sql`UPDATE api_keys SET last_used = NOW() WHERE key_hash = ${keyHash}`.catch(() => {});

  c.set("userId", row.user_id);
  await next();
}
