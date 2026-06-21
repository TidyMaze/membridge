import { Hono } from "hono";
import { sql } from "../db/client";
import { authMiddleware } from "../middleware/auth";
import { rateLimitMiddleware } from "../middleware/ratelimit";

export const context = new Hono();

const MAX_SIZE = 500 * 1024;

context.post("/api/context", authMiddleware, rateLimitMiddleware, async (c) => {
  const userId = c.get("userId") as string;
  const buf = Buffer.from(await c.req.arrayBuffer());
  if (buf.length > MAX_SIZE) return c.json({ error: "payload_too_large" }, 413);

  await sql`
    INSERT INTO contexts (user_id, ciphertext, size_bytes, updated_at)
    VALUES (${userId}, ${buf}, ${buf.length}, NOW())
    ON CONFLICT (user_id) DO UPDATE
      SET ciphertext = EXCLUDED.ciphertext, size_bytes = EXCLUDED.size_bytes, updated_at = NOW()
  `;

  return c.json({ ok: true });
});

context.get("/api/context", authMiddleware, async (c) => {
  const userId = c.get("userId") as string;
  const [row] = await sql`SELECT ciphertext FROM contexts WHERE user_id = ${userId} LIMIT 1`;
  if (!row) return c.json({ error: "not_found" }, 404);

  return new Response(row.ciphertext, {
    status: 200,
    headers: { "Content-Type": "application/octet-stream" },
  });
});
