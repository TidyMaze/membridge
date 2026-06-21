import type { Context, Next } from "hono";
import { sql } from "../db/client";

const LIMIT_PER_HOUR = 100;

export async function rateLimitMiddleware(c: Context, next: Next) {
  const userId = c.get("userId") as string;

  const [row] = await sql.begin(async (tx) => {
    await tx`DELETE FROM rate_limits WHERE window_start < NOW() - INTERVAL '2 hours'`;
    return tx`
      INSERT INTO rate_limits (user_id, window_start, count)
      VALUES (${userId}, date_trunc('hour', NOW()), 1)
      ON CONFLICT (user_id, window_start)
      DO UPDATE SET count = rate_limits.count + 1
      RETURNING count
    `;
  });

  if (row.count > LIMIT_PER_HOUR) return c.json({ error: "rate_limited" }, 429);
  await next();
}
