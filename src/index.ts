import { Hono } from "hono";
import { logger } from "hono/logger";
import { auth } from "./routes/auth";
import { context } from "./routes/context";
import { mcp } from "./routes/mcp";
import { oauthMeta } from "./routes/oauth-meta";
import { sql } from "./db/client";

await sql.file(new URL("./db/schema.sql", import.meta.url).pathname);

const app = new Hono();
app.use(logger());

app.get("/health", (c) => c.json({ ok: true }));
app.route("/", auth);
app.route("/", context);
app.route("/", mcp);
app.route("/", oauthMeta);

app.onError((err, c) => {
  return c.json({ error: err.message }, 500);
});

export default {
  port: Number(process.env.PORT ?? 3000),
  fetch: app.fetch,
};
