import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { auth } from "./routes/auth";
import { context } from "./routes/context";
import { mcp } from "./routes/mcp";
import { oauthMeta } from "./routes/oauth-meta";

export const app = new Hono();
app.use(logger());
app.use(
  "/oauth/*",
  cors({ origin: "*", allowMethods: ["GET", "POST", "OPTIONS"], allowHeaders: ["Content-Type", "Authorization"] }),
);
app.use(
  "/.well-known/*",
  cors({ origin: "*", allowMethods: ["GET", "OPTIONS"], allowHeaders: ["Content-Type", "Authorization"] }),
);
app.use(
  "/mcp",
  cors({ origin: "*", allowMethods: ["GET", "POST", "OPTIONS"], allowHeaders: ["Content-Type", "Authorization"] }),
);

app.get("/", (c) => c.redirect("https://tidymaze.github.io/membridge/", 302));
app.get("/health", (c) => c.json({ ok: true }));
app.route("/", auth);
app.route("/", context);
app.route("/", mcp);
app.route("/", oauthMeta);

app.onError((err, c) => {
  return c.json({ error: err.message }, 500);
});
