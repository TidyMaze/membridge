import { app } from "./app";
import { sql } from "./db/client";
import { cleanExpiredEntries } from "./db/cleanup";

await sql.file(new URL("./db/schema.sql", import.meta.url).pathname);

// Perform startup cleanup of expired entries
await cleanExpiredEntries();

// Periodic cleanup every hour
setInterval(cleanExpiredEntries, 60 * 60 * 1000);

export default {
  port: Number(process.env.PORT ?? 3000),
  fetch: app.fetch,
};
