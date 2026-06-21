import { app } from "./app";
import { sql } from "./db/client";

await sql.file(new URL("./db/schema.sql", import.meta.url).pathname);

export default {
  port: Number(process.env.PORT ?? 3000),
  fetch: app.fetch,
};
