import { sql } from "../src/db/client";

await sql.file(new URL("../src/db/schema.sql", import.meta.url).pathname);
