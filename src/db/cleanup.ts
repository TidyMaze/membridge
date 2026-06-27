import { sql } from "./client";

export async function cleanExpiredEntries() {
  try {
    await sql`DELETE FROM done_tokens WHERE expires_at < NOW()`;
    await sql`DELETE FROM mcp_authorize_requests WHERE expires_at < NOW()`;
    await sql`DELETE FROM oauth_codes WHERE expires_at < NOW()`;
  } catch (err) {
    console.error("Database cleanup failed:", err);
  }
}
