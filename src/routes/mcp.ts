import { Hono, type Context } from "hono";
import { sql } from "../db/client";

export const mcp = new Hono();

async function sha256Hex(input: string) {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex");
}

async function ageDecrypt(ciphertext: Buffer, ageKey: string): Promise<string> {
  const tmpKeyPath = `/tmp/membridge-age-${crypto.randomUUID()}.key`;
  await Bun.write(tmpKeyPath, ageKey.endsWith("\n") ? ageKey : ageKey + "\n");
  try {
    const dec = Bun.spawn(["age", "-d", "-i", tmpKeyPath], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
    dec.stdin.write(ciphertext);
    dec.stdin.end();
    const [out, err, exitCode] = await Promise.all([
      new Response(dec.stdout).text(),
      new Response(dec.stderr).text(),
      dec.exited,
    ]);
    if (exitCode !== 0) throw new Error(`age decrypt failed: ${err.trim()}`);
    return out;
  } finally {
    await Bun.file(tmpKeyPath).delete().catch(() => {});
  }
}

async function ageEncrypt(plaintext: string, ageKey: string): Promise<Buffer> {
  const tmpKeyPath = `/tmp/membridge-age-${crypto.randomUUID()}.key`;
  await Bun.write(tmpKeyPath, ageKey.endsWith("\n") ? ageKey : ageKey + "\n");
  try {
    const recipientProc = Bun.spawn(["age-keygen", "-y", tmpKeyPath], { stdout: "pipe" });
    const pubKey = (await new Response(recipientProc.stdout).text()).trim();

    const enc = Bun.spawn(["age", "-r", pubKey], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
    enc.stdin.write(plaintext);
    enc.stdin.end();
    const [out, err, exitCode] = await Promise.all([
      new Response(enc.stdout).arrayBuffer(),
      new Response(enc.stderr).text(),
      enc.exited,
    ]);
    if (exitCode !== 0) throw new Error(`age encrypt failed: ${err.trim()}`);
    return Buffer.from(out);
  } finally {
    await Bun.file(tmpKeyPath).delete().catch(() => {});
  }
}

const AGE_KEY_PROPERTY = {
  age_key: {
    type: "string",
    description: "Your age secret key (AGE-SECRET-KEY-...), used to decrypt/encrypt your context. Never stored.",
  },
};

const TOOLS = [
  {
    name: "get_context",
    description: "Returns the user's decrypted memory context as markdown",
    inputSchema: { type: "object", properties: { ...AGE_KEY_PROPERTY }, required: ["age_key"] },
  },
  {
    name: "add_note",
    description: "Appends a note to the ## Notes section and re-encrypts",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string" }, ...AGE_KEY_PROPERTY },
      required: ["text", "age_key"],
    },
  },
  {
    name: "search",
    description: "Search the decrypted context for a query string",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" }, ...AGE_KEY_PROPERTY },
      required: ["query", "age_key"],
    },
  },
];

async function getContext(userId: string, ageKey: string): Promise<string> {
  const [row] = await sql`SELECT ciphertext FROM contexts WHERE user_id = ${userId} LIMIT 1`;
  if (!row) return "";
  return ageDecrypt(row.ciphertext, ageKey);
}

async function callTool(userId: string, name: string, args: Record<string, unknown>) {
  const ageKey = String(args.age_key ?? "");
  if (!ageKey) throw new Error("missing required argument: age_key");

  if (name === "get_context") {
    return await getContext(userId, ageKey);
  }

  if (name === "add_note") {
    const text = String(args.text ?? "");
    const current = (await getContext(userId, ageKey)) || "## Rules\n\n## Decisions\n\n## Notes\n";
    const updated = current.includes("## Notes")
      ? current.replace(/## Notes\n/, `## Notes\n- ${text}\n`)
      : `${current}\n## Notes\n- ${text}\n`;
    const ciphertext = await ageEncrypt(updated, ageKey);
    await sql`
      INSERT INTO contexts (user_id, ciphertext, size_bytes, updated_at)
      VALUES (${userId}, ${ciphertext}, ${ciphertext.length}, NOW())
      ON CONFLICT (user_id) DO UPDATE
        SET ciphertext = EXCLUDED.ciphertext, size_bytes = EXCLUDED.size_bytes, updated_at = NOW()
    `;
    return "note added";
  }

  if (name === "search") {
    const query = String(args.query ?? "").toLowerCase();
    const plaintext = await getContext(userId, ageKey);
    return plaintext
      .split("\n")
      .filter((line) => line.toLowerCase().includes(query))
      .join("\n");
  }

  throw new Error(`unknown tool: ${name}`);
}

function rpcResult(id: unknown, result: unknown) {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(id: unknown, code: number, message: string) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function unauthorized(c: Context) {
  const resourceMetadataUrl = `${process.env.BASE_URL}/.well-known/oauth-protected-resource`;
  return c.json({ error: "unauthorized" }, 401, {
    "WWW-Authenticate": `Bearer resource_metadata="${resourceMetadataUrl}"`,
  });
}

mcp.get("/mcp", (c) => {
  const header = c.req.header("Authorization") ?? "";
  if (!header.startsWith("Bearer ")) return unauthorized(c);

  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(`event: endpoint\ndata: /mcp\n\n`));
    },
  });
  return new Response(stream, {
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" },
  });
});

mcp.post("/mcp", async (c) => {
  const header = c.req.header("Authorization") ?? "";
  if (!header.startsWith("Bearer ")) return unauthorized(c);

  const rawKey = header.slice("Bearer ".length);
  const keyHash = await sha256Hex(rawKey);
  const [row] = await sql`SELECT user_id FROM api_keys WHERE key_hash = ${keyHash} LIMIT 1`;
  if (!row) return unauthorized(c);
  const userId = row.user_id;

  const body = await c.req.json();
  const { id, method, params } = body;

  // Notifications (no id) expect no JSON-RPC response body.
  if (id === undefined) return c.body(null, 202);

  try {
    if (method === "initialize") {
      return c.json(
        rpcResult(id, {
          protocolVersion: "2024-11-05",
          serverInfo: { name: "membridge", version: "0.1.0" },
          capabilities: { tools: {} },
        }),
      );
    }

    if (method === "tools/list") {
      return c.json(rpcResult(id, { tools: TOOLS }));
    }

    if (method === "tools/call") {
      try {
        const text = await callTool(userId, params.name, params.arguments ?? {});
        return c.json(rpcResult(id, { content: [{ type: "text", text }] }));
      } catch (toolErr) {
        return c.json(rpcResult(id, { isError: true, content: [{ type: "text", text: (toolErr as Error).message }] }));
      }
    }

    if (method === "resources/list") return c.json(rpcResult(id, { resources: [] }));
    if (method === "prompts/list") return c.json(rpcResult(id, { prompts: [] }));

    return c.json(rpcError(id, -32601, `method not found: ${method}`));
  } catch (err) {
    return c.json(rpcError(id, -32000, (err as Error).message));
  }
});
