/**
 * E2E round-trip: CLI push → MCP read → MCP add_note → CLI pull
 * Requires Postgres on 5433 (docker-compose -f docker-compose.test.yml up -d)
 * Uses real age encryption — no mocks.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { app } from "../src/app";
import { createApiKey, createTestUser, resetDb } from "./helpers";

const BASE = "http://localhost:3000";

async function generateAgeKey(): Promise<{ secretKey: string; publicKey: string }> {
  const path = `/tmp/membridge-e2e-age-${crypto.randomUUID()}.key`;
  const gen = Bun.spawn(["age-keygen", "-o", path], { stderr: "pipe" });
  await gen.exited;
  const content = await Bun.file(path).text();
  await Bun.file(path).delete();
  const secretMatch = content.match(/AGE-SECRET-KEY-\S+/);
  if (!secretMatch) throw new Error("age-keygen failed");
  const secretKey = secretMatch[0];

  const pubProc = Bun.spawn(["age-keygen", "-y", "-"], {
    stdin: new TextEncoder().encode(secretKey + "\n"),
    stdout: "pipe",
    stderr: "pipe",
  });
  const publicKey = (await new Response(pubProc.stdout).text()).trim();
  return { secretKey, publicKey };
}

async function cliPush(plaintext: string, publicKey: string, apiKey: string): Promise<void> {
  const enc = Bun.spawn(["age", "-r", publicKey], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  enc.stdin.write(plaintext);
  enc.stdin.end();
  const [ciphertext, encErr, encExit] = await Promise.all([
    new Response(enc.stdout).arrayBuffer(),
    new Response(enc.stderr).text(),
    enc.exited,
  ]);
  if (encExit !== 0) throw new Error(`age encrypt: ${encErr}`);

  const res = await app.request("/api/context", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/octet-stream" },
    body: ciphertext,
  });
  if (res.status !== 200) throw new Error(`push failed: ${res.status}`);
}

async function cliPull(secretKey: string, apiKey: string): Promise<string> {
  const res = await app.request("/api/context", {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  if (res.status !== 200) throw new Error(`pull failed: ${res.status}`);
  const ciphertext = Buffer.from(await res.arrayBuffer());

  const tmpKey = `/tmp/membridge-e2e-pull-${crypto.randomUUID()}.key`;
  await Bun.write(tmpKey, secretKey + "\n");
  const dec = Bun.spawn(["age", "-d", "-i", tmpKey], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  dec.stdin.write(ciphertext);
  dec.stdin.end();
  const [plaintext, decErr, decExit] = await Promise.all([
    new Response(dec.stdout).text(),
    new Response(dec.stderr).text(),
    dec.exited,
  ]);
  await Bun.file(tmpKey).delete().catch(() => {});
  if (decExit !== 0) throw new Error(`age decrypt: ${decErr}`);
  return plaintext;
}

async function mcpCall(method: string, params: unknown, apiKey: string) {
  const res = await app.request("/mcp", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return res.json();
}

describe("E2E: full sync round-trip", () => {
  let apiKey: string;
  let secretKey: string;
  let publicKey: string;

  beforeEach(async () => {
    await resetDb();
    const userId = await createTestUser("e2e-gh-1", "e2e-user");
    apiKey = `mem_e2e_${crypto.randomUUID().replace(/-/g, "")}`;
    await createApiKey(userId, apiKey);
    const keys = await generateAgeKey();
    secretKey = keys.secretKey;
    publicKey = keys.publicKey;
  });

  afterEach(resetDb);

  test("CLI push → MCP get_context", async () => {
    const content = "## Rules\n- use TDD\n\n## Decisions\n\n## Notes\n";
    await cliPush(content, publicKey, apiKey);

    const body = await mcpCall("tools/call", { name: "get_context", arguments: { age_key: secretKey } }, apiKey);
    expect(body.result.content[0].text).toContain("use TDD");
  });

  test("MCP add_note → CLI pull", async () => {
    const initial = "## Rules\n\n## Decisions\n\n## Notes\n";
    await cliPush(initial, publicKey, apiKey);

    await mcpCall("tools/call", { name: "add_note", arguments: { text: "claude.ai added this", age_key: secretKey } }, apiKey);

    const pulled = await cliPull(secretKey, apiKey);
    expect(pulled).toContain("claude.ai added this");
    expect(pulled).toContain("## Notes");
  });

  test("full round-trip: push → add_note → pull preserves original + note", async () => {
    const initial = "## Rules\n- always test\n\n## Decisions\n- picked bun\n\n## Notes\n";
    await cliPush(initial, publicKey, apiKey);

    await mcpCall("tools/call", { name: "add_note", arguments: { text: "web note from claude.ai", age_key: secretKey } }, apiKey);

    const body = await mcpCall("tools/call", { name: "get_context", arguments: { age_key: secretKey } }, apiKey);
    expect(body.result.content[0].text).toContain("always test");
    expect(body.result.content[0].text).toContain("picked bun");
    expect(body.result.content[0].text).toContain("web note from claude.ai");

    const pulled = await cliPull(secretKey, apiKey);
    expect(pulled).toContain("always test");
    expect(pulled).toContain("web note from claude.ai");
  });

  test("wrong age key on pull returns decrypt error", async () => {
    const initial = "## Notes\n- secret\n";
    await cliPush(initial, publicKey, apiKey);

    const wrongKeys = await generateAgeKey();
    await expect(cliPull(wrongKeys.secretKey, apiKey)).rejects.toThrow("age decrypt");
  });

  test("MCP search finds content pushed via CLI", async () => {
    const content = "## Rules\n- use Resource[IO]\n\n## Notes\n- kafka: sync commit\n";
    await cliPush(content, publicKey, apiKey);

    const body = await mcpCall("tools/call", { name: "search", arguments: { query: "kafka", age_key: secretKey } }, apiKey);
    expect(body.result.content[0].text).toContain("kafka: sync commit");
    expect(body.result.content[0].text).not.toContain("Resource[IO]");
  });
});
