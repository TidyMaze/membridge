import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { app } from "../src/app";
import { createApiKey, createTestUser, resetDb } from "./helpers";

async function generateAgeKey(): Promise<string> {
  const path = `/tmp/membridge-test-age-${crypto.randomUUID()}.key`;
  const proc = Bun.spawn(["age-keygen", "-o", path], { stdout: "pipe", stderr: "pipe" });
  await proc.exited;
  const content = await Bun.file(path).text();
  await Bun.file(path).delete();
  const match = content.match(/AGE-SECRET-KEY-\S+/);
  if (!match) throw new Error("failed to generate age key");
  return match[0];
}

async function rpc(method: string, params: unknown, apiKey: string, ageKey: string) {
  const res = await app.request("/mcp", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "X-Age-Key": ageKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return { status: res.status, body: await res.json() };
}

describe("D4: MCP endpoint", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("rejects requests missing X-Age-Key or Authorization", async () => {
    const res = await app.request("/mcp", { method: "POST", body: "{}" });
    expect(res.status).toBe(401);
  });

  test("initialize returns server info", async () => {
    const userId = await createTestUser("300", "mcp-user");
    await createApiKey(userId, "mem_mcp_key");
    const ageKey = await generateAgeKey();

    const { status, body } = await rpc("initialize", {}, "mem_mcp_key", ageKey);
    expect(status).toBe(200);
    expect(body.result.serverInfo.name).toBe("membridge");
  });

  test("get_context on empty store returns empty text", async () => {
    const userId = await createTestUser("301", "mcp-empty");
    await createApiKey(userId, "mem_mcp_empty_key");
    const ageKey = await generateAgeKey();

    const { body } = await rpc("tools/call", { name: "get_context", arguments: {} }, "mem_mcp_empty_key", ageKey);
    expect(body.result.content[0].text).toBe("");
  });

  test("add_note then get_context round-trips through real age encryption", async () => {
    const userId = await createTestUser("302", "mcp-notes");
    await createApiKey(userId, "mem_mcp_notes_key");
    const ageKey = await generateAgeKey();

    const addRes = await rpc(
      "tools/call",
      { name: "add_note", arguments: { text: "remember this" } },
      "mem_mcp_notes_key",
      ageKey,
    );
    expect(addRes.body.result.content[0].text).toBe("note added");

    const getRes = await rpc("tools/call", { name: "get_context", arguments: {} }, "mem_mcp_notes_key", ageKey);
    expect(getRes.body.result.content[0].text).toContain("- remember this");
    expect(getRes.body.result.content[0].text).toContain("## Notes");
  });

  test("get_context with the wrong age key fails to decrypt", async () => {
    const userId = await createTestUser("303", "mcp-wrongkey");
    await createApiKey(userId, "mem_mcp_wrongkey_key");
    const ageKey = await generateAgeKey();
    const wrongKey = await generateAgeKey();

    await rpc("tools/call", { name: "add_note", arguments: { text: "secret" } }, "mem_mcp_wrongkey_key", ageKey);

    const { body } = await rpc(
      "tools/call",
      { name: "get_context", arguments: {} },
      "mem_mcp_wrongkey_key",
      wrongKey,
    );
    expect(body.error).toBeDefined();
  });

  test("search filters lines by query", async () => {
    const userId = await createTestUser("304", "mcp-search");
    await createApiKey(userId, "mem_mcp_search_key");
    const ageKey = await generateAgeKey();

    await rpc("tools/call", { name: "add_note", arguments: { text: "findme please" } }, "mem_mcp_search_key", ageKey);
    const { body } = await rpc(
      "tools/call",
      { name: "search", arguments: { query: "findme" } },
      "mem_mcp_search_key",
      ageKey,
    );
    expect(body.result.content[0].text).toContain("findme please");
  });
});
