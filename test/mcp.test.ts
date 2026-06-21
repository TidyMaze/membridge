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

async function rpc(method: string, params: unknown, apiKey: string) {
  const res = await app.request("/mcp", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return { status: res.status, body: await res.json() };
}

describe("D4: MCP endpoint", () => {
  beforeEach(resetDb);
  afterEach(resetDb);

  test("rejects requests missing Authorization", async () => {
    const res = await app.request("/mcp", { method: "POST", body: "{}" });
    expect(res.status).toBe(401);
  });

  test("initialize returns server info", async () => {
    const userId = await createTestUser("300", "mcp-user");
    await createApiKey(userId, "mem_mcp_key");

    const { status, body } = await rpc("initialize", {}, "mem_mcp_key");
    expect(status).toBe(200);
    expect(body.result.serverInfo.name).toBe("membridge");
  });

  test("get_context on empty store returns empty text", async () => {
    const userId = await createTestUser("301", "mcp-empty");
    await createApiKey(userId, "mem_mcp_empty_key");
    const ageKey = await generateAgeKey();

    const { body } = await rpc(
      "tools/call",
      { name: "get_context", arguments: { age_key: ageKey } },
      "mem_mcp_empty_key",
    );
    expect(body.result.content[0].text).toBe("");
  });

  test("tools/call without age_key returns a tool error, not a protocol error", async () => {
    const userId = await createTestUser("305", "mcp-noagekey");
    await createApiKey(userId, "mem_mcp_noagekey_key");

    const { body } = await rpc("tools/call", { name: "get_context", arguments: {} }, "mem_mcp_noagekey_key");
    expect(body.error).toBeUndefined();
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).toContain("age_key");
  });

  test("add_note then get_context round-trips through real age encryption", async () => {
    const userId = await createTestUser("302", "mcp-notes");
    await createApiKey(userId, "mem_mcp_notes_key");
    const ageKey = await generateAgeKey();

    const addRes = await rpc(
      "tools/call",
      { name: "add_note", arguments: { text: "remember this", age_key: ageKey } },
      "mem_mcp_notes_key",
    );
    expect(addRes.body.result.content[0].text).toBe("note added");

    const getRes = await rpc(
      "tools/call",
      { name: "get_context", arguments: { age_key: ageKey } },
      "mem_mcp_notes_key",
    );
    expect(getRes.body.result.content[0].text).toContain("- remember this");
    expect(getRes.body.result.content[0].text).toContain("## Notes");
  });

  test("get_context with the wrong age key fails to decrypt", async () => {
    const userId = await createTestUser("303", "mcp-wrongkey");
    await createApiKey(userId, "mem_mcp_wrongkey_key");
    const ageKey = await generateAgeKey();
    const wrongKey = await generateAgeKey();

    await rpc(
      "tools/call",
      { name: "add_note", arguments: { text: "secret", age_key: ageKey } },
      "mem_mcp_wrongkey_key",
    );

    const { body } = await rpc(
      "tools/call",
      { name: "get_context", arguments: { age_key: wrongKey } },
      "mem_mcp_wrongkey_key",
    );
    expect(body.result.isError).toBe(true);
  });

  test("search filters lines by query", async () => {
    const userId = await createTestUser("304", "mcp-search");
    await createApiKey(userId, "mem_mcp_search_key");
    const ageKey = await generateAgeKey();

    await rpc(
      "tools/call",
      { name: "add_note", arguments: { text: "findme please", age_key: ageKey } },
      "mem_mcp_search_key",
    );
    const { body } = await rpc(
      "tools/call",
      { name: "search", arguments: { query: "findme", age_key: ageKey } },
      "mem_mcp_search_key",
    );
    expect(body.result.content[0].text).toContain("findme please");
  });
});
