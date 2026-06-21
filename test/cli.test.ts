import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { app } from "../src/app";
import { createApiKey, createTestUser, resetDb } from "./helpers";

describe("D6: CLI memory.sh", () => {
  let server: ReturnType<typeof Bun.serve>;
  let homeDir: string;

  beforeAll(() => {
    server = Bun.serve({ port: 0, fetch: app.fetch });
  });

  afterAll(() => {
    server.stop();
  });

  beforeEach(async () => {
    await resetDb();
    homeDir = `/tmp/membridge-cli-test-${crypto.randomUUID()}`;
    await Bun.spawn(["mkdir", "-p", homeDir]).exited;
  });

  afterEach(async () => {
    await Bun.spawn(["rm", "-rf", homeDir]).exited;
  });

  async function runCli(args: string[], env: Record<string, string> = {}) {
    const proc = Bun.spawn(["bash", `${import.meta.dir}/../cli/memory.sh`, ...args], {
      env: { ...process.env, HOME: homeDir, ...env },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    return { stdout, stderr, exitCode };
  }

  test("configure creates config + age identity", async () => {
    const { exitCode, stdout } = await runCli(["configure", "mem_cli_key"], {
      MEMORY_ENDPOINT: `http://localhost:${server.port}`,
    });
    expect(exitCode).toBe(0);
    expect(stdout).toContain("Configured");
    expect(await Bun.file(`${homeDir}/.memory/config`).exists()).toBe(true);
    expect(await Bun.file(`${homeDir}/.memory/key.txt`).exists()).toBe(true);
  });

  test("push then pull round-trips local context.md through real age encryption", async () => {
    const userId = await createTestUser("500", "cli-user");
    await createApiKey(userId, "mem_cli_roundtrip_key");

    await runCli(["configure", "mem_cli_roundtrip_key"], {
      MEMORY_ENDPOINT: `http://localhost:${server.port}`,
    });

    const content = "## Rules\n- test rule\n\n## Decisions\n\n## Notes\n- a note\n";
    await Bun.write(`${homeDir}/.memory/context.md`, content);

    const push = await runCli(["push"]);
    expect(push.exitCode).toBe(0);
    expect(push.stdout).toContain("Pushed");

    await Bun.spawn(["rm", "-f", `${homeDir}/.memory/context.md`]).exited;

    const pull = await runCli(["pull"]);
    expect(pull.exitCode).toBe(0);
    const pulled = await Bun.file(`${homeDir}/.memory/context.md`).text();
    expect(pulled).toBe(content);
  });

  test("pull fails clearly when not configured", async () => {
    const { exitCode, stderr } = await runCli(["pull"]);
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("Not configured");
  });
});
