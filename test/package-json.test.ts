import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("package.json keeps runtime dependencies limited to websocket client", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
    dependencies?: Record<string, string>;
  };

  assert.deepEqual(Object.keys(pkg.dependencies ?? {}).sort(), ["ws"]);
});

test("package.json includes OpenClaw plugin manifests in published package", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
    files?: string[];
  };

  assert.ok(pkg.files?.includes("openclaw.plugin.json"));
  assert.ok(pkg.files?.includes("clawdbot.plugin.json"));
});
