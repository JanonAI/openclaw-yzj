import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { buildSignatureString, computeHmacSha1, verifySignature } from "../src/signature.ts";
import type { YZJIncomingMessage } from "../src/types.ts";

const msg: YZJIncomingMessage = {
  type: 2,
  robotId: "robot-1",
  robotName: "应用测试",
  operatorOpenid: "open-1",
  operatorName: "用户",
  time: 1778213000000,
  msgId: "msg-1",
  content: "hello",
  groupType: 3,
};

test("verifySignature validates HmacSHA1 webhook signatures", () => {
  const signature = computeHmacSha1(buildSignatureString(msg), "secret-1");

  assert.deepEqual(verifySignature(msg, signature, "secret-1"), { valid: true });
  assert.equal(verifySignature(msg, "bad-signature", "secret-1").valid, false);
});

test("verifySignature uses constant-time comparison helper", () => {
  const source = readFileSync(new URL("../src/signature.ts", import.meta.url), "utf8");

  assert.match(source, /timingSafeEqualBuffer\(/);
  assert.doesNotMatch(source, /signature\s*==\s*expectedSignature/);
  assert.doesNotMatch(source, /signature\s*===\s*expectedSignature/);
});
