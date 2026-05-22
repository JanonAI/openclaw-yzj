import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";

import { computeHmacSha1, buildSignatureString } from "../src/signature.ts";
import { handleYZJWebhookRequest, registerYZJWebhookTarget } from "../src/monitor.ts";
import type { YZJIncomingMessage } from "../src/types.ts";

class FakeRequest extends EventEmitter {
  method: string;
  url: string;
  headers: Record<string, string>;

  constructor(params: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: unknown;
  }) {
    super();
    this.method = params.method ?? "POST";
    this.url = params.url ?? "/yzj/test";
    this.headers = params.headers ?? {};
    const body = params.body;
    queueMicrotask(() => {
      if (body !== undefined) {
        this.emit("data", Buffer.from(typeof body === "string" ? body : JSON.stringify(body)));
      }
      this.emit("end");
    });
  }

  destroy() {
    this.emit("error", new Error("destroyed"));
  }
}

class FakeResponse {
  statusCode = 200;
  headers: Record<string, string> = {};
  body = "";

  setHeader(name: string, value: string) {
    this.headers[name] = value;
  }

  end(value?: unknown) {
    this.body += value === undefined ? "" : String(value);
  }
}

function createMessage(overrides: Partial<YZJIncomingMessage> = {}): YZJIncomingMessage {
  return {
    type: 2,
    robotId: "robot-1",
    robotName: "应用测试",
    operatorOpenid: "open-1",
    operatorName: "用户",
    time: 1778216000000,
    msgId: "msg-1",
    content: "hello",
    groupType: 3,
    ...overrides,
  };
}

function createTarget(params: {
  accountId?: string;
  secret?: string;
  errors?: string[];
  infos?: string[];
  dispatched?: string[];
}) {
  const dispatched = params.dispatched ?? [];
  const accountId = params.accountId ?? "monitor-test";
  return {
    account: {
      accountId,
      secret: params.secret,
    },
    config: {},
    runtime: {
      error: (message: string) => params.errors?.push(message),
      info: (message: string) => params.infos?.push(message),
    },
    core: {
      channel: {
        routing: {
          resolveAgentRoute: () => ({
            agentId: "main",
            accountId: "default",
            sessionKey: "session-1",
          }),
        },
        session: {
          resolveStorePath: () => "memory",
          readSessionUpdatedAt: () => undefined,
          recordInboundSession: async () => undefined,
        },
        reply: {
          resolveEnvelopeFormatOptions: () => ({}),
          formatAgentEnvelope: ({ body }: { body: string }) => body,
          finalizeInboundContext: (ctx: unknown) => ctx,
          dispatchReplyWithBufferedBlockDispatcher: async () => {
            dispatched.push(accountId);
          },
        },
        text: {
          resolveMarkdownTableMode: () => "preserve",
          convertMarkdownTables: (value: string) => value,
        },
      },
    },
  } as any;
}

test("webhook signature cannot be bypassed with test robot id when secret is configured", async () => {
  const errors: string[] = [];
  const unregister = registerYZJWebhookTarget({
    ...createTarget({ secret: "secret-1", errors }),
    path: "/yzj/signature-bypass-test",
  });
  try {
    const req = new FakeRequest({
      url: "/yzj/signature-bypass-test",
      body: createMessage({ robotId: "test-robotId" }),
    });
    const res = new FakeResponse();

    await handleYZJWebhookRequest(req as any, res as any);

    assert.equal(res.statusCode, 401);
    assert.equal(res.body, "missing sign header");
  } finally {
    unregister();
  }
});

test("webhook invalid signature log does not leak raw signature material", async () => {
  const errors: string[] = [];
  const infos: string[] = [];
  const unregister = registerYZJWebhookTarget({
    ...createTarget({ secret: "secret-1", errors, infos }),
    path: "/yzj/signature-log-test",
  });
  try {
    const msg = createMessage({ content: "sensitive message" });
    const req = new FakeRequest({
      url: "/yzj/signature-log-test",
      headers: { sign: "bad-signature" },
      body: msg,
    });
    const res = new FakeResponse();

    await handleYZJWebhookRequest(req as any, res as any);

    const combined = errors.join("\n");
    assert.equal(res.statusCode, 401);
    assert.doesNotMatch(combined, /bad-signature/);
    assert.doesNotMatch(combined, /sensitive message/);
    assert.doesNotMatch(combined, new RegExp(computeHmacSha1(buildSignatureString(msg), "secret-1").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.equal(infos.some((item) => item.includes("webhook inbound body")), false);
  } finally {
    unregister();
  }
});

test("webhook logs inbound body after signature is accepted", async () => {
  const infos: string[] = [];
  const dispatched: string[] = [];
  const path = "/yzj/inbound-body-log-test";
  const msg = createMessage({ msgId: "msg-body-log", content: "hello body log" });
  const unregister = registerYZJWebhookTarget({
    ...createTarget({ secret: "secret-1", infos, dispatched }),
    path,
  });
  try {
    const req = new FakeRequest({
      url: path,
      headers: { sign: computeHmacSha1(buildSignatureString(msg), "secret-1") },
      body: msg,
    });
    const res = new FakeResponse();

    await handleYZJWebhookRequest(req as any, res as any);
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(res.statusCode, 200);
    assert.equal(infos.includes(`[yzj] webhook inbound body: ${JSON.stringify(msg)}`), true);
    assert.deepEqual(dispatched, ["monitor-test"]);
  } finally {
    unregister();
  }
});

test("webhook rejects malformed business message before dispatching", async () => {
  const dispatched: string[] = [];
  const unregister = registerYZJWebhookTarget({
    ...createTarget({ dispatched }),
    path: "/yzj/malformed-test",
  });
  try {
    const req = new FakeRequest({
      url: "/yzj/malformed-test",
      body: {
        content: "hello",
      },
    });
    const res = new FakeResponse();

    await handleYZJWebhookRequest(req as any, res as any);

    assert.equal(res.statusCode, 400);
    assert.equal(dispatched.length, 0);
  } finally {
    unregister();
  }
});

test("webhook verifies signature per target before dispatching shared path requests", async () => {
  const dispatched: string[] = [];
  const path = "/yzj/shared-secret-test";
  const msg = createMessage({ msgId: "shared-secret-msg" });
  const unregisterA = registerYZJWebhookTarget({
    ...createTarget({ accountId: "account-a", secret: "secret-a", dispatched }),
    path,
  });
  const unregisterB = registerYZJWebhookTarget({
    ...createTarget({ accountId: "account-b", secret: "secret-b", dispatched }),
    path,
  });
  try {
    const req = new FakeRequest({
      url: path,
      headers: { sign: computeHmacSha1(buildSignatureString(msg), "secret-a") },
      body: msg,
    });
    const res = new FakeResponse();

    await handleYZJWebhookRequest(req as any, res as any);
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(res.statusCode, 200);
    assert.deepEqual(dispatched, ["account-a"]);
  } finally {
    unregisterA();
    unregisterB();
  }
});
