import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  classifyWebSocketPayload,
  DEFAULT_WEBSOCKET_HEALTH,
  getReconnectDelayMs,
  shouldReconnectAfterInvalidFrames,
} from "../src/websocket-client-helpers.ts";
import { YZJWebSocketClient } from "../src/websocket-client.ts";

test("websocket health settings use fixed heartbeat and stale defaults", () => {
  assert.deepEqual(DEFAULT_WEBSOCKET_HEALTH, { heartbeatMs: 15_000, staleMs: 45_000 });
});

test("default websocket factory does not disable TLS certificate verification", () => {
  const source = readFileSync(new URL("../src/websocket-client.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /rejectUnauthorized\s*:\s*false/);
});

test("reconnect backoff grows and caps at sixty seconds", () => {
  assert.equal(getReconnectDelayMs(0), 1_000);
  assert.equal(getReconnectDelayMs(1), 2_000);
  assert.equal(getReconnectDelayMs(2), 5_000);
  assert.equal(getReconnectDelayMs(3), 10_000);
  assert.equal(getReconnectDelayMs(4), 30_000);
  assert.equal(getReconnectDelayMs(5), 60_000);
  assert.equal(getReconnectDelayMs(8), 60_000);
});

test("invalid non-control websocket frames reconnect after three consecutive failures", () => {
  assert.equal(shouldReconnectAfterInvalidFrames(1), false);
  assert.equal(shouldReconnectAfterInvalidFrames(2), false);
  assert.equal(shouldReconnectAfterInvalidFrames(3), true);
});

test("auth websocket payload is treated as control traffic", () => {
  assert.deepEqual(
    classifyWebSocketPayload({ success: true, cmd: "auth" }),
    { kind: "control", reason: "auth" },
  );
});

test("ping websocket payload returns pong command", () => {
  assert.deepEqual(
    classifyWebSocketPayload({ cmd: "ping" }),
    { kind: "control", reason: "ping", ack: "{\"cmd\":\"pong\"}" },
  );
});

test("directPush websocket payload with needAck returns xt-websocket level1 ack command", () => {
  assert.deepEqual(
    classifyWebSocketPayload({
      msg: {
        dataKey: "replyCount",
        data: 1,
        dataEncoding: "int",
        msgChgTime: 1773978437058,
        groupId: "69ac29c1e4b0ad1b3b3b473b",
        msgId: "69bcc338e4b0c9f597559c80",
      },
      level: 1,
      needAck: true,
      cmd: "directPush",
      type: "msgChg",
      seq: 1,
    }),
    {
      kind: "control",
      reason: "directPush",
      ack: "{\"cmd\":\"directPush\",\"type\":\"ack\",\"bizType\":\"msgChg\",\"level\":1,\"endSeqId\":1}",
    },
  );
});

test("directPush websocket payload dispatches nested robot message and still returns ack", () => {
  assert.deepEqual(
    classifyWebSocketPayload({
      cmd: "directPush",
      type: "robotMessage",
      level: 1,
      needAck: true,
      seq: 7,
      msg: {
        type: 2,
        robotId: "robot-1",
        robotName: "Robot",
        operatorOpenid: "user-1",
        operatorName: "Alice",
        time: 1773978437058,
        msgId: "msg-1",
        content: "hello",
        groupType: 1,
      },
    }),
    {
      kind: "dispatch",
      message: {
        type: 2,
        robotId: "robot-1",
        robotName: "Robot",
        operatorOpenid: "user-1",
        operatorName: "Alice",
        time: 1773978437058,
        msgId: "msg-1",
        content: "hello",
        groupType: 1,
      },
      ack: "{\"cmd\":\"directPush\",\"type\":\"ack\",\"bizType\":\"robotMessage\",\"level\":1,\"endSeqId\":7}",
    },
  );
});

test("robot websocket business message preserves groupId for sendByApp replies", () => {
  assert.deepEqual(
    classifyWebSocketPayload({
      cmd: "directPush",
      type: "robotMessage",
      msg: {
        type: 2,
        robotId: "robot-1",
        robotName: "Robot",
        operatorOpenid: "user-1",
        operatorName: "Alice",
        time: 1773978437058,
        msgId: "msg-1",
        groupId: "group-1",
        content: "hello",
        groupType: 1,
      },
    }),
    {
      kind: "dispatch",
      message: {
        type: 2,
        robotId: "robot-1",
        robotName: "Robot",
        operatorOpenid: "user-1",
        operatorName: "Alice",
        time: 1773978437058,
        msgId: "msg-1",
        groupId: "group-1",
        content: "hello",
        groupType: 1,
      },
    },
  );
});

test("message websocket payload without business body is treated as notification", () => {
  assert.deepEqual(
    classifyWebSocketPayload({ cmd: "message", lastUpdateTime: "2026-03-20 11:47:17" }),
    { kind: "control", reason: "message" },
  );
});

test("messageRead websocket payload is treated as notification", () => {
  assert.deepEqual(
    classifyWebSocketPayload({ cmd: "messageRead", lastUpdateTime: "2026-03-20 13:20:38" }),
    { kind: "control", reason: "messageRead" },
  );
});

test("rapid websocket closes use growing reconnect backoff instead of resetting on open", async () => {
  const sockets: any[] = [];
  const reconnectTimeouts: Array<{ delay: number; run: () => void }> = [];
  const warnings: string[] = [];

  class FakeSocket {
    readyState = 0;
    listeners = new Map<string, Array<(event?: unknown) => void>>();

    addEventListener(type: string, listener: (event?: unknown) => void) {
      this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    send() {}
    close() {}

    emit(type: string, event?: unknown) {
      if (type === "open") this.readyState = 1;
      if (type === "close") this.readyState = 3;
      for (const listener of this.listeners.get(type) ?? []) listener(event);
    }
  }

  const client = new YZJWebSocketClient({
    url: "wss://example.test/xuntong/websocket?accessToken=token",
    target: {
      account: { accountId: "default" },
      config: {},
      runtime: {},
    } as any,
    logger: {
      info: () => {},
      warn: (message) => warnings.push(message),
    },
    WebSocketFactory: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket as any;
    },
    timers: {
      setTimeout: ((fn: (...args: unknown[]) => void, delay?: number) => {
        reconnectTimeouts.push({ delay: Number(delay), run: () => fn() });
        return reconnectTimeouts.length as any;
      }) as any,
      clearTimeout: (() => {}) as any,
      setInterval: (() => 1) as any,
      clearInterval: (() => {}) as any,
    },
  });

  client.start();
  await Promise.resolve();
  await Promise.resolve();
  sockets[0].emit("open");
  sockets[0].emit("close", { code: 1006, reason: "" });

  reconnectTimeouts.find((item) => item.delay === 1_000)!.run();
  await Promise.resolve();
  await Promise.resolve();
  sockets[1].emit("open");
  sockets[1].emit("close", { code: 1006, reason: "" });

  assert.deepEqual(
    warnings.filter((item) => item.includes("websocket reconnect scheduled")),
    [
      "[default] yzj websocket reconnect scheduled in 1000ms",
      "[default] yzj websocket reconnect scheduled in 2000ms",
    ],
  );
});

test("native websocket pong events keep the connection from being marked stale", async () => {
  const originalNow = Date.now;
  let now = 1_000;
  Date.now = () => now;

  const sockets: any[] = [];
  let intervalCallback: (() => void) | undefined;
  const warnings: string[] = [];

  class FakeSocket {
    readyState = 0;
    pingCount = 0;
    listeners = new Map<string, Array<(event?: unknown) => void>>();

    addEventListener(type: string, listener: (event?: unknown) => void) {
      this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    ping() {
      this.pingCount += 1;
    }

    send() {}
    close() {}

    emit(type: string, event?: unknown) {
      if (type === "open") this.readyState = 1;
      if (type === "close") this.readyState = 3;
      for (const listener of this.listeners.get(type) ?? []) listener(event);
    }
  }

  try {
    const client = new YZJWebSocketClient({
      url: "wss://example.test/xuntong/websocket?accessToken=token",
      target: {
        account: { accountId: "default" },
        config: {},
        runtime: {},
      } as any,
      logger: {
        info: () => {},
        warn: (message) => warnings.push(message),
      },
      WebSocketFactory: () => {
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket as any;
      },
      timers: {
        setTimeout: ((fn: (...args: unknown[]) => void) => fn() as any) as any,
        clearTimeout: (() => {}) as any,
        setInterval: ((fn: () => void) => {
          intervalCallback = fn;
          return 1 as any;
        }) as any,
        clearInterval: (() => {}) as any,
      },
    });

    client.start();
    await Promise.resolve();
    await Promise.resolve();
    sockets[0].emit("open");

    now = 16_000;
    intervalCallback?.();
    assert.equal(sockets[0].pingCount, 1);
    sockets[0].emit("pong");

    now = 60_000;
    intervalCallback?.();

    assert.equal(warnings.some((item) => item.includes("stale connection detected")), false);
  } finally {
    Date.now = originalNow;
  }
});

test("websocket ready status failures do not break connection startup", async () => {
  const sockets: any[] = [];
  const warnings: string[] = [];
  let intervalStarted = false;

  class FakeSocket {
    readyState = 0;
    listeners = new Map<string, Array<(event?: unknown) => void>>();

    addEventListener(type: string, listener: (event?: unknown) => void) {
      this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    send() {}
    close() {}

    emit(type: string, event?: unknown) {
      if (type === "open") this.readyState = 1;
      for (const listener of this.listeners.get(type) ?? []) listener(event);
    }
  }

  const client = new YZJWebSocketClient({
    url: "wss://example.test/xuntong/websocket?accessToken=token",
    target: {
      account: { accountId: "default" },
      config: {},
      runtime: {},
    } as any,
    logger: {
      info: () => {},
      warn: (message) => warnings.push(message),
    },
    WebSocketFactory: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket as any;
    },
    timers: {
      setTimeout: ((fn: (...args: unknown[]) => void) => fn() as any) as any,
      clearTimeout: (() => {}) as any,
      setInterval: (() => {
        intervalStarted = true;
        return 1 as any;
      }) as any,
      clearInterval: (() => {}) as any,
    },
    onReady: () => {
      throw new Error("status sink failed");
    },
  });

  client.start();
  await Promise.resolve();
  await Promise.resolve();

  assert.doesNotThrow(() => sockets[0].emit("open"));
  assert.equal(intervalStarted, true);
  assert.equal(warnings.some((item) => item.includes("websocket status update failed")), true);
});

test("business message dispatch failures are logged instead of becoming unhandled rejections", async () => {
  const sockets: any[] = [];
  const errors: string[] = [];

  class FakeSocket {
    readyState = 0;
    listeners = new Map<string, Array<(event?: unknown) => void>>();

    addEventListener(type: string, listener: (event?: unknown) => void) {
      this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    send() {}
    close() {}

    emit(type: string, event?: unknown) {
      if (type === "open") this.readyState = 1;
      for (const listener of this.listeners.get(type) ?? []) listener(event);
    }
  }

  const client = new YZJWebSocketClient({
    url: "wss://example.test/xuntong/websocket?accessToken=token",
    target: {
      account: { accountId: "default" },
      config: {},
      runtime: {},
    } as any,
    logger: {
      info: () => {},
      warn: () => {},
      error: (message) => errors.push(message),
    },
    WebSocketFactory: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket as any;
    },
    timers: {
      setTimeout: ((fn: (...args: unknown[]) => void) => fn() as any) as any,
      clearTimeout: (() => {}) as any,
      setInterval: (() => 1) as any,
      clearInterval: (() => {}) as any,
    },
  });

  client.start();
  await Promise.resolve();
  await Promise.resolve();
  sockets[0].emit("open");
  sockets[0].emit("message", {
    data: JSON.stringify({
      cmd: "directPush",
      type: "robotMessage",
      msg: {
        type: 2,
        robotId: "robot-1",
        robotName: "Robot",
        operatorOpenid: "user-1",
        operatorName: "Alice",
        time: 1773978437058,
        msgId: "msg-dispatch-fails",
        content: "hello",
        groupType: 1,
      },
    }),
  });
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(errors.some((item) => item.includes("yzj websocket dispatch failed")), true);
});

test("websocket parses buffer text frames before classifying business messages", async () => {
  const sockets: any[] = [];
  const dispatched: string[] = [];

  class FakeSocket {
    readyState = 0;
    listeners = new Map<string, Array<(event?: unknown) => void>>();

    addEventListener(type: string, listener: (event?: unknown) => void) {
      this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    send() {}
    close() {}

    emit(type: string, event?: unknown) {
      if (type === "open") this.readyState = 1;
      for (const listener of this.listeners.get(type) ?? []) listener(event);
    }
  }

  const client = new YZJWebSocketClient({
    url: "wss://example.test/xuntong/websocket?accessToken=token",
    target: {
      account: { accountId: "buffer-frame-test" },
      config: {},
      runtime: {},
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
              dispatched.push("dispatched");
            },
          },
          text: {
            resolveMarkdownTableMode: () => "preserve",
            convertMarkdownTables: (value: string) => value,
          },
        },
      },
    } as any,
    logger: {
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    WebSocketFactory: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket as any;
    },
    timers: {
      setTimeout: ((fn: (...args: unknown[]) => void) => fn() as any) as any,
      clearTimeout: (() => {}) as any,
      setInterval: (() => 1) as any,
      clearInterval: (() => {}) as any,
    },
  });

  client.start();
  await Promise.resolve();
  await Promise.resolve();
  sockets[0].emit("open");
  sockets[0].emit("message", {
    data: Buffer.from(JSON.stringify({
      cmd: "directPush",
      type: "robotMessage",
      msg: {
        type: 2,
        robotId: "robot-1",
        robotName: "Robot",
        operatorOpenid: "user-1",
        operatorName: "Alice",
        time: 1773978437058,
        msgId: "msg-buffer-frame",
        content: "hello",
        groupType: 1,
      },
    }), "utf8"),
  });
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(dispatched, ["dispatched"]);
});

test("stopping websocket client before async socket creation finishes closes the late socket", async () => {
  const closedSockets: Array<{ code?: number; reason?: string }> = [];
  let resolveFactory: ((socket: FakeSocket) => void) | undefined;
  let markFactoryEntered!: () => void;
  const factoryEntered = new Promise<void>((resolve) => {
    markFactoryEntered = resolve;
  });

  class FakeSocket {
    readyState = 0;
    listeners = new Map<string, Array<(event?: unknown) => void>>();

    addEventListener(type: string, listener: (event?: unknown) => void) {
      this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    send() {}

    close(code?: number, reason?: string) {
      closedSockets.push({ code, reason });
    }
  }

  const client = new YZJWebSocketClient({
    url: "wss://example.test/xuntong/websocket?accessToken=token",
    target: {
      account: { accountId: "default" },
      config: {},
      runtime: {},
    } as any,
    logger: {
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    WebSocketFactory: async () => new Promise<any>((resolve) => {
      resolveFactory = (socket: FakeSocket) => resolve(socket as any);
      markFactoryEntered();
    }) as any,
    timers: {
      setTimeout: ((fn: (...args: unknown[]) => void) => fn() as any) as any,
      clearTimeout: (() => {}) as any,
      setInterval: (() => 1) as any,
      clearInterval: (() => {}) as any,
    },
  });

  client.start();
  await factoryEntered;
  client.stop();

  const lateSocket = new FakeSocket();
  resolveFactory?.(lateSocket);
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(closedSockets.some((item) => item.code === 1000 && item.reason === "shutdown"), true);
});

test("invalid websocket payload logs only a summary instead of raw payload content", async () => {
  const sockets: any[] = [];
  const warnings: string[] = [];

  class FakeSocket {
    readyState = 0;
    listeners = new Map<string, Array<(event?: unknown) => void>>();

    addEventListener(type: string, listener: (event?: unknown) => void) {
      this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    send() {}
    close() {}

    emit(type: string, event?: unknown) {
      if (type === "open") this.readyState = 1;
      for (const listener of this.listeners.get(type) ?? []) listener(event);
    }
  }

  const client = new YZJWebSocketClient({
    url: "wss://example.test/xuntong/websocket?accessToken=token",
    target: {
      account: { accountId: "default" },
      config: {},
      runtime: {},
    } as any,
    logger: {
      info: () => {},
      warn: (message) => warnings.push(message),
      error: () => {},
    },
    WebSocketFactory: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket as any;
    },
    timers: {
      setTimeout: ((fn: (...args: unknown[]) => void) => fn() as any) as any,
      clearTimeout: (() => {}) as any,
      setInterval: (() => 1) as any,
      clearInterval: (() => {}) as any,
    },
  });

  client.start();
  await Promise.resolve();
  await Promise.resolve();
  sockets[0].emit("open");
  sockets[0].emit("message", {
    data: JSON.stringify({
      content: "private user content",
      accessToken: "secret-token",
    }),
  });
  await Promise.resolve();
  await Promise.resolve();

  const combined = warnings.join("\n");
  assert.match(combined, /payload summary:/);
  assert.doesNotMatch(combined, /private user content/);
  assert.doesNotMatch(combined, /secret-token/);
});
