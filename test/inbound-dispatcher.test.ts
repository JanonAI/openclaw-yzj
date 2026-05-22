import test from "node:test";
import assert from "node:assert/strict";

import { yzjMessageActions } from "../src/actions.ts";
import { clearInboundState, dispatchInboundMessage } from "../src/inbound-dispatcher.ts";

function createCoreDeliveringFinalText(text: string): any {
  return {
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
        dispatchReplyWithBufferedBlockDispatcher: async ({ dispatcherOptions }: any) => {
          await dispatcherOptions.deliver({ text }, { kind: "final" });
        },
      },
      text: {
        resolveMarkdownTableMode: () => "preserve",
        convertMarkdownTables: (value: string) => value,
      },
    },
  };
}

test("dispatchInboundMessage continues processing when status sink throws", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const warnings: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as typeof fetch;

  try {
    clearInboundState("status-sink-test");
    const msgId = `status-sink-${Date.now()}`;
    await dispatchInboundMessage({
      account: {
        accountId: "status-sink-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "",
        appSecret: "",
        sendMsgUrl: "https://dev.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config: {},
      },
      config: {
        channels: {
          yzj: {
            enabled: true,
            endpoint: "https://dev.kdweibo.cn",
            accounts: {
              app2: {
                appId: "app-2",
                appSecret: "secret-2",
              },
            },
          },
        },
      },
      runtime: {
        warn: (message: string) => warnings.push(message),
      },
      core: createCoreDeliveringFinalText("深圳天气"),
      statusSink: () => {
        throw new Error("status unavailable");
      },
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId,
      content: "今天深圳天气",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.equal(calls.length, 1);
    assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
      msgtype: 2,
      content: "深圳天气",
    });
    assert.equal(warnings.some((line) => line.includes("status update failed")), true);
  } finally {
    globalThis.fetch = originalFetch;
    clearInboundState("status-sink-test");
  }
});

test("dispatchInboundMessage binds context AccountId to inbound account instead of route account", async () => {
  const capturedContexts: any[] = [];
  const logs: string[] = [];

  clearInboundState("personal");
  try {
    const msgId = `account-bind-${Date.now()}`;
    await dispatchInboundMessage({
      account: {
        accountId: "personal",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "",
        appSecret: "",
        sendMsgUrl: "https://dev.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config: {},
      },
      config: {
        channels: {
          yzj: {
            enabled: true,
            endpoint: "https://dev.kdweibo.cn",
            accounts: {
              app2: {
                appId: "app-2",
                appSecret: "secret-2",
              },
            },
          },
        },
      },
      runtime: {
        info: (message: string) => logs.push(message),
      },
      core: {
        channel: {
          routing: {
            resolveAgentRoute: () => ({
              agentId: "main",
              accountId: "app",
              sessionKey: "session-1",
            }),
          },
          session: {
            resolveStorePath: () => "memory",
            readSessionUpdatedAt: () => undefined,
            recordInboundSession: async ({ ctx }: any) => {
              capturedContexts.push(ctx);
            },
          },
          reply: {
            resolveEnvelopeFormatOptions: () => ({}),
            formatAgentEnvelope: ({ body }: { body: string }) => body,
            finalizeInboundContext: (ctx: unknown) => ctx,
            dispatchReplyWithBufferedBlockDispatcher: async () => undefined,
          },
          text: {
            resolveMarkdownTableMode: () => "preserve",
            convertMarkdownTables: (value: string) => value,
          },
        },
      },
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "个人机器人",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId,
      content: "发给我一个猫的图片",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.equal(capturedContexts.length, 1);
    assert.equal(capturedContexts[0]!.AccountId, "personal");
    assert.equal(logs.some((line) => line.includes("yzj inbound dispatch start")), true);
    assert.equal(logs.some((line) => line.includes("yzj inbound route resolved") && line.includes("agentId=main")), true);
    assert.equal(logs.some((line) => line.includes("yzj agent context prepared") && line.includes("accountId=personal")), true);
  } finally {
    clearInboundState("personal");
  }
});

