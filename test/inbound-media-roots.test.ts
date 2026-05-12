import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { clearInboundState, dispatchInboundMessage } from "../src/inbound-dispatcher.ts";
import { yzjMessageActions } from "../src/actions.ts";

function testWorkspaceRoot(): string {
  return path.join(os.tmpdir(), "openclaw-yzj-test-workspace");
}

function testWorkspaceConfig(workspaceRoot: string): Record<string, unknown> {
  return {
    agents: {
      list: [
        {
          id: "main",
          workspace: workspaceRoot,
        },
      ],
    },
  };
}

function createYZJToolContext(turnId: string, replySummary = "发给我一个猫的图片"): Record<string, unknown> {
  return {
    currentChannelId: "user:open-1",
    currentChannelProvider: "yzj",
    currentMessageId: turnId,
    yzjReply: {
      replyOpenId: "open-1",
      replyMsgId: turnId,
      replyRootMsgId: turnId,
      replySummary,
      replyPersonName: "用户",
      replyTitle: "",
      notifyTo: ["open-1"],
    },
  };
}

function createCoreDeliveringMedia(mediaUrl: string): any {
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
          dispatcherOptions.deliver({ text: "", mediaUrl });
        },
      },
      text: {
        resolveMarkdownTableMode: () => "preserve",
        convertMarkdownTables: (value: string) => value,
      },
    },
  };
}

function createCoreDeliveringTextThenMedia(mediaUrl: string): any {
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
          await dispatcherOptions.deliver({ text: "第一段进度说明，长度明确超过二十个字，应该先发送出去。" }, { kind: "block" });
          await dispatcherOptions.deliver({ text: "图片如下：", mediaUrl }, { kind: "block" });
        },
      },
      text: {
        resolveMarkdownTableMode: () => "preserve",
        convertMarkdownTables: (value: string) => value,
      },
    },
  };
}

function createCoreDeliveringTextThenMessageTool(mediaUrl: string, mediaLocalRoot: string, accountId: string, turnId: string): any {
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
        dispatchReplyWithBufferedBlockDispatcher: async ({ dispatcherOptions, replyOptions }: any) => {
          const blockPayload = { text: "我先抓一下行情，再给你做个小图。" };
          await replyOptions?.onBlockReplyQueued?.(blockPayload, { kind: "block" });
          await yzjMessageActions.handleAction!({
            channel: "yzj",
            action: "send",
            cfg: {
              channels: {
                yzj: {
                  enabled: true,
                  endpoint: "https://dev.kdweibo.cn",
                  appId: "app-1",
                  appSecret: "secret-1",
                },
              },
            },
            accountId,
            params: {
              path: mediaUrl,
              message: "行情小图。",
            },
            toolContext: createYZJToolContext(turnId),
            mediaLocalRoots: [mediaLocalRoot],
          } as any);
          await dispatcherOptions.deliver({ ...blockPayload }, { kind: "block" });
        },
      },
      text: {
        resolveMarkdownTableMode: () => "preserve",
        convertMarkdownTables: (value: string) => value,
      },
    },
  };
}

function createCoreDeliveringPartialTextThenToolStartThenMediaThenDuplicateFinal(mediaUrl: string, mediaLocalRoot: string, accountId: string, turnId: string): any {
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
        dispatchReplyWithBufferedBlockDispatcher: async ({ dispatcherOptions, replyOptions }: any) => {
          await replyOptions?.onPartialReply?.({ text: "我先查一下今天金蝶的实时走势，再给你做张图。" });
          await replyOptions?.onToolStart?.({ name: "web_fetch", phase: "start" });
          await yzjMessageActions.handleAction!({
            channel: "yzj",
            action: "send",
            cfg: {
              channels: {
                yzj: {
                  enabled: true,
                  endpoint: "https://dev.kdweibo.cn",
                  appId: "app-1",
                  appSecret: "secret-1",
                },
              },
            },
            accountId,
            params: {
              path: mediaUrl,
              message: "金蝶国际今日走势图。",
            },
            toolContext: createYZJToolContext(turnId),
            mediaLocalRoots: [mediaLocalRoot],
          } as any);
          await dispatcherOptions.deliver({
            text: "我先查一下今天金蝶的实时走势，再给你做张图。",
          }, { kind: "final" });
        },
      },
      text: {
        resolveMarkdownTableMode: () => "preserve",
        convertMarkdownTables: (value: string) => value,
      },
    },
  };
}

function createCoreDeliveringMessageToolThenFinalText(mediaUrl: string, mediaLocalRoot: string, accountId: string, turnId: string): any {
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
          await yzjMessageActions.handleAction!({
            channel: "yzj",
            action: "send",
            cfg: {
              channels: {
                yzj: {
                  enabled: true,
                  endpoint: "https://dev.kdweibo.cn",
                  appId: "app-1",
                  appSecret: "secret-1",
                },
              },
            },
            accountId,
            params: {
              path: mediaUrl,
              message: "金蝶国际今日走势图。",
            },
            toolContext: createYZJToolContext(turnId),
            mediaLocalRoots: [mediaLocalRoot],
          } as any);
          await dispatcherOptions.deliver({
            text: "我把图再发一次。金蝶国际今天盘中是偏强的。",
          }, { kind: "final" });
        },
      },
      text: {
        resolveMarkdownTableMode: () => "preserve",
        convertMarkdownTables: (value: string) => value,
      },
    },
  };
}

function createCoreDeliveringMessageToolThenDuplicateFinalText(mediaUrl: string, mediaLocalRoot: string, accountId: string, turnId: string): any {
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
          await yzjMessageActions.handleAction!({
            channel: "yzj",
            action: "send",
            cfg: {
              channels: {
                yzj: {
                  enabled: true,
                  endpoint: "https://dev.kdweibo.cn",
                  appId: "app-1",
                  appSecret: "secret-1",
                },
              },
            },
            accountId,
            params: {
              path: mediaUrl,
              message: "给你一只猫 ",
            },
            toolContext: createYZJToolContext(turnId),
            mediaLocalRoots: [mediaLocalRoot],
          } as any);
          await dispatcherOptions.deliver({
            text: "给你一只猫 ",
          }, { kind: "final" });
        },
      },
      text: {
        resolveMarkdownTableMode: () => "preserve",
        convertMarkdownTables: (value: string) => value,
      },
    },
  };
}

function createCoreDeliveringMessageToolThenBlockText(mediaUrl: string, mediaLocalRoot: string, accountId: string, turnId: string): any {
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
          await yzjMessageActions.handleAction!({
            channel: "yzj",
            action: "send",
            cfg: {
              channels: {
                yzj: {
                  enabled: true,
                  endpoint: "https://dev.kdweibo.cn",
                  appId: "app-1",
                  appSecret: "secret-1",
                },
              },
            },
            accountId,
            params: {
              path: mediaUrl,
              message: "给你一只猫。",
            },
            toolContext: createYZJToolContext(turnId),
            mediaLocalRoots: [mediaLocalRoot],
          } as any);
          await dispatcherOptions.deliver({
            text: "我再按云之家当前会话账号重发一次，用文件方式试。",
          }, { kind: "block" });
        },
      },
      text: {
        resolveMarkdownTableMode: () => "preserve",
        convertMarkdownTables: (value: string) => value,
      },
    },
  };
}

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

test("dispatchInboundMessage allows media payloads from agent workspace roots", async () => {
  const workspaceRoot = testWorkspaceRoot();
  const config = testWorkspaceConfig(workspaceRoot);
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const filePath = path.join(workspaceRoot, "123456.txt");
  const previousContent = fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined;
  fs.writeFileSync(filePath, "123456");

  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    if (String(url).endsWith("/api/oauth2_v12/auth/getAppAccessToken")) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/docrest/doc/file/uploadfileOpen")) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "file-1" }] }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 });
  }) as typeof fetch;

  try {
    clearInboundState("workspace-root-test");
    await dispatchInboundMessage({
      account: {
        accountId: "workspace-root-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config,
      },
      config,
      runtime: {},
      core: createCoreDeliveringMedia(filePath),
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId: `workspace-root-${Date.now()}`,
      content: "把 txt 发给我",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.equal(calls.length, 3);
    assert.equal(calls[1]!.url, "https://dev.kdweibo.cn/gateway/docrest/doc/file/uploadfileOpen");
    const msgId = JSON.parse(String(calls[2]!.init.body)).param.replyMsgId;
    assert.deepEqual(JSON.parse(String(calls[2]!.init.body)), {
      toOpenId: "open-1",
      msgType: 8,
      content: "[文件]:123456.txt",
      param: {
        file_id: "file-1",
        name: "123456.txt",
        size: 6,
        ext: "txt",
        ftype: 0,
        unreadMonitor: 1,
        replyOpenId: "open-1",
        replyMsgId: msgId,
        replyRootMsgId: msgId,
        replySummary: "把 txt 发给我",
        replyPersonName: "用户",
        replyTitle: "",
        notifyTo: ["open-1"],
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (previousContent === undefined) {
      fs.rmSync(filePath, { force: true });
    } else {
      fs.writeFileSync(filePath, previousContent);
    }
    clearInboundState("workspace-root-test");
  }
});

test("dispatchInboundMessage preserves reply order when text is followed by media", async () => {
  const workspaceRoot = testWorkspaceRoot();
  const config = testWorkspaceConfig(workspaceRoot);
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const filePath = path.join(workspaceRoot, "ordered.png");
  const previousContent = fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined;
  fs.writeFileSync(filePath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

  const sendBodies: unknown[] = [];
  let tokenCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    if (String(url).endsWith("/api/oauth2_v12/auth/getAppAccessToken")) {
      tokenCalls += 1;
      if (tokenCalls === 1) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/docrest/doc/file/uploadfileOpen")) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-1" }] }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/xtinterface/message/send")) {
      sendBodies.push(JSON.parse(String((init as RequestInit).body)));
      return new Response(JSON.stringify({ success: true, data: { msgId: `msg-${sendBodies.length}` } }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    clearInboundState("reply-order-test");
    await dispatchInboundMessage({
      account: {
        accountId: "reply-order-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config,
      },
      config,
      runtime: {},
      core: createCoreDeliveringTextThenMedia(filePath),
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId: `reply-order-${Date.now()}`,
      content: "先说话再发图片",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.equal(sendBodies.length, 2);
    assert.equal((sendBodies[0] as any).msgType, 2);
    assert.equal((sendBodies[1] as any).msgType, 23);
    assert.equal((sendBodies[1] as any).content, "[图片]图片如下：");
  } finally {
    globalThis.fetch = originalFetch;
    if (previousContent === undefined) {
      fs.rmSync(filePath, { force: true });
    } else {
      fs.writeFileSync(filePath, previousContent);
    }
    clearInboundState("reply-order-test");
  }
});

test("dispatchInboundMessage preserves reply order between buffered text and message tool media", async () => {
  const workspaceRoot = testWorkspaceRoot();
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const filePath = path.join(workspaceRoot, "tool-ordered.png");
  const previousContent = fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined;
  fs.writeFileSync(filePath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

  const sendBodies: unknown[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    if (String(url).endsWith("/api/oauth2_v12/auth/getAppAccessToken")) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/docrest/doc/file/uploadfileOpen")) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-tool-1" }] }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/xtinterface/message/send")) {
      sendBodies.push(JSON.parse(String((init as RequestInit).body)));
      return new Response(JSON.stringify({ success: true, data: { msgId: `msg-${sendBodies.length}` } }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    clearInboundState("reply-tool-order-test");
    const msgId = `reply-tool-order-${Date.now()}`;
    await dispatchInboundMessage({
      account: {
        accountId: "reply-tool-order-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config: {},
      },
      config: {},
      runtime: {},
      core: createCoreDeliveringTextThenMessageTool(filePath, workspaceRoot, "reply-tool-order-test", msgId),
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId,
      content: "查行情并发图",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.equal(sendBodies.length, 2);
    assert.equal((sendBodies[0] as any).msgType, 2);
    assert.equal((sendBodies[0] as any).content, "我先抓一下行情，再给你做个小图。");
    assert.equal((sendBodies[1] as any).msgType, 23);
    assert.equal((sendBodies[1] as any).content, "[图片]行情小图。");
  } finally {
    globalThis.fetch = originalFetch;
    if (previousContent === undefined) {
      fs.rmSync(filePath, { force: true });
    } else {
      fs.writeFileSync(filePath, previousContent);
    }
    clearInboundState("reply-tool-order-test");
  }
});

test("dispatchInboundMessage sends ordinary assistant progress text before later media", async () => {
  const workspaceRoot = testWorkspaceRoot();
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const filePath = path.join(workspaceRoot, "tool-message-order.png");
  const previousContent = fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined;
  fs.writeFileSync(filePath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

  const requestOrder: string[] = [];
  const sendBodies: any[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    if (String(url).endsWith("/api/oauth2_v12/auth/getAppAccessToken")) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/docrest/doc/file/uploadfileOpen")) {
      requestOrder.push("upload");
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-message-1" }] }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/xtinterface/message/send")) {
      const body = JSON.parse(String((init as RequestInit).body));
      sendBodies.push(body);
      requestOrder.push(`send:${body.msgType}`);
      return new Response(JSON.stringify({ success: true, data: { msgId: `msg-${requestOrder.length}` } }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    clearInboundState("reply-tool-message-order-test");
    const msgId = `reply-tool-message-order-${Date.now()}`;
    await dispatchInboundMessage({
      account: {
        accountId: "reply-tool-message-order-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config: {},
      },
      config: {},
      runtime: {},
      core: createCoreDeliveringPartialTextThenToolStartThenMediaThenDuplicateFinal(filePath, workspaceRoot, "reply-tool-message-order-test", msgId),
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId,
      content: "发给我一个猫的图片",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.deepEqual(requestOrder, ["send:2", "upload", "send:23"]);
    assert.deepEqual(sendBodies[1].param, {
      desc: [{ type: "image", data: "image-message-1", w: 800, h: 600 }],
      replyOpenId: "open-1",
      replyMsgId: msgId,
      replyRootMsgId: msgId,
      replySummary: "发给我一个猫的图片",
      replyPersonName: "用户",
      replyTitle: "",
      notifyTo: ["open-1"],
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (previousContent === undefined) {
      fs.rmSync(filePath, { force: true });
    } else {
      fs.writeFileSync(filePath, previousContent);
    }
    clearInboundState("reply-tool-message-order-test");
  }
});

test("dispatchInboundMessage preserves final text after message tool media in generated order", async () => {
  const workspaceRoot = testWorkspaceRoot();
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const filePath = path.join(workspaceRoot, "tool-final-duplicate.png");
  const previousContent = fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined;
  fs.writeFileSync(filePath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

  const sendBodies: unknown[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    if (String(url).endsWith("/api/oauth2_v12/auth/getAppAccessToken")) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/docrest/doc/file/uploadfileOpen")) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-final-1" }] }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/xtinterface/message/send")) {
      sendBodies.push(JSON.parse(String((init as RequestInit).body)));
      return new Response(JSON.stringify({ success: true, data: { msgId: `msg-${sendBodies.length}` } }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    clearInboundState("reply-tool-final-test");
    const msgId = `reply-tool-final-${Date.now()}`;
    await dispatchInboundMessage({
      account: {
        accountId: "reply-tool-final-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config: {},
      },
      config: {},
      runtime: {},
      core: createCoreDeliveringMessageToolThenFinalText(filePath, workspaceRoot, "reply-tool-final-test", msgId),
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId,
      content: "查行情并发图",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.equal(sendBodies.length, 2);
    assert.equal((sendBodies[0] as any).msgType, 23);
    assert.equal((sendBodies[0] as any).content, "[图片]金蝶国际今日走势图。");
    assert.equal((sendBodies[1] as any).msgType, 2);
    assert.equal((sendBodies[1] as any).content, "我把图再发一次。金蝶国际今天盘中是偏强的。");
  } finally {
    globalThis.fetch = originalFetch;
    if (previousContent === undefined) {
      fs.rmSync(filePath, { force: true });
    } else {
      fs.writeFileSync(filePath, previousContent);
    }
    clearInboundState("reply-tool-final-test");
  }
});

test("dispatchInboundMessage skips duplicate final text already sent as media caption", async () => {
  const workspaceRoot = testWorkspaceRoot();
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const filePath = path.join(workspaceRoot, "tool-final-caption-duplicate.png");
  const previousContent = fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined;
  fs.writeFileSync(filePath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

  const sendBodies: unknown[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    if (String(url).endsWith("/api/oauth2_v12/auth/getAppAccessToken")) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/docrest/doc/file/uploadfileOpen")) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-caption-1" }] }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/xtinterface/message/send")) {
      sendBodies.push(JSON.parse(String((init as RequestInit).body)));
      return new Response(JSON.stringify({ success: true, data: { msgId: `msg-${sendBodies.length}` } }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    clearInboundState("reply-tool-caption-duplicate-test");
    const msgId = `reply-tool-caption-duplicate-${Date.now()}`;
    await dispatchInboundMessage({
      account: {
        accountId: "reply-tool-caption-duplicate-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config: {},
      },
      config: {},
      runtime: {},
      core: createCoreDeliveringMessageToolThenDuplicateFinalText(filePath, workspaceRoot, "reply-tool-caption-duplicate-test", msgId),
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId,
      content: "给我发一张猫图",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.equal(sendBodies.length, 1);
    assert.equal((sendBodies[0] as any).msgType, 23);
    assert.equal((sendBodies[0] as any).content, "[图片]给你一只猫");
  } finally {
    globalThis.fetch = originalFetch;
    if (previousContent === undefined) {
      fs.rmSync(filePath, { force: true });
    } else {
      fs.writeFileSync(filePath, previousContent);
    }
    clearInboundState("reply-tool-caption-duplicate-test");
  }
});

test("dispatchInboundMessage preserves block text after message tool media in generated order", async () => {
  const workspaceRoot = testWorkspaceRoot();
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const filePath = path.join(workspaceRoot, "tool-block-duplicate.png");
  const previousContent = fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined;
  fs.writeFileSync(filePath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

  const sendBodies: unknown[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    if (String(url).endsWith("/api/oauth2_v12/auth/getAppAccessToken")) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/docrest/doc/file/uploadfileOpen")) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-block-1" }] }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/xtinterface/message/send")) {
      sendBodies.push(JSON.parse(String((init as RequestInit).body)));
      return new Response(JSON.stringify({ success: true, data: { msgId: `msg-${sendBodies.length}` } }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    clearInboundState("reply-tool-block-test");
    const msgId = `reply-tool-block-${Date.now()}`;
    await dispatchInboundMessage({
      account: {
        accountId: "reply-tool-block-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config: {},
      },
      config: {},
      runtime: {},
      core: createCoreDeliveringMessageToolThenBlockText(filePath, workspaceRoot, "reply-tool-block-test", msgId),
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId,
      content: "给我发一张猫图",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.equal(sendBodies.length, 2);
    assert.equal((sendBodies[0] as any).msgType, 23);
    assert.equal((sendBodies[0] as any).content, "[图片]给你一只猫。");
    assert.equal((sendBodies[1] as any).msgType, 2);
    assert.equal((sendBodies[1] as any).content, "我再按云之家当前会话账号重发一次，用文件方式试。");
  } finally {
    globalThis.fetch = originalFetch;
    if (previousContent === undefined) {
      fs.rmSync(filePath, { force: true });
    } else {
      fs.writeFileSync(filePath, previousContent);
    }
    clearInboundState("reply-tool-block-test");
  }
});

test("dispatchInboundMessage keeps later inbound turns independent after message tool media", async () => {
  const workspaceRoot = testWorkspaceRoot();
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const filePath = path.join(workspaceRoot, "tool-final-turn.png");
  const previousContent = fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined;
  fs.writeFileSync(filePath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

  const sendBodies: unknown[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    if (String(url).endsWith("/api/oauth2_v12/auth/getAppAccessToken")) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/docrest/doc/file/uploadfileOpen")) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-turn-1" }] }), { status: 200 });
    }
    if (String(url).endsWith("/gateway/xtinterface/message/send")) {
      sendBodies.push(JSON.parse(String((init as RequestInit).body)));
      return new Response(JSON.stringify({ success: true, data: { msgId: `msg-${sendBodies.length}` } }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    clearInboundState("reply-tool-turn-test");
    const firstMsgId = `reply-tool-turn-first-${Date.now()}`;
    await dispatchInboundMessage({
      account: {
        accountId: "reply-tool-turn-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config: {},
      },
      config: {},
      runtime: {},
      core: createCoreDeliveringMessageToolThenFinalText(filePath, workspaceRoot, "reply-tool-turn-test", firstMsgId),
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId: firstMsgId,
      content: "查行情并发图",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    await dispatchInboundMessage({
      account: {
        accountId: "reply-tool-turn-test",
        enabled: true,
        configured: true,
        endpoint: "https://dev.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "",
        webhookPath: "/yzj/webhook",
        timeout: 10000,
        inboundMode: "websocket",
        mediaLocalRoots: [],
        config: {},
      },
      config: {},
      runtime: {},
      core: createCoreDeliveringFinalText("第二轮普通回复应该正常发送。"),
    } as any, {
      type: 2,
      robotId: "robot-1",
      robotName: "应用测试",
      operatorOpenid: "open-1",
      operatorName: "用户",
      time: Date.now(),
      msgId: `reply-tool-turn-second-${Date.now()}`,
      content: "你是谁",
      groupType: 3,
      groupId: "BOT-open-1-BOT-robot-1",
    }, "websocket");

    assert.equal(sendBodies.length, 3);
    assert.equal((sendBodies[0] as any).msgType, 23);
    assert.equal((sendBodies[1] as any).msgType, 2);
    assert.equal((sendBodies[1] as any).content, "我把图再发一次。金蝶国际今天盘中是偏强的。");
    assert.equal((sendBodies[2] as any).msgType, 2);
    assert.equal((sendBodies[2] as any).content, "第二轮普通回复应该正常发送。");
  } finally {
    globalThis.fetch = originalFetch;
    if (previousContent === undefined) {
      fs.rmSync(filePath, { force: true });
    } else {
      fs.writeFileSync(filePath, previousContent);
    }
    clearInboundState("reply-tool-turn-test");
  }
});
