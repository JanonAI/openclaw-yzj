import test from "node:test";
import assert from "node:assert/strict";

import {
  buildYZJSendByAppMessagePayload,
  buildYZJSendByAppPayload,
  sendYZJAppMessage,
  sendYZJAppTextMessage,
} from "../src/app-message.ts";
import { resolveYZJInboundConversation } from "../src/inbound-dispatcher.ts";

const account = {
  accountId: "default",
  endpoint: "https://dev.kdweibo.cn",
  appId: "app-1",
  appSecret: "secret-1",
  timeout: 10000,
} as any;

test("buildYZJSendByAppPayload targets groupId for V12Controller message/send", () => {
  assert.deepEqual(
    buildYZJSendByAppPayload({ groupId: "group-1", text: "hello" }),
    {
      groupId: "group-1",
      msgType: 2,
      content: "hello",
    },
  );
});

test("buildYZJSendByAppPayload adds replyOpenId param for replying to user message", () => {
  assert.deepEqual(
    buildYZJSendByAppPayload({
      groupId: "group-1",
      text: "收到",
      reply: {
        replyOpenId: "open-1",
        replyMsgId: "msg-1",
        replyRootMsgId: "root-1",
        replySummary: "今天深圳天气",
        replyPersonName: "用户",
        notifyTo: ["open-1"],
      },
    }),
    {
      groupId: "group-1",
      msgType: 2,
      content: "收到",
      param: {
        replyOpenId: "open-1",
        replyMsgId: "msg-1",
        replyRootMsgId: "root-1",
        replySummary: "今天深圳天气",
        replyPersonName: "用户",
        replyTitle: "",
        notifyTo: ["open-1"],
      },
    },
  );
});

test("resolveYZJInboundConversation sends app private chat replies by toOpenId", () => {
  assert.deepEqual(
    resolveYZJInboundConversation({
      groupType: 3,
      groupId: "BOT-user-1-BOT-robot-1",
      operatorOpenid: "user-1",
      robotId: "robot-1",
    }),
    {
      chatId: "user-1",
      chatType: "direct",
      groupIdForSend: "",
      toOpenIdForSend: "user-1",
      notifyOpenid: "",
      routePeer: { kind: "direct", id: "user-1" },
    },
  );
});

test("resolveYZJInboundConversation sends double private chat replies by toOpenId", () => {
  assert.deepEqual(
    resolveYZJInboundConversation({
      groupType: 1,
      groupId: "double-1",
      operatorOpenid: "user-1",
      robotId: "robot-1",
    }),
    {
      chatId: "user-1",
      chatType: "direct",
      groupIdForSend: "",
      toOpenIdForSend: "user-1",
      notifyOpenid: "",
      routePeer: { kind: "direct", id: "user-1" },
    },
  );
});

test("resolveYZJInboundConversation trusts groupType over BOT-like group ids", () => {
  assert.deepEqual(
    resolveYZJInboundConversation({
      groupType: 2,
      groupId: "BOT-like-normal-group",
      operatorOpenid: "user-1",
      robotId: "robot-1",
    }),
    {
      chatId: "BOT-like-normal-group",
      chatType: "group",
      groupIdForSend: "BOT-like-normal-group",
      toOpenIdForSend: "",
      notifyOpenid: "user-1",
      routePeer: { kind: "group", id: "BOT-like-normal-group" },
    },
  );
});

test("resolveYZJInboundConversation sends public multi chats by groupId", () => {
  assert.deepEqual(
    resolveYZJInboundConversation({
      groupType: 4,
      groupId: "public-group-1",
      operatorOpenid: "user-1",
      robotId: "robot-1",
    }),
    {
      chatId: "public-group-1",
      chatType: "group",
      groupIdForSend: "public-group-1",
      toOpenIdForSend: "",
      notifyOpenid: "user-1",
      routePeer: { kind: "group", id: "public-group-1" },
    },
  );
});

test("resolveYZJInboundConversation keeps normal multi-user groups on groupId", () => {
  assert.deepEqual(
    resolveYZJInboundConversation({
      groupType: 2,
      groupId: "group-1",
      operatorOpenid: "user-1",
      robotId: "robot-1",
    }),
    {
      chatId: "group-1",
      chatType: "group",
      groupIdForSend: "group-1",
      toOpenIdForSend: "",
      notifyOpenid: "user-1",
      routePeer: { kind: "group", id: "group-1" },
    },
  );
});

test("sendYZJAppTextMessage posts to V12Controller message/send with bearer token", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];

  const result = await sendYZJAppTextMessage(account, {
    groupId: "group-1",
    text: "hello",
  }, {
    tokenProvider: { getAccessToken: async () => "token-1" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      return new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 });
    },
  });

  assert.equal(result.ok, true);
  assert.equal(result.messageId, "msg-1");
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, "https://dev.kdweibo.cn/gateway/xtinterface/message/send");
  assert.deepEqual(calls[0]!.init.headers, {
    "Authorization": "Bearer token-1",
    "Content-Type": "application/json",
  });
  assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
    groupId: "group-1",
    msgType: 2,
    content: "hello",
  });
});

test("sendYZJAppMessage does not log V12Controller message/send request body", async () => {
  const logs: string[] = [];

  await sendYZJAppMessage(account, {
    toOpenId: "open-1",
    msgType: 23,
    content: "[图片]hello",
    param: {
      desc: [{ type: "image", data: "file-1", w: 800, h: 600 }],
    },
  }, {
    tokenProvider: { getAccessToken: async () => "token-1" },
    logger: { info: (message: string) => logs.push(message) },
    fetchImpl: async () => new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 }),
  } as any);

  assert.deepEqual(logs, []);
});

test("buildYZJSendByAppMessagePayload passes file message fields from AppV12Controller examples", () => {
  assert.deepEqual(
    buildYZJSendByAppMessagePayload({
      groupId: "group-1",
      msgType: 8,
      content: "[文件]:demo.doc",
      param: {
        file_id: "file-1",
        name: "demo.doc",
        size: 9216,
      },
    }),
    {
      groupId: "group-1",
      msgType: 8,
      content: "[文件]:demo.doc",
      param: {
        file_id: "file-1",
        name: "demo.doc",
        size: 9216,
      },
    },
  );
});

test("sendYZJAppMessage can send rich text image payload through message/send", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];

  const result = await sendYZJAppMessage(account, {
    groupId: "group-1",
    msgType: 23,
    content: "[图片]hello",
    param: {
      desc: [{ type: "image", data: "file-1", w: 800, h: 600 }],
    },
    msgLen: 8,
  }, {
    tokenProvider: { getAccessToken: async () => "token-1" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      return new Response(JSON.stringify({ success: true, errorCode: 0 }), { status: 200 });
    },
  });

  assert.equal(result.ok, true);
  assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
    groupId: "group-1",
    msgType: 23,
    content: "[图片]hello",
    param: {
      desc: [{ type: "image", data: "file-1", w: 800, h: 600 }],
    },
    msgLen: 8,
  });
});
