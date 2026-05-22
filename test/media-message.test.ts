import test from "node:test";
import assert from "node:assert/strict";

import { uploadAndSendYZJAppMedia } from "../src/media-message.ts";

const account = {
  accountId: "default",
  endpoint: "https://dev.kdweibo.cn",
  appId: "app-1",
  appSecret: "secret-1",
  timeout: 10000,
} as any;

const oneByOnePng = Buffer.from(
  "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63600000020001e221bc330000000049454e44ae426082",
  "hex",
);

test("uploadAndSendYZJAppMedia uploads mp4 and sends it as msgType 8 file", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];

  const result = await uploadAndSendYZJAppMedia(account, {
    toOpenId: "open-1",
    mediaBuffer: Buffer.from("video-bytes"),
    fileName: "111.mp4",
  }, {
    tokenProvider: { getAccessToken: async () => "token-1" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      if (calls.length === 1) {
        return new Response(JSON.stringify({ success: true, data: { fileId: "file-1" } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 });
    },
  });

  assert.equal(result.ok, true);
  assert.equal(result.messageId, "msg-1");
  assert.equal(calls.length, 2);
  assert.equal(calls[0]!.url, "https://dev.kdweibo.cn/gateway/docrest/doc/file/uploadfileOpen");
  assert.deepEqual(calls[0]!.init.headers, {
    Authorization: "Bearer token-1",
  });
  assert.equal(calls[1]!.url, "https://dev.kdweibo.cn/gateway/xtinterface/message/send");
  assert.deepEqual(JSON.parse(String(calls[1]!.init.body)), {
    toOpenId: "open-1",
    msgType: 8,
    content: "[文件]:111.mp4",
    param: {
      file_id: "file-1",
      name: "111.mp4",
      size: 11,
      ext: "mp4",
      ftype: 0,
      unreadMonitor: 1,
    },
  });
});

test("uploadAndSendYZJAppMedia keeps reply param on file sends", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];

  const result = await uploadAndSendYZJAppMedia(account, {
    toOpenId: "open-1",
    mediaBuffer: Buffer.from("file-bytes"),
    fileName: "demo.txt",
    reply: {
      replyOpenId: "open-1",
      replyMsgId: "msg-1",
      replyRootMsgId: "msg-1",
      replySummary: "今天深圳天气",
      replyPersonName: "用户",
      notifyTo: ["open-1"],
    },
  }, {
    tokenProvider: { getAccessToken: async () => "token-1" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      if (calls.length === 1) {
        return new Response(JSON.stringify({ success: true, data: { fileId: "file-1" } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 });
    },
  });

  assert.equal(result.ok, true);
  assert.deepEqual(JSON.parse(String(calls[1]!.init.body)), {
    toOpenId: "open-1",
    msgType: 8,
    content: "[文件]:demo.txt",
    param: {
      file_id: "file-1",
      name: "demo.txt",
      size: 10,
      ext: "txt",
      ftype: 0,
      unreadMonitor: 1,
      replyOpenId: "open-1",
      replyMsgId: "msg-1",
      replyRootMsgId: "msg-1",
      replySummary: "今天深圳天气",
      replyPersonName: "用户",
      notifyTo: ["open-1"],
    },
  });
});

test("uploadAndSendYZJAppMedia sends png as msgType 23 rich image", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];

  const result = await uploadAndSendYZJAppMedia(account, {
    groupId: "group-1",
    text: "hello",
    mediaBuffer: oneByOnePng,
    fileName: "demo.png",
  }, {
    tokenProvider: { getAccessToken: async () => "token-1" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      if (calls.length === 1) {
        return new Response(JSON.stringify({ success: true, data: { file_id: "image-file-1" } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: true, data: { msgId: "msg-2" } }), { status: 200 });
    },
  });

  assert.equal(result.ok, true);
  assert.equal(result.messageId, "msg-2");
  assert.deepEqual(JSON.parse(String(calls[1]!.init.body)), {
    groupId: "group-1",
    msgType: 23,
    content: "hello\n[图片]",
    param: {
      desc: [{ type: "image", data: "image-file-1", w: 1, h: 1 }],
    },
  });
});

test("uploadAndSendYZJAppMedia keeps reply param and visible at on rich image sends", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];

  const result = await uploadAndSendYZJAppMedia(account, {
    groupId: "group-1",
    text: "深圳天气图",
    mediaBuffer: oneByOnePng,
    fileName: "weather.png",
    reply: {
      replyOpenId: "open-1",
      replyMsgId: "msg-1",
      replyRootMsgId: "msg-1",
      replySummary: "@王振宇V12测试513 今日深圳天气变化 弄一张图片发给我",
      replyPersonName: "杨好",
      notifyTo: ["open-1"],
    },
  }, {
    tokenProvider: { getAccessToken: async () => "token-1" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      if (calls.length === 1) {
        return new Response(JSON.stringify({ success: true, data: { fileId: "image-file-1" } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: true, data: { msgId: "msg-2" } }), { status: 200 });
    },
  });

  assert.equal(result.ok, true);
  assert.deepEqual(JSON.parse(String(calls[1]!.init.body)), {
    groupId: "group-1",
    msgType: 23,
    content: "深圳天气图\n[图片]",
    param: {
      desc: [
        { type: "image", data: "image-file-1", w: 1, h: 1 },
      ],
      replyOpenId: "open-1",
      replyMsgId: "msg-1",
      replyRootMsgId: "msg-1",
      replySummary: "@王振宇V12测试513 今日深圳天气变化 弄一张图片发给我",
      replyPersonName: "杨好",
      notifyTo: ["open-1"],
    },
  });
});

test("uploadAndSendYZJAppMedia detects extensionless png bytes as rich image", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];

  const result = await uploadAndSendYZJAppMedia(account, {
    toOpenId: "open-1",
    text: "hello",
    mediaBuffer: oneByOnePng,
    fileName: "cat",
  }, {
    tokenProvider: { getAccessToken: async () => "token-1" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      if (calls.length === 1) {
        return new Response(JSON.stringify({ success: true, data: { fileId: "image-file-1" } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: true, data: { msgId: "msg-2" } }), { status: 200 });
    },
  });

  assert.equal(result.ok, true);
  assert.deepEqual(JSON.parse(String(calls[1]!.init.body)), {
    toOpenId: "open-1",
    msgType: 23,
    content: "hello\n[图片]",
    param: {
      desc: [{ type: "image", data: "image-file-1", w: 1, h: 1 }],
    },
  });
});

test("uploadAndSendYZJAppMedia accepts uploadfileOpen array response", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];

  const result = await uploadAndSendYZJAppMedia(account, {
    toOpenId: "open-1",
    mediaBuffer: oneByOnePng,
    fileName: "demo.png",
  }, {
    tokenProvider: { getAccessToken: async () => "token-1" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      if (calls.length === 1) {
        return new Response(JSON.stringify({ success: true, error: null, errorCode: 0, data: [{ fileId: "array-file-1" }] }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: true, data: { msgId: "msg-3" } }), { status: 200 });
    },
  });

  assert.equal(result.ok, true);
  assert.equal(result.messageId, "msg-3");
});

test("uploadAndSendYZJAppMedia denies local file paths unless mediaLocalRoots is configured", async () => {
  await assert.rejects(
    () => uploadAndSendYZJAppMedia(account, {
      toOpenId: "open-1",
      mediaUrl: "C:\\secret\\demo.txt",
    }, {
      tokenProvider: { getAccessToken: async () => "token-1" },
      fetchImpl: async () => new Response("{}", { status: 200 }),
    }),
    /Local file access denied/,
  );
});

test("uploadAndSendYZJAppMedia denies private remote media addresses", async () => {
  await assert.rejects(
    () => uploadAndSendYZJAppMedia(account, {
      toOpenId: "open-1",
      mediaUrl: "http://127.0.0.1/demo.txt",
    }, {
      tokenProvider: { getAccessToken: async () => "token-1" },
      fetchImpl: async () => new Response("{}", { status: 200 }),
    }),
    /private\/reserved IP/,
  );
});

test("uploadAndSendYZJAppMedia rejects remote redirects instead of following them unchecked", async () => {
  await assert.rejects(
    () => uploadAndSendYZJAppMedia(account, {
      toOpenId: "open-1",
      mediaUrl: "https://example.com/demo.txt",
    }, {
      tokenProvider: { getAccessToken: async () => "token-1" },
      fetchImpl: async () => new Response("", {
        status: 302,
        headers: {
          Location: "http://127.0.0.1/private.txt",
        },
      }),
    }),
    /redirect/i,
  );
});

test("uploadAndSendYZJAppMedia rejects remote media larger than configured limit before buffering", async () => {
  await assert.rejects(
    () => uploadAndSendYZJAppMedia(account, {
      toOpenId: "open-1",
      mediaUrl: "https://example.com/large.bin",
    }, {
      tokenProvider: { getAccessToken: async () => "token-1" },
      fetchImpl: async () => new Response("too large", {
        status: 200,
        headers: {
          "Content-Length": String(51 * 1024 * 1024),
        },
      }),
    }),
    /too large/i,
  );
});

test("uploadAndSendYZJAppMedia rejects oversized mediaBuffer before uploading", async () => {
  let uploadCalled = false;
  await assert.rejects(
    () => uploadAndSendYZJAppMedia(account, {
      toOpenId: "open-1",
      mediaBuffer: Buffer.alloc(51 * 1024 * 1024),
      fileName: "large.bin",
    }, {
      tokenProvider: { getAccessToken: async () => "token-1" },
      fetchImpl: async () => {
        uploadCalled = true;
        return new Response("{}", { status: 200 });
      },
    }),
    /too large/i,
  );
  assert.equal(uploadCalled, false);
});

test("uploadAndSendYZJAppMedia rejects ipv4-mapped ipv6 private remote media addresses", async () => {
  await assert.rejects(
    () => uploadAndSendYZJAppMedia(account, {
      toOpenId: "open-1",
      mediaUrl: "http://[::ffff:127.0.0.1]/demo.txt",
    }, {
      tokenProvider: { getAccessToken: async () => "token-1" },
      fetchImpl: async () => new Response("{}", { status: 200 }),
    }),
    /private\/reserved IP/,
  );
});
