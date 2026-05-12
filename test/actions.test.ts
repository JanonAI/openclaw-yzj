import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { yzjMessageActions } from "../src/actions.ts";
import { yzjPlugin } from "../src/channel.ts";
import { YZJ_MEDIA_UNSUPPORTED_MESSAGE } from "../src/media-unsupported.ts";
import { resolveYZJSendTarget } from "../src/targets.ts";

const testDir = path.dirname(fileURLToPath(import.meta.url));

function toolResultText(result: Awaited<ReturnType<NonNullable<typeof yzjMessageActions.handleAction>>>): string {
  const first = result.content?.[0];
  return first && "text" in first ? String(first.text) : "";
}

test("yzj personal robot media unsupported message is user-facing", () => {
  assert.equal(
    YZJ_MEDIA_UNSUPPORTED_MESSAGE,
    "当前个人机器人只支持发送文本，暂不支持上传图片、文件或视频。",
  );
});

test("yzj message send action advertises media send support when configured", () => {
  const discovery = yzjMessageActions.describeMessageTool({
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
  } as any);

  assert.deepEqual(discovery?.actions, ["send"]);
  assert.deepEqual(discovery?.capabilities, []);
});

test("yzj message send action sends local image path as media", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    if (calls.length === 1) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (calls.length === 2) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-file-1" }] }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 });
  }) as typeof fetch;

  try {
    const result = await yzjMessageActions.handleAction!({
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
      params: {
        to: "open-1",
        message: "图片测试",
        path: "C:\\Users\\kingdee\\Desktop\\docs\\random-image.png",
      },
      mediaLocalRoots: ["C:\\Users\\kingdee\\Desktop\\docs"],
    } as any);

    assert.deepEqual(JSON.parse(toolResultText(result)), {
      ok: true,
      messageId: "msg-1",
    });
    assert.equal(calls[1]!.url, "https://dev.kdweibo.cn/gateway/docrest/doc/file/uploadfileOpen");
    assert.equal(calls[2]!.url, "https://dev.kdweibo.cn/gateway/xtinterface/message/send");
    assert.deepEqual(JSON.parse(String(calls[2]!.init.body)), {
      toOpenId: "open-1",
      msgType: 23,
      content: "[图片]图片测试",
      param: {
        desc: [{ type: "image", data: "image-file-1", w: 800, h: 600 }],
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj message send action defaults to current direct conversation for media", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    if (calls.length === 1) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (calls.length === 2) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-file-1" }] }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 });
  }) as typeof fetch;

  try {
    const result = await yzjMessageActions.handleAction!({
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
      params: {
        path: "C:\\Users\\kingdee\\Desktop\\docs\\random-image.png",
      },
      toolContext: {
        currentChannelId: "user:open-1",
        currentChannelProvider: "yzj",
      },
      mediaLocalRoots: ["C:\\Users\\kingdee\\Desktop\\docs"],
    } as any);

    assert.deepEqual(JSON.parse(toolResultText(result)), {
      ok: true,
      messageId: "msg-1",
    });
    assert.deepEqual(JSON.parse(String(calls[2]!.init.body)), {
      toOpenId: "open-1",
      msgType: 23,
      content: "[图片]",
      param: {
        desc: [{ type: "image", data: "image-file-1", w: 800, h: 600 }],
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj message send action explains media unsupported when only sendMsgUrl is configured", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as typeof fetch;

  try {
    const result = await yzjMessageActions.handleAction!({
      channel: "yzj",
      action: "send",
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            sendMsgUrl: "https://dev.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1",
          },
        },
      },
      params: {
        to: "open-1",
        path: "C:\\Users\\kingdee\\Desktop\\docs\\random-image.png",
      },
      mediaLocalRoots: ["C:\\Users\\kingdee\\Desktop\\docs"],
    } as any);

    assert.deepEqual(JSON.parse(toolResultText(result)), {
      ok: true,
      messageId: "",
      mediaUnsupported: true,
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "https://dev.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1");
    assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
      msgtype: 2,
      content: YZJ_MEDIA_UNSUPPORTED_MESSAGE,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj message send action returns structured local media denial instead of throwing", async () => {
  const result = await yzjMessageActions.handleAction!({
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
    params: {
      to: "open-1",
      path: "C:\\Users\\kingdee\\Desktop\\yzj.zip",
    },
    mediaLocalRoots: ["C:\\Users\\kingdee\\Desktop\\docs"],
  } as any);

  const payload = JSON.parse(toolResultText(result));
  assert.equal(payload.ok, false);
  assert.equal(payload.messageId, "");
  assert.equal(payload.mediaLocalRootsDenied, true);
  assert.match(payload.error, /mediaLocalRoots/);
});

test("yzj message send action merges account media roots with agent scoped roots", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    if (calls.length === 1) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (calls.length === 2) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-file-1" }] }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 });
  }) as typeof fetch;

  try {
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
            mediaLocalRoots: ["C:\\Users\\kingdee\\Desktop\\docs"],
          },
        },
      },
      params: {
        to: "open-1",
        path: "C:\\Users\\kingdee\\Desktop\\docs\\random-image.png",
      },
      mediaLocalRoots: ["C:\\Users\\kingdee\\.openclaw\\workspace"],
    } as any);

    assert.deepEqual(JSON.parse(String(calls[2]!.init.body)), {
      toOpenId: "open-1",
      msgType: 23,
      content: "[图片]",
      param: {
        desc: [{ type: "image", data: "image-file-1", w: 800, h: 600 }],
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj threading tool context exposes current conversation for message action defaults", () => {
  const toolContext = yzjPlugin.threading?.buildToolContext?.({
    cfg: {} as any,
    accountId: "personal",
    context: {
      To: "user:open-1",
      CurrentMessageId: "msg-1",
    },
    hasRepliedRef: { value: false },
  });

  assert.deepEqual(toolContext, {
    currentChannelId: "user:open-1",
    currentChannelProvider: "yzj",
    currentMessageId: "msg-1",
    hasRepliedRef: { value: false },
    yzjAccountId: "personal",
  });
});

test("yzj message send action keeps inbound personal account even if supplied accountId points to app", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as typeof fetch;

  try {
    const result = await yzjMessageActions.handleAction!({
      channel: "yzj",
      action: "send",
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            endpoint: "https://devtest.kdweibo.cn",
            accounts: {
              app: {
                appId: "app-1",
                appSecret: "secret-1",
              },
              personal: {
                sendMsgUrl: "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=personal-token",
              },
            },
          },
        },
      },
      accountId: "app",
      params: {
        path: "C:\\Users\\kingdee\\Desktop\\docs\\cat.png",
        message: "给你一只猫",
      },
      toolContext: {
        currentChannelId: "user:open-1",
        currentChannelProvider: "yzj",
        currentMessageId: "msg-1",
        yzjAccountId: "personal",
      } as any,
      mediaLocalRoots: ["C:\\Users\\kingdee\\Desktop\\docs"],
    } as any);

    assert.deepEqual(JSON.parse(toolResultText(result)), {
      ok: true,
      messageId: "",
      mediaUnsupported: true,
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=personal-token");
    assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
      msgtype: 2,
      content: YZJ_MEDIA_UNSUPPORTED_MESSAGE,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("resolveYZJSendTarget distinguishes direct and group prefixes", () => {
  assert.deepEqual(resolveYZJSendTarget("user:open-1"), { toOpenId: "open-1" });
  assert.deepEqual(resolveYZJSendTarget("yzj:group:group-1"), { groupId: "group-1" });
  assert.deepEqual(resolveYZJSendTarget("bare-group", "group"), { groupId: "bare-group" });
});

test("yzj outbound sendPayload sends mediaUrl through uploadfileOpen and message/send", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    if (calls.length === 1) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    if (calls.length === 2) {
      return new Response(JSON.stringify({ success: true, data: [{ fileId: "image-file-1" }] }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 });
  }) as typeof fetch;

  try {
    assert.ok(yzjPlugin.outbound?.sendPayload);
    const result = await yzjPlugin.outbound.sendPayload({
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            endpoint: "https://dev.kdweibo.cn",
            appId: "app-1",
            appSecret: "secret-1",
          },
        },
      } as any,
      to: "open-1",
      text: "",
      payload: {
        text: "图片测试",
        mediaUrl: "C:\\Users\\kingdee\\Desktop\\docs\\random-image.png",
      } as any,
      mediaLocalRoots: ["C:\\Users\\kingdee\\Desktop\\docs"],
    } as any);

    assert.equal(result.channel, "yzj");
    assert.equal(result.messageId, "msg-1");
    assert.equal(calls[1]!.url, "https://dev.kdweibo.cn/gateway/docrest/doc/file/uploadfileOpen");
    assert.equal(calls[2]!.url, "https://dev.kdweibo.cn/gateway/xtinterface/message/send");
    assert.deepEqual(JSON.parse(String(calls[2]!.init.body)), {
      toOpenId: "open-1",
      msgType: 23,
      content: "[图片]图片测试",
      param: {
        desc: [{ type: "image", data: "image-file-1", w: 800, h: 600 }],
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj outbound sendPayload sends text through legacy sendMsgUrl when app credentials are absent", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as typeof fetch;

  try {
    assert.ok(yzjPlugin.outbound?.sendPayload);
    const result = await yzjPlugin.outbound.sendPayload({
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            sendMsgUrl: "https://dev.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1",
          },
        },
      } as any,
      to: "open-1",
      text: "",
      payload: {
        text: "深圳天气",
      } as any,
    } as any);

    assert.equal(result.channel, "yzj");
    assert.equal(result.messageId, "");
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "https://dev.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1");
    assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
      msgtype: 2,
      content: "深圳天气",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj outbound sendPayload keeps personal account on sendMsgUrl even when top-level app credentials exist", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as typeof fetch;

  try {
    assert.ok(yzjPlugin.outbound?.sendPayload);
    const result = await yzjPlugin.outbound.sendPayload({
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            endpoint: "https://devtest.kdweibo.cn",
            appId: "top-app",
            appSecret: "top-secret",
            accounts: {
              personal: {
                sendMsgUrl: "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=personal-token",
              },
            },
          },
        },
      } as any,
      accountId: "personal",
      to: "open-1",
      text: "",
      payload: {
        text: "深圳天气",
      } as any,
    } as any);

    assert.equal(result.channel, "yzj");
    assert.equal((result as any).ok, true);
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=personal-token");
    assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
      msgtype: 2,
      content: "深圳天气",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj outbound sendPayload marks legacy media unsupported notice as successful", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as typeof fetch;

  try {
    assert.ok(yzjPlugin.outbound?.sendPayload);
    const result = await yzjPlugin.outbound.sendPayload({
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            sendMsgUrl: "https://dev.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1",
          },
        },
      } as any,
      to: "open-1",
      text: "",
      payload: {
        mediaUrl: "C:\\Users\\kingdee\\Desktop\\docs\\random-image.png",
      } as any,
      mediaLocalRoots: ["C:\\Users\\kingdee\\Desktop\\docs"],
    } as any);

    assert.equal((result as any).ok, true);
    assert.deepEqual(result.meta, { mediaUnsupported: true });
    assert.equal(calls.length, 1);
    assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
      msgtype: 2,
      content: YZJ_MEDIA_UNSUPPORTED_MESSAGE,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj outbound sendMedia marks legacy media unsupported notice as successful", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ success: true }), { status: 200 })) as typeof fetch;

  try {
    assert.ok(yzjPlugin.outbound?.sendMedia);
    const result = await yzjPlugin.outbound.sendMedia({
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            sendMsgUrl: "https://dev.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1",
          },
        },
      } as any,
      to: "open-1",
      text: "",
      mediaUrl: "C:\\Users\\kingdee\\Desktop\\docs\\random-image.png",
      mediaLocalRoots: ["C:\\Users\\kingdee\\Desktop\\docs"],
    } as any);

    assert.equal((result as any).ok, true);
    assert.deepEqual(result.meta, { mediaUnsupported: true });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj outbound sendText does not log sendMsgUrl request body for legacy webhook mode", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const logs: string[] = [];
  const originalFetch = globalThis.fetch;
  const originalInfo = console.info;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as typeof fetch;
  console.info = (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  };

  try {
    assert.ok(yzjPlugin.outbound?.sendText);
    const result = await yzjPlugin.outbound.sendText({
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            sendMsgUrl: "https://dev.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1",
          },
        },
      } as any,
      to: "open-1",
      text: "深圳天气",
    } as any);

    assert.equal(result.channel, "yzj");
    assert.equal(result.messageId, "");
    assert.equal(calls.length, 1);
    assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
      msgtype: 2,
      content: "深圳天气",
    });
    assert.deepEqual(logs, []);
  } finally {
    globalThis.fetch = originalFetch;
    console.info = originalInfo;
  }
});

test("yzj outbound sendText strips user prefix before app message/send", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url, init) => {
    calls.push({ url: String(url), init: init as RequestInit });
    if (String(url).endsWith("/api/oauth2_v12/auth/getAppAccessToken")) {
      return new Response(JSON.stringify({ success: true, data: { accessToken: "token-1", expireIn: 7200 } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: true, data: { msgId: "msg-1" } }), { status: 200 });
  }) as typeof fetch;

  try {
    assert.ok(yzjPlugin.outbound?.sendText);
    const result = await yzjPlugin.outbound.sendText({
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            endpoint: "https://dev.kdweibo.cn",
            appId: "app-1",
            appSecret: "secret-1",
          },
        },
      } as any,
      to: "user:open-1",
      text: "给你一只猫",
    } as any);

    assert.equal(result.channel, "yzj");
    assert.equal(result.messageId, "msg-1");
    assert.equal(calls[1]!.url, "https://dev.kdweibo.cn/gateway/xtinterface/message/send");
    assert.deepEqual(JSON.parse(String(calls[1]!.init.body)), {
      msgType: 2,
      toOpenId: "open-1",
      content: "给你一只猫",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj outbound sendMedia adds reply param for app file messages", async () => {
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
    assert.ok(yzjPlugin.outbound?.sendMedia);
    const result = await yzjPlugin.outbound.sendMedia({
      cfg: {
        channels: {
          yzj: {
            enabled: true,
            endpoint: "https://dev.kdweibo.cn",
            appId: "app-1",
            appSecret: "secret-1",
          },
        },
      } as any,
      to: "user:open-1",
      text: "",
      mediaUrl: path.join(testDir, "fixtures", "demo.txt"),
      mediaLocalRoots: [path.join(testDir, "fixtures")],
      replyToId: "msg-1",
    } as any);

    assert.equal(result.channel, "yzj");
    assert.equal(result.messageId, "msg-1");
    assert.equal(calls[2]!.url, "https://dev.kdweibo.cn/gateway/xtinterface/message/send");
    assert.deepEqual(JSON.parse(String(calls[2]!.init.body)), {
      toOpenId: "open-1",
      msgType: 8,
      content: "[文件]:demo.txt",
      param: {
        file_id: "file-1",
        name: "demo.txt",
        size: 1,
        ext: "txt",
        ftype: 0,
        unreadMonitor: 1,
        replyOpenId: "open-1",
        replyMsgId: "msg-1",
        replyRootMsgId: "msg-1",
        replySummary: "",
        replyPersonName: "",
        replyTitle: "",
        notifyTo: ["open-1"],
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("yzj outbound chunker respects text chunk limit", () => {
  assert.ok(yzjPlugin.outbound?.chunker);
  assert.deepEqual(yzjPlugin.outbound.chunker("abcdef", 2), ["ab", "cd", "ef"]);
});
