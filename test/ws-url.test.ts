import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_YZJ_ENDPOINT,
  deriveYZJAccessTokenWebSocketUrl,
  deriveYZJWebSocketUrl,
  normalizeYZJEndpoint,
  resolveInboundMode,
  resolveYZJEndpointUrl,
} from "../src/ws-url.ts";
import { listYZJAccountIds, resolveYZJAccount } from "../src/accounts.ts";

test("deriveYZJWebSocketUrl builds websocket URL from sendMsgUrl", () => {
  assert.equal(
    deriveYZJWebSocketUrl("https://yunzhijia.com/gateway/robot/webhook/send?yzjtype=12&yzjtoken=abc"),
    "wss://yunzhijia.com/xuntong/websocket?yzjtoken=abc",
  );
});

test("deriveYZJWebSocketUrl rejects malformed urls", () => {
  assert.throws(() => deriveYZJWebSocketUrl("not-a-url"), /invalid sendMsgUrl/i);
});

test("deriveYZJWebSocketUrl rejects missing yzjtoken", () => {
  assert.throws(
    () => deriveYZJWebSocketUrl("https://yunzhijia.com/gateway/robot/webhook/send?yzjtype=12"),
    /missing yzjtoken/i,
  );
});

test("deriveYZJAccessTokenWebSocketUrl builds websocket URL from endpoint and accessToken", () => {
  assert.equal(
    deriveYZJAccessTokenWebSocketUrl("https://dev.kdweibo.cn", "access token"),
    "wss://dev.kdweibo.cn/xuntong/websocket?accessToken=access%20token",
  );
});

test("resolveYZJEndpointUrl resolves AppV12Controller outer path against endpoint", () => {
  assert.equal(
    resolveYZJEndpointUrl("https://api.yunzhijia.com", "/gateway/xtinterface/message/send"),
    "https://api.yunzhijia.com/gateway/xtinterface/message/send",
  );
});

test("normalizeYZJEndpoint defaults to yunzhijia.com when endpoint is not configured", () => {
  assert.equal(DEFAULT_YZJ_ENDPOINT, "https://yunzhijia.com");
  assert.equal(normalizeYZJEndpoint(undefined), "https://yunzhijia.com");
  assert.equal(normalizeYZJEndpoint(""), "https://yunzhijia.com");
});

test("resolveInboundMode prefers account config over channel config", () => {
  assert.equal(
    resolveInboundMode({ inboundMode: "websocket" }, { inboundMode: "webhook" }),
    "websocket",
  );
});

test("resolveInboundMode falls back to channel config then webhook default", () => {
  assert.equal(resolveInboundMode({}, { inboundMode: "websocket" }), "websocket");
  assert.equal(resolveInboundMode({}, {}), "webhook");
});

test("split app and personal accounts resolve to distinct websocket url sources", () => {
  const cfg = {
    channels: {
      yzj: {
        enabled: true,
        inboundMode: "websocket",
        endpoint: "https://devtest.kdweibo.cn",
        appId: "app-1",
        appSecret: "secret-1",
        sendMsgUrl: "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1",
      },
    },
  } as any;

  assert.deepEqual(listYZJAccountIds(cfg), ["app", "personal"]);
  const app = resolveYZJAccount({ cfg, accountId: "app" });
  const personal = resolveYZJAccount({ cfg, accountId: "personal" });

  assert.equal(deriveYZJAccessTokenWebSocketUrl(app.endpoint, "access-token"), "wss://devtest.kdweibo.cn/xuntong/websocket?accessToken=access-token");
  assert.equal(deriveYZJWebSocketUrl(personal.sendMsgUrl), "wss://devtest.kdweibo.cn/xuntong/websocket?yzjtoken=token-1");
});
