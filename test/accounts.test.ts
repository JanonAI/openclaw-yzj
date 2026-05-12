import test from "node:test";
import assert from "node:assert/strict";

import { resolveYZJAccount } from "../src/accounts.ts";

test("resolveYZJAccount treats app credentials as configured without sendMsgUrl", () => {
  const account = resolveYZJAccount({
    cfg: {
      channels: {
        yzj: {
          enabled: true,
          inboundMode: "websocket",
          endpoint: "https://dev.kdweibo.cn",
          appId: "app-1",
          appSecret: "secret-1",
        },
      },
    } as any,
  });

  assert.equal(account.configured, true);
  assert.equal(account.endpoint, "https://dev.kdweibo.cn");
  assert.equal(account.appId, "app-1");
  assert.equal(account.appSecret, "secret-1");
  assert.equal(account.sendMsgUrl, "");
});

test("listYZJAccountIds splits top-level app credentials and sendMsgUrl into separate robot accounts", async () => {
  const { listYZJAccountIds, resolveDefaultYZJAccountId } = await import("../src/accounts.ts");
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
  assert.equal(resolveDefaultYZJAccountId(cfg), "app");
});

test("resolveYZJAccount maps split app and personal accounts to distinct credentials", () => {
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

  const app = resolveYZJAccount({ cfg, accountId: "app" });
  assert.equal(app.accountId, "app");
  assert.equal(app.appId, "app-1");
  assert.equal(app.appSecret, "secret-1");
  assert.equal(app.sendMsgUrl, "");

  const personal = resolveYZJAccount({ cfg, accountId: "personal" });
  assert.equal(personal.accountId, "personal");
  assert.equal(personal.appId, "");
  assert.equal(personal.appSecret, "");
  assert.equal(personal.sendMsgUrl, "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=token-1");
});

test("explicit accounts do not inherit top-level robot identity fields", () => {
  const cfg = {
    channels: {
      yzj: {
        enabled: true,
        inboundMode: "websocket",
        endpoint: "https://devtest.kdweibo.cn",
        appId: "top-app",
        appSecret: "top-secret",
        sendMsgUrl: "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=top-token",
        accounts: {
          app: {
            appId: "account-app",
            appSecret: "account-secret",
          },
          personal: {
            sendMsgUrl: "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=personal-token",
          },
        },
      },
    },
  } as any;

  const app = resolveYZJAccount({ cfg, accountId: "app" });
  assert.equal(app.endpoint, "https://devtest.kdweibo.cn");
  assert.equal(app.appId, "account-app");
  assert.equal(app.appSecret, "account-secret");
  assert.equal(app.sendMsgUrl, "");

  const personal = resolveYZJAccount({ cfg, accountId: "personal" });
  assert.equal(personal.endpoint, "https://devtest.kdweibo.cn");
  assert.equal(personal.appId, "");
  assert.equal(personal.appSecret, "");
  assert.equal(personal.sendMsgUrl, "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=personal-token");
});

test("listYZJAccountIds returns only explicit accounts when accounts are configured", async () => {
  const { listYZJAccountIds, resolveDefaultYZJAccountId } = await import("../src/accounts.ts");
  const cfg = {
    channels: {
      yzj: {
        enabled: true,
        endpoint: "https://devtest.kdweibo.cn",
        inboundMode: "websocket",
        defaultAccount: "personal",
        accounts: {
          app: {
            appId: "account-app",
            appSecret: "account-secret",
          },
          personal: {
            sendMsgUrl: "https://devtest.kdweibo.cn/gateway/robot/webhook/send?yzjtype=0&yzjtoken=personal-token",
          },
        },
      },
    },
  } as any;

  assert.deepEqual(listYZJAccountIds(cfg), ["app", "personal"]);
  assert.equal(resolveDefaultYZJAccountId(cfg), "personal");
});
