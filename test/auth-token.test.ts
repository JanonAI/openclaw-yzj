import test from "node:test";
import assert from "node:assert/strict";

import { YZJAccessTokenProvider } from "../src/auth-token.ts";

test("YZJAccessTokenProvider exchanges appId and secret for accessToken", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const provider = new YZJAccessTokenProvider({
    account: {
      accountId: "default",
      endpoint: "https://dev.kdweibo.cn",
      appId: "app-1",
      appSecret: "secret-1",
      timeout: 10000,
    } as any,
    now: () => 1_000,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      return new Response(JSON.stringify({
        success: true,
        errorCode: 0,
        data: {
          accessToken: "token-1",
          expireIn: 7200,
          refreshToken: "refresh-1",
        },
      }), { status: 200 });
    },
  });

  assert.equal(await provider.getAccessToken(), "token-1");

  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, "https://dev.kdweibo.cn/api/oauth2_v12/auth/getAppAccessToken");
  assert.equal(calls[0]!.init.method, "POST");
  assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
    appId: "app-1",
    secret: "secret-1",
    timestamp: 1000,
  });
});
