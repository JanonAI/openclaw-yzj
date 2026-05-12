import type { ResolvedYZJAccount } from "./types.ts";
import { resolveYZJEndpointUrl } from "./ws-url.ts";

type FetchLike = typeof fetch;

type AccessTokenProviderOptions = {
  account: ResolvedYZJAccount;
  fetchImpl?: FetchLike;
  now?: () => number;
};

type TokenResponse = {
  success?: boolean;
  errorCode?: number;
  error?: string;
  data?: {
    accessToken?: string;
    expireIn?: number;
    refreshToken?: string;
  };
};

export class YZJAccessTokenProvider {
  private readonly account: ResolvedYZJAccount;
  private readonly fetchImpl: FetchLike;
  private readonly now: () => number;
  private cachedAccessToken = "";
  private expiresAt = 0;

  constructor(options: AccessTokenProviderOptions) {
    this.account = options.account;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? Date.now;
  }

  async getAccessToken(): Promise<string> {
    if (this.cachedAccessToken && this.now() < this.expiresAt) {
      return this.cachedAccessToken;
    }

    if (!this.account.appId || !this.account.appSecret) {
      throw new Error("appId/appSecret not configured");
    }

    const response = await this.fetchImpl(
      resolveYZJEndpointUrl(this.account.endpoint, "/api/oauth2_v12/auth/getAppAccessToken"),
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          appId: this.account.appId,
          secret: this.account.appSecret,
          timestamp: this.now(),
        }),
      },
    );

    const responseText = await response.text();
    let parsed: TokenResponse;
    try {
      parsed = JSON.parse(responseText) as TokenResponse;
    } catch {
      throw new Error(`getAccessToken returned invalid JSON: HTTP ${response.status}`);
    }

    if (!response.ok || parsed.success !== true) {
      const code = parsed.errorCode ?? response.status;
      const message = parsed.error || response.statusText || "unknown error";
      throw new Error(`getAccessToken failed: ${code} ${message}`);
    }

    const accessToken = parsed.data?.accessToken?.trim();
    if (!accessToken) {
      throw new Error("getAccessToken response missing accessToken");
    }

    const expireInSeconds = parsed.data?.expireIn && parsed.data.expireIn > 0
      ? parsed.data.expireIn
      : 3600;
    this.cachedAccessToken = accessToken;
    this.expiresAt = this.now() + Math.max(60, expireInSeconds - 60) * 1000;
    return accessToken;
  }
}

const providers = new WeakMap<ResolvedYZJAccount, YZJAccessTokenProvider>();

export function getYZJAccessTokenProvider(account: ResolvedYZJAccount): YZJAccessTokenProvider {
  let provider = providers.get(account);
  if (!provider) {
    provider = new YZJAccessTokenProvider({ account });
    providers.set(account, provider);
  }
  return provider;
}
