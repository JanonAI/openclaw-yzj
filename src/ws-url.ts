export type InboundModeConfig = {
  inboundMode?: "webhook" | "websocket" | null | undefined;
};

export function resolveInboundMode(
  accountConfig: InboundModeConfig | null | undefined,
  channelConfig: InboundModeConfig | null | undefined,
): "webhook" | "websocket" {
  return accountConfig?.inboundMode ?? channelConfig?.inboundMode ?? "webhook";
}

export const DEFAULT_YZJ_ENDPOINT = "https://yunzhijia.com";

function parseEndpoint(endpoint: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new Error("invalid endpoint");
  }
  if (parsed.protocol !== "https:") throw new Error("endpoint must use https");
  if (!parsed.host) throw new Error("missing endpoint host");
  return parsed;
}

export function normalizeYZJEndpoint(endpoint: string | undefined | null): string {
  const raw = endpoint?.trim() || DEFAULT_YZJ_ENDPOINT;
  const parsed = parseEndpoint(raw);
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString().replace(/\/$/, "");
}

export function resolveYZJEndpointUrl(endpoint: string, path: string): string {
  const normalizedEndpoint = normalizeYZJEndpoint(endpoint);
  const normalizedPath = path.startsWith("/") ? path.slice(1) : path;
  return new URL(normalizedPath, `${normalizedEndpoint}/`).toString();
}

export function deriveYZJWebSocketUrl(sendMsgUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(sendMsgUrl);
  } catch {
    throw new Error("invalid sendMsgUrl");
  }

  const token = parsed.searchParams.get("yzjtoken")?.trim();
  if (!token) throw new Error("missing yzjtoken");
  if (!parsed.host) throw new Error("missing host");

  return `wss://${parsed.host}/xuntong/websocket?yzjtoken=${encodeURIComponent(token)}`;
}

export function deriveYZJAccessTokenWebSocketUrl(endpoint: string, accessToken: string): string {
  const parsed = parseEndpoint(normalizeYZJEndpoint(endpoint));
  const token = accessToken.trim();
  if (!token) throw new Error("missing accessToken");
  return `wss://${parsed.host}/xuntong/websocket?accessToken=${encodeURIComponent(token)}`;
}
