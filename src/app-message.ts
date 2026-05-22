import type { ResolvedYZJAccount } from "./types.ts";
import { getYZJAccessTokenProvider } from "./auth-token.ts";
import { resolveYZJEndpointUrl } from "./ws-url.ts";

type FetchLike = typeof fetch;

type TokenProvider = {
  getAccessToken: () => Promise<string>;
};

export type YZJSendByAppTarget = {
  groupId?: string;
  toOpenId?: string;
  text: string;
  reply?: {
    replyOpenId?: string;
    replyMsgId: string;
    replyRootMsgId?: string;
    replySummary?: string;
    replyPersonName?: string;
    notifyTo?: string[];
  };
};

export type YZJSendByAppMessageTarget = {
  groupId?: string;
  toOpenId?: string;
  msgType: 2 | 8 | 23;
  content?: string;
  param?: Record<string, unknown>;
  clientMsgId?: string;
};

type SendOptions = {
  tokenProvider?: TokenProvider;
  fetchImpl?: FetchLike;
  logger?: {
    info?: (message: string) => void;
  };
};

export type YZJSendByAppResult = {
  ok: boolean;
  messageId?: string;
  error?: Error;
};

export function buildYZJReplyParam(reply: NonNullable<YZJSendByAppTarget["reply"]>): Record<string, unknown> {
  const notifyTo = reply.notifyTo?.map((item) => item.trim()).filter(Boolean) ?? [];
  const param: Record<string, unknown> = {
    replySummary: reply.replySummary ?? "",
    replyPersonName: reply.replyPersonName ?? "",
    replyMsgId: reply.replyMsgId,
    replyRootMsgId: reply.replyRootMsgId || reply.replyMsgId,
    notifyTo,
  };
  if (reply.replyOpenId?.trim()) {
    param.replyOpenId = reply.replyOpenId.trim();
  }
  return param;
}

export function buildYZJSendByAppPayload(target: YZJSendByAppTarget): Record<string, unknown> {
  const replyParam = target.reply?.replyMsgId ? buildYZJReplyParam(target.reply) : undefined;
  return buildYZJSendByAppMessagePayload({
    groupId: target.groupId,
    toOpenId: target.toOpenId,
    msgType: 2,
    content: target.text,
    param: replyParam,
  });
}

export function buildYZJSendByAppMessagePayload(target: YZJSendByAppMessageTarget): Record<string, unknown> {
  const groupId = target.groupId?.trim();
  const toOpenId = target.toOpenId?.trim();
  if (!groupId && !toOpenId) {
    throw new Error("groupId or toOpenId is required");
  }
  if (groupId && toOpenId) {
    throw new Error("groupId and toOpenId cannot both be set");
  }

  const payload: Record<string, unknown> = {
    msgType: target.msgType,
  };
  if (groupId) payload.groupId = groupId;
  if (toOpenId) payload.toOpenId = toOpenId;
  if (target.content !== undefined) payload.content = target.content;
  if (target.param !== undefined) payload.param = target.param;
  if (target.clientMsgId?.trim()) payload.clientMsgId = target.clientMsgId.trim();

  return payload;
}

function extractMessageId(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const record = body as Record<string, any>;
  return record.msgId
    ?? record.data?.msgId
    ?? record.data?.id
    ?? record.data?.messageId;
}

export async function sendYZJAppMessage(
  account: ResolvedYZJAccount,
  target: YZJSendByAppMessageTarget,
  options: SendOptions = {},
): Promise<YZJSendByAppResult> {
  try {
    const accessToken = await (options.tokenProvider ?? getYZJAccessTokenProvider(account)).getAccessToken();
    const fetchImpl = options.fetchImpl ?? fetch;
    const body = buildYZJSendByAppMessagePayload(target);
    options.logger?.info?.(`[yzj] message/send request body: ${JSON.stringify(body)}`);
    const response = await fetchImpl(
      resolveYZJEndpointUrl(account.endpoint, "/gateway/xtinterface/message/send"),
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      },
    );

    const responseText = await response.text();
    options.logger?.info?.(`[yzj] message/send response status=${response.status} body=${responseText}`);
    let parsed: unknown = undefined;
    if (responseText.trim()) {
      try {
        parsed = JSON.parse(responseText);
      } catch {
        parsed = undefined;
      }
    }

    if (!response.ok) {
      return { ok: false, error: new Error(`HTTP ${response.status}: ${responseText}`) };
    }

    if (parsed && typeof parsed === "object" && (parsed as Record<string, unknown>).success === false) {
      const record = parsed as Record<string, unknown>;
      return {
        ok: false,
        error: new Error(String(record.error ?? record.errorCode ?? "message/send failed")),
      };
    }

    return { ok: true, messageId: extractMessageId(parsed) };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
}

export async function sendYZJAppTextMessage(
  account: ResolvedYZJAccount,
  target: YZJSendByAppTarget,
  options: SendOptions = {},
): Promise<YZJSendByAppResult> {
  const payload = buildYZJSendByAppPayload(target);
  return sendYZJAppMessage(account, {
    groupId: payload.groupId as string | undefined,
    toOpenId: payload.toOpenId as string | undefined,
    msgType: payload.msgType as 2,
    content: payload.content as string | undefined,
    param: payload.param as Record<string, unknown> | undefined,
    clientMsgId: payload.clientMsgId as string | undefined,
  }, options);
}
