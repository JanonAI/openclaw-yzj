import { jsonResult } from "openclaw/plugin-sdk/agent-runtime";
import { readStringParam } from "openclaw/plugin-sdk/param-readers";
import { extractToolSend } from "openclaw/plugin-sdk/tool-send";
import type { ChannelMessageActionAdapter } from "openclaw/plugin-sdk/channel-contract";

import type { OpenclawConfig } from "./compat.ts";
import { resolveYZJAccount, listYZJAccountIds } from "./accounts.ts";
import { sendYZJAppTextMessage, type YZJSendByAppTarget } from "./app-message.ts";
import { YZJ_MEDIA_UNSUPPORTED_MESSAGE } from "./media-unsupported.ts";
import { uploadAndSendYZJAppMedia } from "./media-message.ts";
import { mergeYZJMediaLocalRoots } from "./media-roots.ts";
import {
  buildYZJOutboundQueueKey,
  enqueueYZJOutbound,
  markYZJOutboundTextSent,
} from "./outbound-queue.ts";
import {
  getYZJInboundReplyContext,
  getYZJLatestInboundReplyContext,
} from "./reply-handoff.ts";
import { resolveYZJSendTarget } from "./targets.ts";
import type { ResolvedYZJAccount } from "./types.ts";

const SUPPORTED_ACTIONS = new Set(["send"]);
function isLocalMediaRootsDeniedError(error: unknown): boolean {
  return error instanceof Error
    && error.message.startsWith("Local file access denied")
    && error.message.includes("mediaLocalRoots");
}

function summarizeText(text: string, limit = 120): string {
  const normalized = text.replace(/\s+/g, " ").trim();
  return normalized.length > limit ? `${normalized.slice(0, limit)}...` : normalized;
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

async function sendYZJWebhookText(account: ResolvedYZJAccount, target: {
  toOpenId?: string;
  groupId?: string;
  text: string;
  reply?: YZJSendByAppTarget["reply"];
}): Promise<void> {
  if (!account.sendMsgUrl) {
    throw new Error("appId/appSecret or sendMsgUrl not configured; YZJ send requires V12Controller credentials or legacy sendMsgUrl.");
  }

  const payload: Record<string, unknown> = {
    msgtype: 2,
    content: target.text,
  };
  console.info(`[yzj] sendMsgUrl request body: ${JSON.stringify(payload)}`);

  const response = await fetch(account.sendMsgUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`sendMsgUrl failed: HTTP ${response.status}: ${await response.text()}`);
  }
}

type YZJSendActionParams = {
  to: string;
  text: string;
  mediaUrl?: string;
  fileName?: string;
};

function readYZJSendParams(params: Record<string, unknown>): YZJSendActionParams {
  const to = readStringParam(params, "to")
    ?? readStringParam(params, "target")
    ?? "";
  const text = readStringParam(params, "message", { allowEmpty: true })
    ?? readStringParam(params, "text", { allowEmpty: true })
    ?? "";
  const mediaUrl = readStringParam(params, "media", { trim: false })
    ?? readStringParam(params, "mediaUrl", { trim: false })
    ?? readStringParam(params, "path", { trim: false })
    ?? readStringParam(params, "filePath", { trim: false })
    ?? readStringParam(params, "url", { trim: false });
  const fileName = readStringParam(params, "fileName")
    ?? readStringParam(params, "name");

  return {
    to,
    text,
    mediaUrl: mediaUrl ?? undefined,
    fileName: fileName ?? undefined,
  };
}

function readYZJToolContextAccountId(toolContext: unknown): string | undefined {
  if (!toolContext || typeof toolContext !== "object") return undefined;
  const value = (toolContext as Record<string, unknown>).yzjAccountId;
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readYZJToolContextReply(toolContext: unknown): YZJSendByAppTarget["reply"] | undefined {
  if (!toolContext || typeof toolContext !== "object") return undefined;
  const value = (toolContext as Record<string, unknown>).yzjReply;
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  const replyMsgId = typeof record.replyMsgId === "string" ? record.replyMsgId.trim() : "";
  if (!replyMsgId) return undefined;
  const notifyTo = Array.isArray(record.notifyTo)
    ? record.notifyTo.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : undefined;
  return {
    replyOpenId: typeof record.replyOpenId === "string" ? record.replyOpenId : undefined,
    replyMsgId,
    replyRootMsgId: typeof record.replyRootMsgId === "string" ? record.replyRootMsgId : undefined,
    replySummary: typeof record.replySummary === "string" ? record.replySummary : undefined,
    replyPersonName: typeof record.replyPersonName === "string" ? record.replyPersonName : undefined,
    notifyTo,
  };
}

function resolveYZJToolReply(toolContext: unknown): YZJSendByAppTarget["reply"] | undefined {
  if (!toolContext || typeof toolContext !== "object") return undefined;
  const currentMessageId = (toolContext as Record<string, unknown>).currentMessageId;
  const messageId = typeof currentMessageId === "string" ? currentMessageId : undefined;
  const contextReply = readYZJToolContextReply(toolContext);
  if (contextReply) return contextReply;
  return getYZJInboundReplyContext(messageId);
}

function resolveYZJLatestToolReply(params: {
  toolContext: unknown;
  accountId?: string;
  conversationId?: string;
}): YZJSendByAppTarget["reply"] | undefined {
  const reply = resolveYZJToolReply(params.toolContext);
  if (reply) return reply;
  return getYZJLatestInboundReplyContext({
    accountId: params.accountId,
    conversationId: params.conversationId,
  });
}

export const yzjMessageActions: ChannelMessageActionAdapter = {
  describeMessageTool: ({ cfg }) => {
    const openclawConfig = cfg as OpenclawConfig;
    const accountIds = listYZJAccountIds(openclawConfig);
    const anyConfigured = accountIds.some((id) => {
      const acc = resolveYZJAccount({ cfg: openclawConfig, accountId: id });
      return acc.enabled && acc.configured;
    });
    if (!anyConfigured) {
      return { actions: [], capabilities: [], schema: null };
    }
    console.info(`[yzj] message tool discovery accounts=${accountIds.join(",")} actions=send`);
    return {
      actions: Array.from(SUPPORTED_ACTIONS) as any,
      capabilities: [],
      schema: null,
    };
  },
  supportsAction: ({ action }) => SUPPORTED_ACTIONS.has(action),
  extractToolSend: ({ args }) => extractToolSend(args, "sendMessage"),
  handleAction: async ({ action, params, cfg, accountId, mediaLocalRoots, toolContext }) => {
    if (!SUPPORTED_ACTIONS.has(action)) {
      throw new Error(`Action "${action}" is not supported for YZJ.`);
    }

    const sendParams = readYZJSendParams(params);
    console.info(
      `[yzj] message action received action=${action} accountId=${accountId ?? ""} params=${safeJson(params)} toolContext=${safeJson(toolContext)}`,
    );
    const rawTarget = sendParams.to.trim() || toolContext?.currentChannelId?.trim() || "";
    const target = resolveYZJSendTarget(rawTarget);
    if (!target.toOpenId && !target.groupId) {
      throw new Error("send requires target parameter: to, target, or current YZJ conversation.");
    }
    if (!sendParams.text.trim() && !sendParams.mediaUrl) {
      throw new Error("send requires at least one of: message, text, media, mediaUrl, path, filePath, or url.");
    }

    const contextAccountId = readYZJToolContextAccountId(toolContext);
    const effectiveAccountId = contextAccountId ?? accountId;
    const openclawConfig = cfg as OpenclawConfig;
    const account = resolveYZJAccount({ cfg: openclawConfig, accountId: effectiveAccountId });
    const reply = resolveYZJLatestToolReply({
      toolContext,
      accountId: account.accountId,
      conversationId: rawTarget,
    });
    console.info(
      `[yzj] message action target resolved account=${account.accountId} effectiveAccountId=${effectiveAccountId ?? ""} rawTarget=${rawTarget} groupId=${target.groupId ?? ""} toOpenId=${target.toOpenId ?? ""} media=${sendParams.mediaUrl ? "yes" : "no"} text="${summarizeText(sendParams.text)}"`,
    );
    const queueKey = buildYZJOutboundQueueKey({
      accountId: account.accountId,
      groupId: target.groupId,
      toOpenId: target.toOpenId,
    });
    const turnId = toolContext?.currentMessageId === undefined ? undefined : String(toolContext.currentMessageId);
    markYZJOutboundTextSent({
      queueKey,
      turnId,
      text: sendParams.text,
    });
    return enqueueYZJOutbound(queueKey, async () => {
      if (sendParams.mediaUrl) {
        if (!account.appId || !account.appSecret) {
          await sendYZJWebhookText(account, {
            ...sendParams,
            toOpenId: target.toOpenId,
            groupId: target.groupId,
            text: YZJ_MEDIA_UNSUPPORTED_MESSAGE,
            reply,
          });
          return jsonResult({ ok: true, messageId: "", mediaUnsupported: true });
        }

        try {
          const result = await uploadAndSendYZJAppMedia(account, {
            toOpenId: target.toOpenId,
            groupId: target.groupId,
            text: sendParams.text,
            mediaUrl: sendParams.mediaUrl,
            fileName: sendParams.fileName,
            mediaLocalRoots: mergeYZJMediaLocalRoots(account.mediaLocalRoots, mediaLocalRoots),
            reply,
          }, {
            logger: console,
          });
          if (!result.ok) {
            throw result.error ?? new Error("message/send media failed");
          }
          console.info(`[yzj] message action media send result ok=true messageId=${result.messageId ?? ""}`);
          return jsonResult({ ok: true, messageId: result.messageId ?? "" });
        } catch (error) {
          if (isLocalMediaRootsDeniedError(error)) {
            const message = error instanceof Error ? error.message : String(error);
            return jsonResult({
              ok: false,
              messageId: "",
              mediaLocalRootsDenied: true,
              error: message,
            });
          }
          throw error;
        }
      }

      if (!account.appId || !account.appSecret) {
        await sendYZJWebhookText(account, {
          ...sendParams,
          toOpenId: target.toOpenId,
          groupId: target.groupId,
          text: sendParams.text,
          reply,
        });
        console.info("[yzj] message action legacy text send result ok=true");
        return jsonResult({ ok: true, messageId: "" });
      }

      const result = await sendYZJAppTextMessage(account, {
        toOpenId: target.toOpenId,
        groupId: target.groupId,
        text: sendParams.text,
        reply,
      }, {
        logger: console,
      });
      if (!result.ok) {
        throw result.error ?? new Error("message/send failed");
      }
      console.info(`[yzj] message action text send result ok=true messageId=${result.messageId ?? ""}`);
      return jsonResult({ ok: true, messageId: result.messageId ?? "" });
    });
  },
};
