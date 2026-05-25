import type { OpenclawConfig, PluginRuntime } from "./compat.ts";
import { getAgentScopedMediaLocalRoots } from "openclaw/plugin-sdk/media-runtime";

import { getYZJRuntime } from "./runtime.ts";
import { InboundDedupeStore } from "./dedupe-store.ts";
import { sendYZJAppTextMessage } from "./app-message.ts";
import { YZJ_MEDIA_UNSUPPORTED_MESSAGE } from "./media-unsupported.ts";
import { mergeYZJMediaLocalRoots } from "./media-roots.ts";
import { uploadAndSendYZJAppMedia } from "./media-message.ts";
import {
  buildYZJOutboundQueueKey,
  clearYZJOutboundQueues,
  clearYZJOutboundTurnTexts,
  consumeYZJOutboundDuplicateText,
  enqueueYZJOutbound,
} from "./outbound-queue.ts";
import {
  clearYZJInboundReplyContextsForAccount,
  rememberYZJInboundReplyContext,
} from "./reply-handoff.ts";
import type {
  ResolvedYZJAccount,
  YZJIncomingMessage,
  YZJInboundStatusPatch,
  YZJLogger,
} from "./types.ts";
import { formatYZJConversationTarget } from "./targets.ts";
import { resolveYZJEndpointUrl } from "./ws-url.ts";
import { getYZJAccessTokenProvider } from "./auth-token.ts";

export type YZJInboundSource = "webhook" | "websocket";

export type YZJInboundTarget = {
  account: ResolvedYZJAccount;
  config: OpenclawConfig;
  runtime: YZJLogger;
  core?: PluginRuntime;
  statusSink?: (patch: YZJInboundStatusPatch) => void;
};

const dedupeStore = new InboundDedupeStore();

type YZJInboundConversation = {
  chatId: string;
  chatType: "direct" | "group";
  groupIdForSend: string;
  toOpenIdForSend: string;
  notifyOpenid: string;
  routePeer: { kind: "direct" | "group"; id: string };
};

type YZJBlockReplyPayload = {
  text?: string;
  mediaUrl?: string;
  mediaUrls?: string[];
};

type YZJToolStartPayload = {
  name?: string;
  phase?: string;
  args?: unknown;
  input?: unknown;
  params?: unknown;
};

function logInfo(logger: YZJLogger, message: string): void {
  logger.info?.(message);
  if (!logger.info) logger.log?.(message);
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

function updateInboundStatus(target: YZJInboundTarget, patch: YZJInboundStatusPatch): void {
  try {
    target.statusSink?.(patch);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    target.runtime.warn?.(`[${target.account.accountId}] yzj status update failed: ${errorMsg}`);
  }
}

function resolveCore(target: YZJInboundTarget): PluginRuntime {
  return target.core ?? getYZJRuntime();
}

async function sendQuickExprReaction(
  account: ResolvedYZJAccount,
  params: { groupId: string; msgId: string },
  logger: YZJLogger,
): Promise<void> {
  if (!params.msgId || !params.groupId) return;
  // quickExpr 仅支持应用机器人（需要 appId/appSecret 换取 accesstoken）
  if (!account.appId || !account.appSecret) return;
  try {
    const accessToken = await getYZJAccessTokenProvider(account).getAccessToken();
    const url = resolveYZJEndpointUrl(account.endpoint, "/gateway/xtinterface/message/quickExpr");
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        groupId: params.groupId,
        msgId: params.msgId,
        action: "add",
        expr: "[收到]",
      }),
      signal: AbortSignal.timeout(8_000),
    });
    logInfo(logger, `[${account.accountId}] quickExpr response status=${resp.status}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn?.(`[${account.accountId}] quickExpr failed (ignored): ${msg}`);
  }
}

function triggerQuickExprReaction(target: YZJInboundTarget, msg: YZJIncomingMessage): void {
  void sendQuickExprReaction(target.account, {
    groupId: msg.groupId?.trim() || "",
    msgId: msg.msgId?.trim() || "",
  }, target.runtime).catch((err) => {
    const msgText = err instanceof Error ? err.message : String(err);
    target.runtime.warn?.(`[${target.account.accountId}] quickExpr failed (ignored): ${msgText}`);
  });
}

export function clearInboundState(accountId: string): void {
  dedupeStore.clearAccount(accountId);
  clearYZJOutboundQueues();
  clearYZJInboundReplyContextsForAccount(accountId);
}

function isPrivateRobotGroupId(groupId: string): boolean {
  return groupId.toUpperCase().startsWith("BOT-");
}

function isDirectConversationByGroupType(groupType: number | undefined, groupId: string): boolean {
  if (groupType === 1 || groupType === 3) return true;
  if (groupType === 2 || groupType === 4) return false;
  return isPrivateRobotGroupId(groupId);
}

export function resolveYZJInboundConversation(msg: {
  groupType?: number;
  groupId?: string;
  operatorOpenid?: string;
  robotId?: string;
}): YZJInboundConversation {
  const operatorOpenid = msg.operatorOpenid?.trim() || "unknown";
  const robotId = msg.robotId?.trim() || "unknown";
  const rawGroupId = msg.groupId?.trim() || "";
  const isDirect = isDirectConversationByGroupType(msg.groupType, rawGroupId);
  if (isDirect) {
    return {
      chatId: operatorOpenid,
      chatType: "direct",
      groupIdForSend: "",
      toOpenIdForSend: operatorOpenid,
      notifyOpenid: "",
      routePeer: { kind: "direct", id: operatorOpenid },
    };
  }

  const chatId = rawGroupId || robotId;
  return {
    chatId,
    chatType: "group",
    groupIdForSend: rawGroupId,
    toOpenIdForSend: "",
    notifyOpenid: operatorOpenid,
    routePeer: { kind: "group", id: chatId },
  };
}

export async function dispatchInboundMessage(
  target: YZJInboundTarget,
  msg: YZJIncomingMessage,
  source: YZJInboundSource,
): Promise<{ duplicate: boolean }> {
  const accountId = target.account.accountId;
  logInfo(
    target.runtime,
    `[${accountId}] yzj inbound dispatch start source=${source} msgId=${msg.msgId || ""} robotId=${msg.robotId || ""} robotName=${msg.robotName || ""} operatorOpenid=${msg.operatorOpenid || ""} operatorName=${msg.operatorName || ""} groupType=${msg.groupType ?? ""} groupId=${msg.groupId || ""} content="${summarizeText(msg.content || "")}"`,
  );
  if (!dedupeStore.markSeen(accountId, msg.msgId)) {
    logInfo(target.runtime, `[${accountId}] yzj duplicate inbound dropped from ${source}: ${msg.msgId}`);
    return { duplicate: true };
  }

  updateInboundStatus(target, { lastInboundAt: Date.now() });
  await sendQuickExprReaction(target.account, {
    groupId: msg.groupId?.trim() || "",
    msgId: msg.msgId?.trim() || "",
  }, target.runtime);
  await startAgentForInbound(target, msg, source);
  return { duplicate: false };
}

async function sendYZJMessage(
  target: YZJInboundTarget,
  operatorOpenid: string,
  groupId: string,
  text: string,
  replyData: {
    replyOpenId?: string;
    replyMsgId: string;
    replyRootMsgId: string;
    replySummary: string;
    replyPersonName: string;
    notifyTo: string[];
  } | undefined,
): Promise<void> {
  const { account } = target;

  if (account.appId && account.appSecret) {
    const safeReplyData = replyData?.notifyTo.length ? replyData : undefined;
    const result = await sendYZJAppTextMessage(account, {
      groupId: groupId || undefined,
      toOpenId: groupId ? undefined : operatorOpenid,
      text,
      reply: safeReplyData,
    }, { logger: target.runtime });
    if (result.ok) {
      updateInboundStatus(target, { lastOutboundAt: Date.now() });
      return;
    }

    target.runtime.error?.(`[yzj] message/send 发送消息失败：${result.error?.message ?? "unknown error"}`);
    return;
  }

  const sendMsgUrl = account.sendMsgUrl;

  if (!sendMsgUrl) {
    target.runtime.error?.(`[yzj] appId/appSecret 或 sendMsgUrl 未配置，无法发送消息`);
    return;
  }

  try {
    const payload: Record<string, unknown> = {
      msgtype: 2,
      content: text,
    };
    target.runtime.info?.(`[yzj] sendMsgUrl request body: ${JSON.stringify(payload)}`);

    const response = await fetch(sendMsgUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorText = await response.text();
      target.runtime.error?.(`[yzj] 发送消息失败：HTTP ${response.status} - ${errorText}`);
    } else {
      updateInboundStatus(target, { lastOutboundAt: Date.now() });
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    target.runtime.error?.(`[yzj] 发送消息时发生错误：${errorMsg}`);
  }
}

async function sendYZJMedia(
  target: YZJInboundTarget,
  operatorOpenid: string,
  groupId: string,
  text: string,
  mediaUrl: string,
  mediaLocalRoots: readonly string[],
  replyData: {
    replyOpenId?: string;
    replyMsgId: string;
    replyRootMsgId: string;
    replySummary: string;
    replyPersonName: string;
    notifyTo: string[];
  } | undefined,
): Promise<void> {
  const { account } = target;
  if (!account.appId || !account.appSecret) {
    await sendYZJMessage(target, operatorOpenid, groupId, YZJ_MEDIA_UNSUPPORTED_MESSAGE, undefined);
    return;
  }

  const result = await uploadAndSendYZJAppMedia(account, {
    groupId: groupId || undefined,
    toOpenId: groupId ? undefined : operatorOpenid,
    text,
    mediaUrl,
    mediaLocalRoots,
    reply: replyData,
  }, { logger: target.runtime });
  if (result.ok) {
    updateInboundStatus(target, { lastOutboundAt: Date.now() });
    return;
  }

  target.runtime.error?.(`[yzj] message/send 媒体发送失败：${result.error?.message ?? "unknown error"}`);
}

async function startAgentForInbound(
  target: YZJInboundTarget,
  msg: YZJIncomingMessage,
  source: YZJInboundSource,
): Promise<void> {
  const { account, config } = target;
  const core = resolveCore(target);

  const operatorOpenid = msg.operatorOpenid?.trim() || "unknown";
  const operatorName = msg.operatorName?.trim() || "未知用户";
  const content = msg.content?.trim() || "";
  const robotId = msg.robotId?.trim() || "unknown";
  const msgId = msg.msgId?.trim() || "";
  const groupType = msg.groupType || 0;
  const conversation = resolveYZJInboundConversation({
    groupType,
    groupId: msg.groupId,
    operatorOpenid,
    robotId,
  });
  const conversationTarget = formatYZJConversationTarget(conversation);

  let replyData = undefined;
  if (msgId.length > 0) {
    replyData = {
      replyOpenId: operatorOpenid,
      replyMsgId: msgId,
      replyRootMsgId: msgId,
      replySummary: content,
      replyPersonName: operatorName,
      notifyTo: [operatorOpenid],
    };
  }
  if (replyData) {
    rememberYZJInboundReplyContext({
      accountId: account.accountId,
      conversationId: conversationTarget,
      messageId: msgId,
      reply: replyData,
    });
  }

  const route = core.channel.routing.resolveAgentRoute({
    cfg: config,
    channel: "yzj",
    accountId: account.accountId,
    peer: conversation.routePeer,
  });

  logInfo(
    target.runtime,
    `[${account.accountId}] yzj inbound route resolved source=${source} msgId=${msgId} chatType=${conversation.chatType} conversationTarget=${conversationTarget} routePeer=${safeJson(conversation.routePeer)} agentId=${route.agentId} routeAccountId=${route.accountId ?? ""} sessionKey=${route.sessionKey}`,
  );

  const storePath = core.channel.session.resolveStorePath(config.session?.store, {
    agentId: route.agentId,
  });
  logInfo(
    target.runtime,
    `[${account.accountId}] yzj agent context prepared msgId=${msgId} agentId=${route.agentId} accountId=${account.accountId} storePath=${storePath} sender=${operatorName}/${operatorOpenid} replyTo=${conversationTarget}`,
  );

  const envelopeOptions = core.channel.reply.resolveEnvelopeFormatOptions(config);
  const previousTimestamp = core.channel.session.readSessionUpdatedAt({
    storePath,
    sessionKey: route.sessionKey,
  });

  const body = core.channel.reply.formatAgentEnvelope({
    channel: "YZJ",
    from: `user:${operatorOpenid}`,
    previousTimestamp,
    envelope: envelopeOptions,
    body: content,
  });

  const ctxPayload = core.channel.reply.finalizeInboundContext({
    Body: body,
    RawBody: content,
    CommandBody: content,
    From: `yzj:${operatorOpenid}`,
    To: conversationTarget,
    SessionKey: route.sessionKey,
    AccountId: account.accountId,
    ChatType: conversation.chatType,
    ConversationLabel: `user:${operatorOpenid}`,
    SenderName: operatorName,
    SenderId: operatorOpenid,
    Provider: "yzj",
    Surface: "yzj",
    CurrentMessageId: msg.msgId,
    MessageSid: msg.msgId,
    OriginatingChannel: "yzj",
    OriginatingTo: conversationTarget,
    YZJReply: replyData,
  });

  await core.channel.session.recordInboundSession({
    storePath,
    sessionKey: ctxPayload.SessionKey ?? route.sessionKey,
    ctx: ctxPayload,
    onRecordError: (err: unknown) => {
      target.runtime.error?.(`[yzj] failed updating session meta: ${String(err)}`);
    },
  });

  const tableMode = core.channel.text.resolveMarkdownTableMode({
    cfg: config,
    channel: "yzj",
    accountId: account.accountId,
  });
  const mediaLocalRoots = mergeYZJMediaLocalRoots(account.mediaLocalRoots, getAgentScopedMediaLocalRoots(config, route.agentId));
  const outboundQueueKey = buildYZJOutboundQueueKey({
    accountId: account.accountId,
    groupId: conversation.groupIdForSend,
    toOpenId: conversation.toOpenIdForSend,
  });
  const turnId = msgId || msg.msgId;

  let messageBuffer: string[] = [];
  let partialTextBuffer = "";
  const outboundTasks: Promise<void>[] = [];
  const queuedBlockReplyTexts = new Map<string, number>();
  const sentTextKeys = new Set<string>();
  try {
  const enqueueOutbound = (task: () => Promise<void>): Promise<void> => {
    const queued = enqueueYZJOutbound(outboundQueueKey, task);
    outboundTasks.push(queued);
    return queued;
  };
  const normalizeTextKey = (text: string): string => text.replace(/\s+/g, " ").trim();
  const rememberSentText = (text: string): void => {
    const textKey = normalizeTextKey(text);
    if (textKey) sentTextKeys.add(textKey);
  };
  const hasSentText = (text: string): boolean => sentTextKeys.has(normalizeTextKey(text));
  const markQueuedBlockText = (text: string): void => {
    queuedBlockReplyTexts.set(text, (queuedBlockReplyTexts.get(text) ?? 0) + 1);
  };
  const consumeQueuedBlockText = (text: string): boolean => {
    const count = queuedBlockReplyTexts.get(text) ?? 0;
    if (count <= 0) return false;
    if (count === 1) queuedBlockReplyTexts.delete(text);
    else queuedBlockReplyTexts.set(text, count - 1);
    return true;
  };

  const flushBufferedText = async (): Promise<void> => {
    if (messageBuffer.length === 0) return;
    const fullMessage = messageBuffer.join("");
    messageBuffer = [];
    partialTextBuffer = "";
    if (hasSentText(fullMessage)) return;
    if (consumeYZJOutboundDuplicateText({ queueKey: outboundQueueKey, turnId, text: fullMessage })) return;
    rememberSentText(fullMessage);
    logInfo(
      target.runtime,
      `[${account.accountId}] yzj agent ordinary outbound text msgId=${msgId} agentId=${route.agentId} chatType=${conversation.chatType} groupId=${conversation.groupIdForSend} toOpenId=${conversation.toOpenIdForSend} text="${summarizeText(fullMessage)}"`,
    );
    await enqueueOutbound(() => sendYZJMessage(target, conversation.toOpenIdForSend, conversation.groupIdForSend, fullMessage, replyData));
  };
  const flushPartialText = async (): Promise<void> => {
    if (!partialTextBuffer) return;
    messageBuffer = [partialTextBuffer];
    await flushBufferedText();
  };

  await core.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx: ctxPayload,
    cfg: config,
    replyOptions: {
      onPartialReply: async (payload: YZJBlockReplyPayload) => {
        const mediaUrls = payload.mediaUrls?.length ? payload.mediaUrls : payload.mediaUrl ? [payload.mediaUrl] : [];
        if (mediaUrls.length > 0) return;
        const text = core.channel.text.convertMarkdownTables(payload.text ?? "", tableMode);
        if (!text || hasSentText(text)) return;
        partialTextBuffer = text;
      },
      onToolStart: async (payload: YZJToolStartPayload) => {
        if (payload.phase && payload.phase !== "start") return;
        logInfo(
          target.runtime,
          `[${account.accountId}] yzj agent tool start msgId=${msgId} agentId=${route.agentId} tool=${payload.name ?? ""} payload=${safeJson(payload)}`,
        );
        await flushPartialText();
      },
      onBlockReplyQueued: async (payload: YZJBlockReplyPayload) => {
        const mediaUrls = payload.mediaUrls?.length ? payload.mediaUrls : payload.mediaUrl ? [payload.mediaUrl] : [];
        if (mediaUrls.length > 0) return;
        const text = core.channel.text.convertMarkdownTables(payload.text ?? "", tableMode);
        if (!text) return;
        markQueuedBlockText(text);
        await flushBufferedText();
        if (hasSentText(text)) return;
        if (consumeYZJOutboundDuplicateText({ queueKey: outboundQueueKey, turnId, text })) return;
        rememberSentText(text);
        await enqueueOutbound(() => sendYZJMessage(target, conversation.toOpenIdForSend, conversation.groupIdForSend, text, replyData));
      },
    } as unknown as Record<string, unknown>,
    dispatcherOptions: {
      deliver: async (payload: YZJBlockReplyPayload, info?: { kind?: string }) => {
        const text = core.channel.text.convertMarkdownTables(payload.text ?? "", tableMode);
        if (info?.kind === "block" && consumeQueuedBlockText(text)) return;
        const mediaUrls = payload.mediaUrls?.length ? payload.mediaUrls : payload.mediaUrl ? [payload.mediaUrl] : [];
        if (mediaUrls.length > 0) {
          await flushPartialText();
          if (messageBuffer.length > 0) {
            await flushBufferedText();
          }
          for (const mediaUrl of mediaUrls) {
            if (mediaUrl?.trim()) {
              logInfo(
                target.runtime,
                `[${account.accountId}] yzj agent media outbound msgId=${msgId} agentId=${route.agentId} chatType=${conversation.chatType} groupId=${conversation.groupIdForSend} toOpenId=${conversation.toOpenIdForSend} mediaUrl=${mediaUrl.trim()} text="${summarizeText(text)}"`,
              );
              await enqueueOutbound(() => sendYZJMedia(target, conversation.toOpenIdForSend, conversation.groupIdForSend, text, mediaUrl.trim(), mediaLocalRoots, replyData));
            }
          }
          return;
        }

        if (text) messageBuffer.push(text);
        const length = messageBuffer.reduce((sum, item) => sum + item.length, 0);
        if (length > 20 || info?.kind === "block") {
          await flushBufferedText();
        }
      },
      onError: (err: unknown, info: { kind?: string }) => {
        messageBuffer = [];
        const errorMsg = `抱歉,处理您的消息时遇到问题: ${err instanceof Error ? err.message : String(err)}`;
        target.runtime.error?.(`[${account.accountId}] yzj ${info.kind ?? "reply"} reply failed: ${String(err)}`);
        enqueueOutbound(() => sendYZJMessage(target, conversation.toOpenIdForSend, conversation.groupIdForSend, errorMsg, replyData));
      },
    },
  });

  await flushBufferedText();
  await Promise.all(outboundTasks);
  clearYZJOutboundTurnTexts({ queueKey: outboundQueueKey, turnId });
  } finally {
    queuedBlockReplyTexts.clear();
    sentTextKeys.clear();
  }
}
