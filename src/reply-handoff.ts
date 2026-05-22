import type { YZJSendByAppTarget } from "./app-message.ts";

export type YZJReplyContext = NonNullable<YZJSendByAppTarget["reply"]> & {
  replyRootMsgId: string;
  replySummary: string;
  replyPersonName: string;
  replyTitle?: string;
  notifyTo: string[];
};

type StoredReplyContext = {
  accountId?: string;
  conversationId?: string;
  reply: YZJReplyContext;
  expiresAt: number;
};

const DEFAULT_REPLY_CONTEXT_TTL_MS = 30 * 60 * 1000;
const inboundReplyContexts = new Map<string, StoredReplyContext>();
const latestInboundReplyContextsByConversation = new Map<string, StoredReplyContext>();

function normalizeMessageId(messageId: string | undefined): string {
  return messageId?.trim() ?? "";
}

function normalizeConversationId(conversationId: string | undefined): string {
  return conversationId?.trim() ?? "";
}

function normalizeAccountId(accountId: string | undefined): string {
  return accountId?.trim() ?? "";
}

function conversationKey(accountId: string | undefined, conversationId: string | undefined): string {
  const normalizedConversationId = normalizeConversationId(conversationId);
  if (!normalizedConversationId) return "";
  return `${normalizeAccountId(accountId)}\u0000${normalizedConversationId}`;
}

function isYZJRobotOpenId(value: string | undefined): boolean {
  return value?.trim().toUpperCase().startsWith("BOT-") ?? false;
}

function cloneReplyContext(reply: YZJSendByAppTarget["reply"] | undefined): YZJReplyContext | undefined {
  if (!reply?.replyMsgId?.trim()) return undefined;
  return {
    ...(reply.replyOpenId?.trim() ? { replyOpenId: reply.replyOpenId.trim() } : {}),
    replyMsgId: reply.replyMsgId.trim(),
    replyRootMsgId: reply.replyRootMsgId?.trim() || reply.replyMsgId.trim(),
    replySummary: reply.replySummary ?? "",
    replyPersonName: reply.replyPersonName ?? "",
    replyTitle: reply.replyTitle ?? "",
    notifyTo: reply.notifyTo?.map((item) => item.trim()).filter(Boolean) ?? [],
  };
}

function pruneExpired(map: Map<string, StoredReplyContext>, now = Date.now()): void {
  for (const [key, value] of map.entries()) {
    if (value.expiresAt <= now) map.delete(key);
  }
}

export function rememberYZJInboundReplyContext(params: {
  accountId?: string;
  conversationId?: string;
  messageId?: string;
  reply?: YZJSendByAppTarget["reply"];
  ttlMs?: number;
}): void {
  const messageId = normalizeMessageId(params.messageId);
  const reply = cloneReplyContext(params.reply);
  if (!messageId || !reply) return;
  pruneExpired(inboundReplyContexts);
  pruneExpired(latestInboundReplyContextsByConversation);
  const accountId = normalizeAccountId(params.accountId) || undefined;
  const conversationId = normalizeConversationId(params.conversationId) || undefined;
  const stored = {
    accountId,
    conversationId,
    reply,
    expiresAt: Date.now() + (params.ttlMs ?? DEFAULT_REPLY_CONTEXT_TTL_MS),
  };
  inboundReplyContexts.set(messageId, stored);

  const key = conversationKey(accountId, conversationId);
  if (key && !isYZJRobotOpenId(reply.replyOpenId)) {
    latestInboundReplyContextsByConversation.set(key, stored);
  }
}

export function getYZJInboundReplyContext(messageId: string | undefined): YZJReplyContext | undefined {
  const key = normalizeMessageId(messageId);
  if (!key) return undefined;
  pruneExpired(inboundReplyContexts);
  const stored = inboundReplyContexts.get(key);
  return cloneReplyContext(stored?.reply);
}

export function getYZJLatestInboundReplyContext(params: {
  accountId?: string;
  conversationId?: string;
}): YZJReplyContext | undefined {
  const key = conversationKey(params.accountId, params.conversationId);
  if (!key) return undefined;
  pruneExpired(latestInboundReplyContextsByConversation);
  const stored = latestInboundReplyContextsByConversation.get(key);
  return cloneReplyContext(stored?.reply);
}

export function clearYZJReplyContextState(): void {
  inboundReplyContexts.clear();
  latestInboundReplyContextsByConversation.clear();
}

export function clearYZJInboundReplyContextsForAccount(accountId: string): void {
  const normalized = accountId.trim();
  if (!normalized) return;
  for (const [key, value] of inboundReplyContexts.entries()) {
    if (value.accountId === normalized) inboundReplyContexts.delete(key);
  }
  for (const [key, value] of latestInboundReplyContextsByConversation.entries()) {
    if (value.accountId === normalized) latestInboundReplyContextsByConversation.delete(key);
  }
}
