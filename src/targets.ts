export type YZJResolvedSendTarget = {
  toOpenId?: string;
  groupId?: string;
};

function stripYZJPrefix(raw: string): string {
  return raw.trim().replace(/^yzj:/i, "").trim();
}

export function normalizeYZJMessagingTarget(raw: string): string | undefined {
  const trimmed = stripYZJPrefix(raw);
  if (!trimmed) return undefined;
  return trimmed;
}

export function resolveYZJSendTarget(
  raw: string,
  fallbackChatType: "direct" | "group" = "direct",
): YZJResolvedSendTarget {
  const target = stripYZJPrefix(raw);
  if (!target) return {};

  const prefixed = /^([a-z_]+):(.*)$/i.exec(target);
  if (prefixed) {
    const prefix = prefixed[1]!.toLowerCase();
    const value = prefixed[2]!.trim();
    if (!value) return {};

    if (prefix === "group" || prefix === "chat") {
      return { groupId: value };
    }
    if (prefix === "user" || prefix === "openid" || prefix === "open_id") {
      return { toOpenId: value };
    }
  }

  return fallbackChatType === "group"
    ? { groupId: target }
    : { toOpenId: target };
}

export function formatYZJConversationTarget(params: {
  chatType: "direct" | "group";
  toOpenIdForSend: string;
  groupIdForSend: string;
  chatId: string;
}): string {
  if (params.chatType === "group") {
    return `group:${params.groupIdForSend || params.chatId}`;
  }
  return `user:${params.toOpenIdForSend || params.chatId}`;
}
