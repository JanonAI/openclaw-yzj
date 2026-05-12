/**
 * YZJ Robot Channel 插件
 *
 * 提供完整的 Channel 接口实现
 */

import type {
  ChannelAccountSnapshot,
  ChannelPlugin,
  OpenclawConfig,
} from "./compat.ts";
import {
  DEFAULT_ACCOUNT_ID,
  deleteAccountFromConfigSection,
  formatPairingApproveHint,
  setAccountEnabledInConfigSection,
} from "./compat.ts";

import { listYZJAccountIds, resolveDefaultYZJAccountId, resolveYZJAccount } from "./accounts.ts";
import { sendYZJAppTextMessage } from "./app-message.ts";
import { uploadAndSendYZJAppMedia } from "./media-message.ts";
import { getYZJAccessTokenProvider } from "./auth-token.ts";
import { yzjConfigSchema } from "./config-schema.ts";
import type { ResolvedYZJAccount } from "./types.ts";
import { clearInboundState } from "./inbound-dispatcher.ts";
import { registerYZJWebhookTarget } from "./monitor.ts";
import { yzjOnboardingAdapter } from "./onboarding.ts";
import { deriveYZJAccessTokenWebSocketUrl, deriveYZJWebSocketUrl } from "./ws-url.ts";
import { YZJWebSocketClient } from "./websocket-client.ts";
import { yzjMessageActions } from "./actions.ts";
import { mergeYZJMediaLocalRoots } from "./media-roots.ts";
import { YZJ_MEDIA_UNSUPPORTED_MESSAGE } from "./media-unsupported.ts";
import { normalizeYZJMessagingTarget, resolveYZJSendTarget } from "./targets.ts";
import { buildYZJOutboundQueueKey, enqueueYZJOutbound } from "./outbound-queue.ts";

const meta = {
  id: "yzj",
  label: "YZJ Robot",
  selectionLabel: "云之家",
  docsPath: "/channels/yzj",
  docsLabel: "yzj",
  blurb: "云之家智能机器人（API 模式）通过 Webhook 接收消息 + 主动发送消息",
  aliases: ["yzj", "云之家", "yunzhijia"],
  order: 90,
  quickstartAllowFrom: true,
};

async function sendYZJLegacyWebhookText(params: {
  sendMsgUrl: string;
  to?: string;
  text: string;
}): Promise<void> {
  const payload: {
    msgtype: number;
    content: string;
  } = {
    msgtype: 2,
    content: params.text,
  };

  const response = await fetch(params.sendMsgUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`sendMsgUrl failed: HTTP ${response.status}`);
  }
}

function resolveOutboundDestination(to: string): { toOpenId?: string; groupId?: string } {
  return resolveYZJSendTarget(to);
}

function buildOutboundReplyForDestination(destination: { toOpenId?: string; groupId?: string }, replyToId?: string | null) {
  const replyMsgId = replyToId?.trim();
  if (!replyMsgId) return undefined;
  const toOpenId = destination.toOpenId?.trim();
  return {
    ...(toOpenId ? { replyOpenId: toOpenId } : {}),
    replyMsgId,
    replyRootMsgId: replyMsgId,
    replySummary: "",
    replyPersonName: "",
    replyTitle: "",
    notifyTo: toOpenId ? [toOpenId] : [],
  };
}

/**
 * 规范化 YZJ 消息目标
 * YZJ 使用 OpenID 作为目标标识符
 */
/**
 * 等待 abort 信号触发，保持 startAccount 的 Promise 处于 pending 状态。
 */
function waitForAbortSignal(abortSignal: AbortSignal): Promise<void> {
  if (abortSignal.aborted) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve) => {
    abortSignal.addEventListener("abort", () => resolve(), { once: true });
  });
}

export const yzjPlugin: ChannelPlugin<ResolvedYZJAccount> = {
  id: "yzj",
  meta,
  onboarding: yzjOnboardingAdapter,
  setupWizard: yzjOnboardingAdapter,
  capabilities: {
    chatTypes: ["direct", "group"],
    media: true,
    reactions: false,
    threads: false,
    polls: false,
    nativeCommands: false,
    blockStreaming: true,
  },
  agentPrompt: {
    messageToolHints: () => [
      "- YZJ supports media send through `message` action=send. Use `media`, `mediaUrl`, `path`, `filePath`, or `url` for a local file path or remote media URL; the plugin uploads it with /gateway/docrest/doc/file/uploadfileOpen and sends it with /gateway/xtinterface/message/send.",
      "- When the user asks you to send a local image/file/video path back to them, call `message` with action=send and the path/media field. Do not answer that the file was read or that a preview may be visible.",
      "- When you create a file for the user and they ask you to send it, call `message` with action=send and `path`/`filePath` pointing to the generated file. Do not only summarize the file path or contents.",
      "- In a YZJ inbound turn, omit `to`/`target` to reply to the current conversation. Explicit targets are `user:<openId>` for private chats and `group:<groupId>` for groups.",
    ],
  },
  actions: yzjMessageActions,
  reload: { configPrefixes: ["channels.yzj"] },
  configSchema: yzjConfigSchema,
  config: {
    listAccountIds: (cfg) => listYZJAccountIds(cfg as OpenclawConfig),
    resolveAccount: (cfg, accountId) => resolveYZJAccount({ cfg: cfg as OpenclawConfig, accountId }),
    defaultAccountId: (cfg) => resolveDefaultYZJAccountId(cfg as OpenclawConfig),
    setAccountEnabled: ({ cfg, accountId, enabled }) =>
      setAccountEnabledInConfigSection({
        cfg: cfg as OpenclawConfig,
        sectionKey: "yzj",
        accountId,
        enabled,
        allowTopLevel: true,
      }),
    deleteAccount: ({ cfg, accountId }) =>
      deleteAccountFromConfigSection({
        cfg: cfg as OpenclawConfig,
        sectionKey: "yzj",
        clearBaseFields: ["name", "endpoint", "appId", "appSecret", "sendMsgUrl", "webhookPath", "timeout", "inboundMode"],
        accountId,
      }),
    isConfigured: (account) => account.configured,
    describeAccount: (account): ChannelAccountSnapshot => ({
      accountId: account.accountId,
      name: account.name,
      enabled: account.enabled,
      configured: account.configured,
      webhookPath: account.webhookPath ?? "/yzj/webhook",
    }),
    resolveAllowFrom: () => {
      // YZJ 不支持 allowFrom 配置，返回空数组
      return [];
    },
    formatAllowFrom: ({ allowFrom }) =>
      allowFrom
        .map((entry) => String(entry).trim())
        .filter(Boolean)
        .map((entry) => entry.toLowerCase()),
  },
  security: {
    resolveDmPolicy: ({ cfg, accountId, account }) => {
      const resolvedAccountId = accountId ?? account.accountId ?? DEFAULT_ACCOUNT_ID;
      const useAccountPath = Boolean((cfg as OpenclawConfig).channels?.yzj?.accounts?.[resolvedAccountId]);
      const basePath = useAccountPath ? `channels.yzj.accounts.${resolvedAccountId}.` : "channels.yzj.";
      return {
        policy: "pairing", // YZJ 只支持配对策略
        allowFrom: [], // YZJ 不支持 allowFrom
        policyPath: `${basePath}dm.policy`,
        allowFromPath: `${basePath}dm.allowFrom`,
        approveHint: formatPairingApproveHint("yzj"),
        normalizeEntry: (raw) => raw.trim().toLowerCase(),
      };
    },
  },
  groups: {
    // YZJ 机器人在群组中默认不需要 @ 提及
    resolveRequireMention: () => false,
  },
  threading: {
    // YZJ 不支持线程回复
    resolveReplyToMode: () => "off",
    buildToolContext: ({ context, accountId, hasRepliedRef }) => {
      const yzjReply = (context as unknown as { YZJReply?: unknown }).YZJReply;
      return {
        currentChannelId: normalizeYZJMessagingTarget(context.To ?? "") ?? undefined,
        currentChannelProvider: "yzj",
        currentMessageId: context.CurrentMessageId,
        hasRepliedRef,
        yzjAccountId: accountId?.trim() || undefined,
        ...(yzjReply ? { yzjReply } : {}),
      } as any;
    },
  },
  messaging: {
    normalizeTarget: normalizeYZJMessagingTarget,
    targetResolver: {
      looksLikeId: (raw) => Boolean(raw.trim()),
      hint: "<openid>",
    },
  },
  outbound: {
    deliveryMode: "direct",
    chunkerMode: "text",
    textChunkLimit: 20480,
    chunker: (text, limit) => {
      const size = Math.max(1, Math.floor(limit));
      const chunks: string[] = [];
      for (let index = 0; index < text.length; index += size) {
        chunks.push(text.slice(index, index + size));
      }
      return chunks.length > 0 ? chunks : [text];
    },
    sendPayload: async ({ cfg, to, payload, mediaLocalRoots, accountId, replyToId }) => {
      const text = payload.text ?? "";
      const mediaUrls = payload.mediaUrls?.length ? payload.mediaUrls : payload.mediaUrl ? [payload.mediaUrl] : [];

      if (!text.trim() && mediaUrls.length === 0) {
        return {
          channel: "yzj",
          ok: true,
          messageId: "",
        };
      }

      if (mediaUrls.length === 0) {
        const account = resolveYZJAccount({ cfg: cfg as OpenclawConfig, accountId });
        const destination = resolveOutboundDestination(to);
        const queueKey = buildYZJOutboundQueueKey({
          accountId: account.accountId,
          groupId: destination.groupId,
          toOpenId: destination.toOpenId,
        });

        if (!account.appId || !account.appSecret) {
          if (account.sendMsgUrl) {
            await enqueueYZJOutbound(queueKey, async () => {
              await sendYZJLegacyWebhookText({
                sendMsgUrl: account.sendMsgUrl,
                to: destination.toOpenId,
                text,
              });
            });
            return {
              channel: "yzj",
              ok: true,
              messageId: "",
            };
          }
          return {
            channel: "yzj",
            ok: false,
            messageId: "",
            error: new Error("appId/appSecret or sendMsgUrl not configured"),
          };
        }
        const result = await enqueueYZJOutbound(queueKey, async () =>
          sendYZJAppTextMessage(account, {
            toOpenId: destination.toOpenId,
            groupId: destination.groupId,
            text,
            reply: buildOutboundReplyForDestination(destination, replyToId),
          }));
        return {
          channel: "yzj",
          ok: result.ok,
          messageId: result.messageId ?? "",
          ...(result.error ? { error: result.error } : {}),
        };
      }

      const account = resolveYZJAccount({ cfg: cfg as OpenclawConfig, accountId });
      const destination = resolveOutboundDestination(to);
      const queueKey = buildYZJOutboundQueueKey({
        accountId: account.accountId,
        groupId: destination.groupId,
        toOpenId: destination.toOpenId,
      });
      if (!account.appId || !account.appSecret) {
        if (account.sendMsgUrl) {
          await enqueueYZJOutbound(queueKey, async () => {
            await sendYZJLegacyWebhookText({
              sendMsgUrl: account.sendMsgUrl,
              to: destination.toOpenId,
              text: YZJ_MEDIA_UNSUPPORTED_MESSAGE,
            });
          });
          return {
            channel: "yzj",
            ok: true,
            messageId: "",
            meta: { mediaUnsupported: true },
          };
        }
        return {
          channel: "yzj",
          messageId: "",
          meta: { error: YZJ_MEDIA_UNSUPPORTED_MESSAGE },
        };
      }

      let lastMessageId = "";
      for (const [index, mediaUrlRaw] of mediaUrls.entries()) {
        const mediaUrl = mediaUrlRaw?.trim();
        if (!mediaUrl) continue;
        const result = await enqueueYZJOutbound(queueKey, async () =>
          uploadAndSendYZJAppMedia(account, {
            toOpenId: destination.toOpenId,
            groupId: destination.groupId,
            text: index === 0 ? text : "",
            mediaUrl,
            mediaLocalRoots: mergeYZJMediaLocalRoots(account.mediaLocalRoots, mediaLocalRoots),
            reply: buildOutboundReplyForDestination(destination, replyToId),
          }));
        if (!result.ok) {
          return {
            channel: "yzj",
            ok: false,
            messageId: lastMessageId,
            error: result.error ?? new Error("message/send media failed"),
          };
        }
        lastMessageId = result.messageId ?? lastMessageId;
      }

      return {
        channel: "yzj",
        ok: true,
        messageId: lastMessageId,
      };
    },
    sendText: async ({ cfg, to, text, accountId, replyToId }) => {
      const logPrefix = `[yzj][outbound][${accountId || "default"}]`;

      const account = resolveYZJAccount({ cfg: cfg as OpenclawConfig, accountId });
      const destination = resolveOutboundDestination(to);
      const queueKey = buildYZJOutboundQueueKey({
        accountId: account.accountId,
        groupId: destination.groupId,
        toOpenId: destination.toOpenId,
      });
      if (account.appId && account.appSecret) {
        const result = await enqueueYZJOutbound(queueKey, async () =>
          sendYZJAppTextMessage(account, {
            toOpenId: destination.toOpenId,
            groupId: destination.groupId,
            text,
            reply: buildOutboundReplyForDestination(destination, replyToId),
          }));
        if (result.ok) {
          return {
            channel: "yzj",
            ok: true,
            messageId: result.messageId ?? "",
          };
        }
        return {
          channel: "yzj",
          ok: false,
          messageId: "",
            error: result.error ?? new Error("message/send failed"),
        };
      }

      // 兼容旧机器人 webhook 配置。
      const sendMsgUrl = account.sendMsgUrl;

      if (!sendMsgUrl) {
        console.error(`${logPrefix} appId/appSecret or sendMsgUrl not configured`);
        return {
          channel: "yzj",
          ok: false,
          messageId: "",
          error: new Error("appId/appSecret or sendMsgUrl not configured"),
        };
      }

      try {
        await enqueueYZJOutbound(queueKey, async () => {
          await sendYZJLegacyWebhookText({
            sendMsgUrl,
            to: destination.toOpenId,
            text,
          });
        });
        return {
          channel: "yzj",
          ok: true,
          messageId: "",
        };
      } catch (error) {
        console.error(`${logPrefix} send message failed:`, error);
        return {
          channel: "yzj",
          ok: false,
          messageId: "",
          error: error instanceof Error ? error : new Error(String(error)),
        };
      }
    },
    sendMedia: async ({ cfg, to, text, mediaUrl, mediaLocalRoots, accountId, replyToId }) => {
      const account = resolveYZJAccount({ cfg: cfg as OpenclawConfig, accountId });
      const destination = resolveOutboundDestination(to);
      const queueKey = buildYZJOutboundQueueKey({
        accountId: account.accountId,
        groupId: destination.groupId,
        toOpenId: destination.toOpenId,
      });
      if (!account.appId || !account.appSecret) {
        if (account.sendMsgUrl) {
          await enqueueYZJOutbound(queueKey, async () => {
            await sendYZJLegacyWebhookText({
              sendMsgUrl: account.sendMsgUrl,
              to: destination.toOpenId,
              text: YZJ_MEDIA_UNSUPPORTED_MESSAGE,
            });
          });
          return {
            channel: "yzj",
            ok: true,
            messageId: "",
            meta: { mediaUnsupported: true },
          };
        }
        return {
          channel: "yzj",
          messageId: "",
          meta: { error: YZJ_MEDIA_UNSUPPORTED_MESSAGE },
        };
      }

      try {
        const result = await enqueueYZJOutbound(queueKey, async () =>
          uploadAndSendYZJAppMedia(account, {
            toOpenId: destination.toOpenId,
            groupId: destination.groupId,
            text,
            mediaUrl,
            mediaLocalRoots: mergeYZJMediaLocalRoots(account.mediaLocalRoots, mediaLocalRoots),
            reply: buildOutboundReplyForDestination(destination, replyToId),
          }));
        if (result.ok) {
          return {
            channel: "yzj",
            ok: true,
            messageId: result.messageId ?? "",
          };
        }
        return {
          channel: "yzj",
          ok: false,
          messageId: "",
            error: result.error ?? new Error("message/send media failed"),
        };
      } catch (error) {
        return {
          channel: "yzj",
          ok: false,
          messageId: "",
          error: error instanceof Error ? error : new Error(String(error)),
        };
      }
    },
  },
  status: {
    defaultRuntime: {
      accountId: DEFAULT_ACCOUNT_ID,
      running: false,
      lastStartAt: null,
      lastStopAt: null,
      lastError: null,
    },
    buildChannelSummary: ({ snapshot }) => ({
      configured: snapshot.configured ?? false,
      running: snapshot.running ?? false,
      webhookPath: snapshot.webhookPath ?? null,
      inboundMode: (snapshot as any).inboundMode ?? null,
      lastStartAt: snapshot.lastStartAt ?? null,
      lastStopAt: snapshot.lastStopAt ?? null,
      lastError: snapshot.lastError ?? null,
      lastInboundAt: snapshot.lastInboundAt ?? null,
      lastOutboundAt: snapshot.lastOutboundAt ?? null,
      probe: snapshot.probe,
      lastProbeAt: snapshot.lastProbeAt ?? null,
    }),
    probeAccount: async () => ({ ok: true }),
    buildAccountSnapshot: ({ account, runtime }) => ({
      accountId: account.accountId,
      name: account.name,
      enabled: account.enabled,
      configured: account.configured,
      webhookPath: account.webhookPath ?? "/yzj/webhook",
      inboundMode: account.inboundMode,
      running: runtime?.running ?? false,
      connected: runtime?.running ?? false,
      lastStartAt: runtime?.lastStartAt ?? null,
      lastStopAt: runtime?.lastStopAt ?? null,
      lastError: runtime?.lastError ?? null,
      lastInboundAt: runtime?.lastInboundAt ?? null,
      lastOutboundAt: runtime?.lastOutboundAt ?? null,
      dmPolicy: "pairing",
    }),
  },
  gateway: {
    /**
     * **startAccount (启动账号)**
     *
     * YZJ lifecycle is long-running: keep webhook targets active until
     * gateway stop/reload aborts the account.
     */
    startAccount: async (ctx) => {
      const account = ctx.account;
      if (!account.configured) {
        ctx.log?.warn(`[${account.accountId}] YZJ not configured; skipping webhook registration`);
        ctx.setStatus({ accountId: account.accountId, running: false, configured: false });
        await waitForAbortSignal(ctx.abortSignal);
        return;
      }

      let websocketUrl: string | (() => Promise<string>) = "";
      if (account.inboundMode === "websocket") {
        try {
          if (account.appId && account.appSecret) {
            const tokenProvider = getYZJAccessTokenProvider(account);
            websocketUrl = async () =>
              deriveYZJAccessTokenWebSocketUrl(account.endpoint, await tokenProvider.getAccessToken());
          } else {
            websocketUrl = deriveYZJWebSocketUrl(account.sendMsgUrl);
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          ctx.log?.error(`[${account.accountId}] invalid websocket config: ${errorMessage}`);
          ctx.setStatus({
            accountId: account.accountId,
            running: false,
            configured: true,
            lastError: errorMessage,
            webhookPath: account.webhookPath ?? `/yzj/webhook/${account.accountId}`,
          });
          await waitForAbortSignal(ctx.abortSignal);
          return;
        }
      }

      const path = (account.webhookPath ?? `/yzj/webhook/${account.accountId}`).trim();
      const logger = {
        info: (message: string) => ctx.log?.info?.(message),
        warn: (message: string) => ctx.log?.warn?.(message),
        error: (message: string) => ctx.log?.error?.(message),
      };
      const unregister = registerYZJWebhookTarget({
        account,
        config: ctx.cfg as OpenclawConfig,
        runtime: logger,
        path,
        statusSink: (patch) => ctx.setStatus({ accountId: account.accountId, ...patch }),
      });
      const websocketClient = account.inboundMode === "websocket"
        ? new YZJWebSocketClient({
            url: websocketUrl,
            target: {
              account,
              config: ctx.cfg as OpenclawConfig,
              runtime: logger,
              statusSink: (patch) => ctx.setStatus({ accountId: account.accountId, ...patch }),
            },
            logger,
            onReady: () => {
              ctx.setStatus({
                accountId: account.accountId,
                running: true,
                connected: true,
                lastError: null,
              });
            },
            onDegraded: (message) => {
              ctx.setStatus({
                accountId: account.accountId,
                running: false,
                connected: false,
                lastError: message,
              });
            },
          })
        : null;

      try {
        ctx.log?.info(`[${account.accountId}] YZJ webhook registered at ${path}`);
        ctx.setStatus({
          accountId: account.accountId,
          running: account.inboundMode === "webhook",
          connected: account.inboundMode === "webhook",
          configured: true,
          webhookPath: path,
          lastStartAt: Date.now(),
          lastError: null,
        } as any);

        websocketClient?.start();

        await waitForAbortSignal(ctx.abortSignal);
      } finally {
        websocketClient?.stop();
        unregister();
        clearInboundState(account.accountId);
        ctx.setStatus({
          accountId: account.accountId,
          running: false,
          connected: false,
          lastStopAt: Date.now(),
        });
      }
    },
    stopAccount: async (ctx) => {
      ctx.setStatus({
        accountId: ctx.account.accountId,
        running: false,
        connected: false,
        lastStopAt: Date.now(),
      });
    },
  },
};
