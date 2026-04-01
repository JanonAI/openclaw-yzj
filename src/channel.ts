/**
 * YZJ Robot Channel 插件
 *
 * 提供完整的 Channel 接口实现
 */

import type {
  ChannelAccountSnapshot,
  ChannelPlugin,
  OpenclawConfig,
} from "./compat.js";
import {
  DEFAULT_ACCOUNT_ID,
  deleteAccountFromConfigSection,
  formatPairingApproveHint,
  setAccountEnabledInConfigSection,
} from "./compat.js";

import { listYZJAccountIds, resolveDefaultYZJAccountId, resolveYZJAccount } from "./accounts.js";
import { yzjConfigSchema } from "./config-schema.js";
import type { ResolvedYZJAccount } from "./types.js";
import { clearInboundState } from "./inbound-dispatcher.js";
import { registerYZJWebhookTarget } from "./monitor.js";
import { yzjOnboardingAdapter } from "./onboarding.js";
import { deriveYZJWebSocketUrl } from "./ws-url.js";
import { YZJWebSocketClient } from "./websocket-client.js";

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

/**
 * 规范化 YZJ 消息目标
 * YZJ 使用 OpenID 作为目标标识符
 */
function normalizeYZJMessagingTarget(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  return trimmed.replace(/^(yzj|yunzhijia):/i, "").trim() || undefined;
}

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
    media: false,
    reactions: false,
    threads: false,
    polls: false,
    nativeCommands: false,
    blockStreaming: true,
  },
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
        clearBaseFields: ["name", "sendMsgUrl", "webhookPath", "timeout", "inboundMode"],
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
    resolveAllowFrom: ({ cfg, accountId }) => {
      const account = resolveYZJAccount({ cfg: cfg as OpenclawConfig, accountId });
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
      return [text];
    },
    sendText: async ({ cfg, to, text, accountId, replyToId, threadId }) => {
      const logPrefix = `[yzj][outbound][${accountId || "default"}]`;

      // 从账户配置获取 sendMsgUrl
      const account = resolveYZJAccount({ cfg: cfg as OpenclawConfig, accountId });
      const sendMsgUrl = account.sendMsgUrl;

      if (!sendMsgUrl) {
        console.error(`${logPrefix} sendMsgUrl not configured`);
        return {
          channel: "yzj",
          ok: false,
          messageId: "",
          error: new Error("sendMsgUrl not configured"),
        };
      }

      const payload = {
        msgtype: 2, // MessageType.TEXT
        content: text,
      };

      if (to) {
        payload['notifyParams'] = [{
          type: "openIds",
          values: [to]
        }];
      }

      try {
        const response = await fetch(sendMsgUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        });

        console.info(`${logPrefix} response status: ${response.status} ${response.statusText}`);

        if (response.ok) {
          return {
            channel: "yzj",
            ok: true,
          };
        } else {
          const errorText = `HTTP ${response.status}`;
          console.error(`${logPrefix} ${errorText}`);
          return {
            channel: "yzj",
            ok: false,
            messageId: "",
            error: new Error(errorText),
          };
        }
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
    sendMedia: async ({ cfg, to, text, mediaUrl, accountId }) => {
      throw new Error("YZJ outbound error");
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

      let websocketUrl = "";
      if (account.inboundMode === "websocket") {
        try {
          websocketUrl = deriveYZJWebSocketUrl(account.sendMsgUrl);
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
                lastError: null,
              });
            },
            onDegraded: (message) => {
              ctx.setStatus({
                accountId: account.accountId,
                running: false,
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
          configured: true,
          webhookPath: path,
          inboundMode: account.inboundMode,
          lastStartAt: Date.now(),
          lastError: null,
        });

        websocketClient?.start();

        await waitForAbortSignal(ctx.abortSignal);
      } finally {
        websocketClient?.stop();
        unregister();
        clearInboundState(account.accountId);
        ctx.setStatus({
          accountId: account.accountId,
          running: false,
          lastStopAt: Date.now(),
        });
      }
    },
    stopAccount: async (ctx) => {
      ctx.setStatus({
        accountId: ctx.account.accountId,
        running: false,
        lastStopAt: Date.now(),
      });
    },
  },
};
