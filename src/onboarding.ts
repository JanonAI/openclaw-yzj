/**
 * YZJ Robot 配置向导
 *
 * 提供交互式配置向导，帮助用户设置 YZJ Robot 账户
 */

import type { ChannelSetupWizardAdapter, OpenclawConfig, WizardPrompter } from './compat.ts';
import { DEFAULT_ACCOUNT_ID, normalizeAccountId } from './compat.ts';

import { listYZJAccountIds, resolveDefaultYZJAccountId, resolveYZJAccount } from './accounts.ts';
import type { YZJInboundMode } from './types.ts';
import { normalizeYZJWebhookPath } from './onboarding-helpers.ts';
import { DEFAULT_YZJ_ENDPOINT } from './ws-url.ts';

const channel = 'yzj' as const;

/**
 * 显示 YZJ 配置帮助信息
 */
async function noteYZJConfigHelp(prompter: WizardPrompter): Promise<void> {
  await prompter.note(
    [
      '1) 准备云之家开放平台应用的 appId 和 appSecret',
      '2) 入站 websocket 会用 appId/appSecret 换 accessToken，再连接 /xuntong/websocket',
      '3) 出站会调用 /gateway/xtinterface/message/send',
      '4) 旧 sendMsgUrl 机器人 webhook 配置仍可作为兼容模式保留',
    ].join('\n'),
    'YZJ 配置说明',
  );
}

function inboundModeLabel(mode: YZJInboundMode): string {
  return mode === 'websocket' ? 'WebSocket 长连接（推荐）' : 'Webhook 回调';
}

/**
 * YZJ 配置向导适配器
 */
export const yzjOnboardingAdapter: ChannelSetupWizardAdapter = {
  channel,

  /**
   * 获取当前配置状态
   */
  getStatus: async ({ cfg }) => {
    const configured = listYZJAccountIds(cfg as OpenclawConfig).some((accountId) => {
      const account = resolveYZJAccount({ cfg: cfg as OpenclawConfig, accountId });
      return account.configured;
    });
    return {
      channel,
      configured,
      statusLines: [`YZJ: ${configured ? '已配置' : '需要配置 appId/appSecret 或 sendMsgUrl'}`],
      selectionHint: configured ? '已配置' : undefined,
      quickstartScore: configured ? 1 : 5,
    };
  },

  /**
   * 配置 YZJ 账户
   */
  configure: async ({ cfg, prompter, accountOverrides, shouldPromptAccountIds }) => {
    const yzjOverride = accountOverrides.yzj?.trim();
    const defaultYZJAccountId = resolveDefaultYZJAccountId(cfg as OpenclawConfig);
    let yzjAccountId = yzjOverride
      ? (normalizeAccountId(yzjOverride) ?? DEFAULT_ACCOUNT_ID)
      : defaultYZJAccountId;

    if (shouldPromptAccountIds && !yzjOverride) {
      const accountIds = listYZJAccountIds(cfg as OpenclawConfig);
      if (accountIds.length > 1) {
        const selected = await prompter.select({
          message: '选择 YZJ 账户',
          options: accountIds.map((id) => ({ value: id, label: id })),
          initialValue: yzjAccountId,
        });
        yzjAccountId = String(selected);
      }
    }

    let next = cfg as OpenclawConfig;
    const resolvedAccount = resolveYZJAccount({ cfg: next, accountId: yzjAccountId });
    const accountConfigured = resolvedAccount.configured;

    if (!accountConfigured) {
      await noteYZJConfigHelp(prompter);
    }

    let inboundMode = resolvedAccount.inboundMode;
    if (resolvedAccount.configured) {
      const keepInboundMode = await prompter.confirm({
        message: `当前入站模式为 ${inboundModeLabel(inboundMode)}，是否保留？`,
        initialValue: true,
      });
      if (!keepInboundMode) {
        inboundMode = String(
          await prompter.select({
            message: '选择 YZJ 入站模式',
            options: [
              { value: 'websocket', label: inboundModeLabel('websocket') },
              { value: 'webhook', label: inboundModeLabel('webhook') },
            ],
            initialValue: inboundMode,
          }),
        ) as YZJInboundMode;
      }
    } else {
      inboundMode = String(
        await prompter.select({
          message: '选择 YZJ 入站模式',
          options: [
            { value: 'websocket', label: inboundModeLabel('websocket') },
            { value: 'webhook', label: inboundModeLabel('webhook') },
          ],
          initialValue: 'websocket',
        }),
      ) as YZJInboundMode;
    }

    let endpoint = resolvedAccount.endpoint;
    endpoint = String(
      await prompter.text({
        message: '云之家开放平台地址',
        initialValue: endpoint || DEFAULT_YZJ_ENDPOINT,
        validate: (value) => (value?.trim() ? undefined : '必填'),
      }),
    ).trim();

    let appId = resolvedAccount.appId;
    if (!appId) {
      appId = String(
        await prompter.text({
          message: '输入云之家应用 appId',
          validate: (value) => (value?.trim() ? undefined : '必填'),
        }),
      ).trim();
    }

    let appSecret = resolvedAccount.appSecret;
    if (!appSecret) {
      appSecret = String(
        await prompter.text({
          message: '输入云之家应用 appSecret',
          validate: (value) => (value?.trim() ? undefined : '必填'),
        }),
      ).trim();
    }

    const sendMsgUrl = resolvedAccount.sendMsgUrl;

    // 提示输入 webhook 路径
    const webhookPathHint = inboundMode === 'websocket'
      ? 'Webhook 路径（兜底入口，可与 websocket 并行接收）'
      : 'Webhook 路径（用于接收消息回调）';
    const existingWebhookPath = resolvedAccount.webhookPath || '/yzj/webhook';
    const webhookPath = normalizeYZJWebhookPath(String(
      await prompter.text({
        message: webhookPathHint,
        initialValue: existingWebhookPath,
        validate: (value) => (value?.trim() ? undefined : '必填'),
      }),
    ));

    // 提示输入超时时间
    const timeoutInput = await prompter.text({
      message: '超时时间（毫秒，默认: 10000）',
      initialValue: String(resolvedAccount.timeout || 10000),
      validate: (value) => {
        if (!value?.trim()) return '必填';
        const num = Number(value.trim());
        if (isNaN(num) || num <= 0) return '必须是正整数';
        return undefined;
      },
    });
    const timeout = Number(String(timeoutInput).trim());

    // 应用配置
    if (yzjAccountId === DEFAULT_ACCOUNT_ID) {
      next = {
        ...next,
        channels: {
          ...next.channels,
          yzj: {
            ...next.channels?.yzj,
            enabled: true,
            endpoint,
            appId,
            appSecret,
            sendMsgUrl,
            webhookPath,
            timeout,
            inboundMode,
          },
        },
      };
    } else {
      next = {
        ...next,
        channels: {
          ...next.channels,
          yzj: {
            ...next.channels?.yzj,
            enabled: true,
            accounts: {
              ...((next.channels?.yzj as any)?.accounts ?? {}),
              [yzjAccountId]: {
                ...((next.channels?.yzj as any)?.accounts?.[yzjAccountId] ?? {}),
                enabled: true,
                endpoint,
                appId,
                appSecret,
                sendMsgUrl,
                webhookPath,
                timeout,
                inboundMode,
              },
            },
          },
        },
      };
    }

    // YZJ 需要接收外部 webhook，自动设置 gateway.bind = lan
    if ((next as any).gateway?.bind !== 'lan') {
      next = {
        ...next,
        gateway: {
          ...(next as any).gateway,
          bind: 'lan',
        },
      } as OpenclawConfig;
    }

    return { cfg: next, accountId: yzjAccountId };
  },

  /**
   * 禁用 YZJ 通道
   */
  disable: (cfg) => ({
    ...cfg,
    channels: {
      ...cfg.channels,
      yzj: { ...(cfg.channels?.yzj as any), enabled: false },
    },
  }),
};
