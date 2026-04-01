/**
 * YZJ Robot 配置向导
 *
 * 提供交互式配置向导，帮助用户设置 YZJ Robot 账户
 */

import type { ChannelSetupWizardAdapter, OpenclawConfig, WizardPrompter } from './compat.js';
import { DEFAULT_ACCOUNT_ID, normalizeAccountId } from './compat.js';

import { listYZJAccountIds, resolveDefaultYZJAccountId, resolveYZJAccount } from './accounts.js';
import type { YZJInboundMode } from './types.js';
import { normalizeYZJWebhookPath } from './onboarding-helpers.js';

const channel = 'yzj' as const;

/**
 * 显示 YZJ 配置帮助信息
 */
async function noteYZJConfigHelp(prompter: WizardPrompter): Promise<void> {
  await prompter.note(
    [
      '1) 登录云之家管理后台 → 智能机器人 → 创建机器人',
      '2) 获取机器人发送消息的 URL（sendMsgUrl）',
      '3) 选择入站模式：webhook 或 websocket',
      '4) 若使用 websocket，插件会自动从 sendMsgUrl 推导 WebSocket 地址',
      '5) 你也可以使用环境变量 YZJ_SEND_MSG_URL',
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
      statusLines: [`YZJ: ${configured ? '已配置' : '需要配置 sendMsgUrl 和 inboundMode'}`],
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

    // 提示输入 sendMsgUrl
    let sendMsgUrl = resolvedAccount.sendMsgUrl;
    if (!sendMsgUrl) {
      sendMsgUrl = String(
        await prompter.text({
          message: '输入 YZJ Robot 发送消息的 URL',
          validate: (value) => (value?.trim() ? undefined : '必填'),
        }),
      ).trim();
    } else {
      const keep = await prompter.confirm({
        message: 'sendMsgUrl 已配置，是否保留？',
        initialValue: true,
      });
      if (!keep) {
        sendMsgUrl = String(
          await prompter.text({
            message: '输入新的 YZJ Robot 发送消息的 URL',
            validate: (value) => (value?.trim() ? undefined : '必填'),
          }),
        ).trim();
      }
    }

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
