/**
 * YZJ Robot 账户管理
 *
 * 提供账户配置的创建、验证和解析功能
 */

import type { OpenclawConfig } from './compat.ts';
import { DEFAULT_ACCOUNT_ID, normalizeAccountId } from './compat.ts';

import type { ResolvedYZJAccount, YZJAccountConfig, YZJConfig } from './types.ts';
import { normalizeYZJEndpoint, resolveInboundMode } from './ws-url.ts';

const APP_ACCOUNT_ID = "app";
const PERSONAL_ACCOUNT_ID = "personal";

function hasTopLevelAppCredentials(config: YZJConfig | undefined): boolean {
  return Boolean(config?.appId?.trim() && config?.appSecret?.trim());
}

function hasTopLevelSendMsgUrl(config: YZJConfig | undefined): boolean {
  return Boolean(config?.sendMsgUrl?.trim());
}

function shouldSplitTopLevelRobots(cfg: OpenclawConfig): boolean {
  const yzjConfig = cfg.channels?.yzj as YZJConfig | undefined;
  if (!yzjConfig) return false;
  if (yzjConfig.accounts && Object.keys(yzjConfig.accounts).length > 0) return false;
  return hasTopLevelAppCredentials(yzjConfig) && hasTopLevelSendMsgUrl(yzjConfig);
}

/**
 * 列出所有配置的账户ID
 */
function listConfiguredAccountIds(cfg: OpenclawConfig): string[] {
  const accounts = (cfg.channels?.yzj as YZJConfig | undefined)?.accounts;
  if (!accounts || typeof accounts !== 'object') return [];
  return Object.keys(accounts).filter(Boolean);
}

/**
 * 列出所有 YZJ 账户ID
 * 始终包含默认账户ID，同时包含所有配置的账户ID
 */
export function listYZJAccountIds(cfg: OpenclawConfig): string[] {
  if (shouldSplitTopLevelRobots(cfg)) {
    return [APP_ACCOUNT_ID, PERSONAL_ACCOUNT_ID];
  }
  const ids = listConfiguredAccountIds(cfg);
  if (ids.length > 0) {
    return Array.from(new Set(ids)).sort((a, b) => a.localeCompare(b));
  }
  return [DEFAULT_ACCOUNT_ID];
}

/**
 * 解析默认 YZJ 账户ID
 */
export function resolveDefaultYZJAccountId(cfg: OpenclawConfig): string {
  const yzjConfig = cfg.channels?.yzj as YZJConfig | undefined;
  if (yzjConfig?.defaultAccount?.trim()) return yzjConfig.defaultAccount.trim();
  if (shouldSplitTopLevelRobots(cfg)) return APP_ACCOUNT_ID;
  const ids = listYZJAccountIds(cfg);
  if (ids.includes(DEFAULT_ACCOUNT_ID)) return DEFAULT_ACCOUNT_ID;
  return ids[0] ?? DEFAULT_ACCOUNT_ID;
}

/**
 * 解析账户配置
 */
function resolveAccountConfig(
  cfg: OpenclawConfig,
  accountId: string,
): YZJAccountConfig | undefined {
  const accounts = (cfg.channels?.yzj as YZJConfig | undefined)?.accounts;
  if (!accounts || typeof accounts !== 'object') return undefined;

  const lowerCaseAccountId = accountId.toLowerCase();
  for (const key of Object.keys(accounts)) {
    if (key.toLowerCase() === lowerCaseAccountId) {
      return accounts[key] as YZJAccountConfig | undefined;
    }
  }
  return undefined;
}

/**
 * 合并账户配置
 * 将基础配置和账户特定配置合并
 */
function mergeYZJAccountConfig(cfg: OpenclawConfig, accountId: string): YZJAccountConfig {
  const raw = (cfg.channels?.yzj ?? {}) as YZJConfig;
  const { accounts: _ignored, defaultAccount: _ignored2, ...base } = raw;
  if (shouldSplitTopLevelRobots(cfg)) {
    if (accountId === APP_ACCOUNT_ID) {
      return {
        ...base,
        sendMsgUrl: "",
      };
    }
    if (accountId === PERSONAL_ACCOUNT_ID) {
      return {
        ...base,
        appId: "",
        appSecret: "",
      };
    }
  }
  const account = resolveAccountConfig(cfg, accountId) ?? {};
  if (Object.keys(account).length === 0) {
    return base;
  }
  const sharedBase: YZJAccountConfig = {
    enabled: base.enabled,
    endpoint: base.endpoint,
    webhookPath: base.webhookPath,
    timeout: base.timeout,
    inboundMode: base.inboundMode,
    mediaLocalRoots: base.mediaLocalRoots,
  };
  return { ...sharedBase, ...account };
}

/**
 * 解析完整的 YZJ 账户信息
 */
export function resolveYZJAccount(params: {
  cfg: OpenclawConfig;
  accountId?: string | null;
}): ResolvedYZJAccount {
  const accountId = normalizeAccountId(params.accountId);
  const baseEnabled = (params.cfg.channels?.yzj as YZJConfig | undefined)?.enabled !== false;
  const merged = mergeYZJAccountConfig(params.cfg, accountId);
  const enabled = baseEnabled && merged.enabled !== false;

  const sendMsgUrl = merged.sendMsgUrl?.trim() || '';
  const endpoint = normalizeYZJEndpoint(merged.endpoint);
  const appId = merged.appId?.trim() || '';
  const appSecret = merged.appSecret?.trim() || '';
  const webhookPath = merged.webhookPath?.trim() || `/yzj/webhook/${accountId}`;
  const timeout = merged.timeout ?? 10000;
  const inboundMode = resolveInboundMode(merged, params.cfg.channels?.yzj as YZJConfig | undefined);
  const mediaLocalRoots = Array.isArray(merged.mediaLocalRoots)
    ? merged.mediaLocalRoots.map((item) => item.trim()).filter(Boolean)
    : [];
  const configured = Boolean(sendMsgUrl || (appId && appSecret));

  return {
    accountId,
    name: merged.name?.trim() || undefined,
    enabled,
    configured,
    endpoint,
    appId,
    appSecret,
    sendMsgUrl,
    webhookPath,
    timeout,
    inboundMode,
    mediaLocalRoots,
    secret: merged.secret,
    config: merged,
  };
}

/**
 * 列出所有已启用的 YZJ 账户
 */
export function listEnabledYZJAccounts(cfg: OpenclawConfig): ResolvedYZJAccount[] {
  return listYZJAccountIds(cfg)
    .map((accountId) => resolveYZJAccount({ cfg, accountId }))
    .filter((account) => account.enabled);
}
