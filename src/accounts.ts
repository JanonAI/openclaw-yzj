/**
 * YZJ Robot 账户管理
 *
 * 提供账户配置的创建、验证和解析功能
 */

import type { OpenclawConfig } from './compat.js';
import { DEFAULT_ACCOUNT_ID, normalizeAccountId } from './compat.js';

import type { ResolvedYZJAccount, YZJAccountConfig, YZJConfig } from './types.js';

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
 * 如果没有配置账户，则返回默认账户ID
 */
export function listYZJAccountIds(cfg: OpenclawConfig): string[] {
  const ids = listConfiguredAccountIds(cfg);
  if (ids.length === 0) return [DEFAULT_ACCOUNT_ID];
  return ids.sort((a, b) => a.localeCompare(b));
}

/**
 * 解析默认 YZJ 账户ID
 */
export function resolveDefaultYZJAccountId(cfg: OpenclawConfig): string {
  const yzjConfig = cfg.channels?.yzj as YZJConfig | undefined;
  if (yzjConfig?.defaultAccount?.trim()) return yzjConfig.defaultAccount.trim();
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
  return accounts[accountId] as YZJAccountConfig | undefined;
}

/**
 * 合并账户配置
 * 将基础配置和账户特定配置合并
 */
function mergeYZJAccountConfig(cfg: OpenclawConfig, accountId: string): YZJAccountConfig {
  const raw = (cfg.channels?.yzj ?? {}) as YZJConfig;
  const { accounts: _ignored, defaultAccount: _ignored2, ...base } = raw;
  const account = resolveAccountConfig(cfg, accountId) ?? {};
  return { ...base, ...account };
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
  const webhookPath = merged.webhookPath?.trim() || '/yzj/webhook';
  const timeout = merged.timeout ?? 10000;
  const configured = Boolean(sendMsgUrl);

  return {
    accountId,
    name: merged.name?.trim() || undefined,
    enabled,
    configured,
    sendMsgUrl,
    webhookPath,
    timeout,
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
