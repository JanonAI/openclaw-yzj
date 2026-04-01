/**
 * Compatibility surface shared across older and newer OpenClaw releases.
 *
 * Keep runtime helpers local so plugin loading does not depend on SDK
 * subpath exports that changed between 2026.2.x and 2026.3.x.
 */

import type {
  ChannelAccountSnapshot as OpenClawChannelAccountSnapshot,
  ChannelConfigSchema as OpenClawChannelConfigSchema,
  ChannelPlugin as OpenClawChannelPlugin,
  OpenClawConfig as ImportedOpenClawConfig,
  OpenClawPluginApi as ImportedOpenClawPluginApi,
  PluginRuntime as ImportedPluginRuntime,
  WizardPrompter as ImportedWizardPrompter,
} from "openclaw/plugin-sdk";

export const DEFAULT_ACCOUNT_ID = "default";

const VALID_ACCOUNT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/i;
const INVALID_ACCOUNT_ID_CHARS_RE = /[^a-z0-9_-]+/g;
const LEADING_DASH_RE = /^-+/;
const TRAILING_DASH_RE = /-+$/;
const BLOCKED_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function isBlockedObjectKey(key: string): boolean {
  return BLOCKED_OBJECT_KEYS.has(key);
}

function canonicalizeAccountId(value: string): string {
  if (VALID_ACCOUNT_ID_RE.test(value)) return value.toLowerCase();
  return value
    .toLowerCase()
    .replace(INVALID_ACCOUNT_ID_CHARS_RE, "-")
    .replace(LEADING_DASH_RE, "")
    .replace(TRAILING_DASH_RE, "")
    .slice(0, 64);
}

function normalizeCanonicalAccountId(value: string): string | undefined {
  const canonical = canonicalizeAccountId(value);
  if (!canonical || isBlockedObjectKey(canonical)) return undefined;
  return canonical;
}

export function normalizeAccountId(value: string | undefined | null): string {
  const trimmed = (value ?? "").trim();
  if (!trimmed) return DEFAULT_ACCOUNT_ID;
  return normalizeCanonicalAccountId(trimmed) ?? DEFAULT_ACCOUNT_ID;
}

type EmptyPluginConfigSchemaIssue = {
  path: Array<string | number>;
  message: string;
};

type EmptyPluginConfigSchemaResult =
  | { success: true; data: unknown }
  | { success: false; error: { issues: EmptyPluginConfigSchemaIssue[] } };

function pluginConfigError(message: string): EmptyPluginConfigSchemaResult {
  return {
    success: false,
    error: {
      issues: [{ path: [], message }],
    },
  };
}

export function emptyPluginConfigSchema() {
  return {
    safeParse(value: unknown): EmptyPluginConfigSchemaResult {
      if (value === undefined) {
        return { success: true, data: undefined };
      }
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return pluginConfigError("expected config object");
      }
      if (Object.keys(value).length > 0) {
        return pluginConfigError("config must be empty");
      }
      return { success: true, data: value };
    },
    jsonSchema: {
      type: "object",
      additionalProperties: false,
      properties: {},
    },
  };
}

export function setAccountEnabledInConfigSection(params: {
  cfg: OpenclawConfig;
  sectionKey: string;
  accountId: string;
  enabled: boolean;
  allowTopLevel?: boolean;
}): OpenclawConfig {
  const accountKey = params.accountId || DEFAULT_ACCOUNT_ID;
  const base = params.cfg.channels?.[params.sectionKey];
  const hasAccounts = Boolean((base as any)?.accounts);

  if (params.allowTopLevel && accountKey === DEFAULT_ACCOUNT_ID && !hasAccounts) {
    return {
      ...params.cfg,
      channels: {
        ...params.cfg.channels,
        [params.sectionKey]: {
          ...base,
          enabled: params.enabled,
        },
      },
    } as OpenclawConfig;
  }

  const baseAccounts = ((base as any)?.accounts ?? {}) as Record<string, unknown>;
  const existing = (baseAccounts[accountKey] ?? {}) as Record<string, unknown>;

  return {
    ...params.cfg,
    channels: {
      ...params.cfg.channels,
      [params.sectionKey]: {
        ...base,
        accounts: {
          ...baseAccounts,
          [accountKey]: {
            ...existing,
            enabled: params.enabled,
          },
        },
      },
    },
  } as OpenclawConfig;
}

export function deleteAccountFromConfigSection(params: {
  cfg: OpenclawConfig;
  sectionKey: string;
  accountId: string;
  clearBaseFields?: string[];
}): OpenclawConfig {
  const accountKey = params.accountId || DEFAULT_ACCOUNT_ID;
  const base = params.cfg.channels?.[params.sectionKey];

  if (!base) return params.cfg;

  const baseAccounts = (base as any).accounts && typeof (base as any).accounts === "object"
    ? { ...((base as any).accounts as Record<string, unknown>) }
    : undefined;

  if (accountKey !== DEFAULT_ACCOUNT_ID) {
    const accounts = baseAccounts ? { ...baseAccounts } : {};
    delete accounts[accountKey];
    return {
      ...params.cfg,
      channels: {
        ...params.cfg.channels,
        [params.sectionKey]: {
          ...base,
          accounts: Object.keys(accounts).length ? accounts : undefined,
        },
      },
    } as OpenclawConfig;
  }

  if (baseAccounts && Object.keys(baseAccounts).length > 0) {
    delete baseAccounts[accountKey];
    const baseRecord = { ...(base as Record<string, unknown>) };
    for (const field of params.clearBaseFields ?? []) {
      if (field in baseRecord) baseRecord[field] = undefined;
    }
    return {
      ...params.cfg,
      channels: {
        ...params.cfg.channels,
        [params.sectionKey]: {
          ...baseRecord,
          accounts: Object.keys(baseAccounts).length ? baseAccounts : undefined,
        },
      },
    } as OpenclawConfig;
  }

  const nextChannels = { ...(params.cfg.channels ?? {}) } as Record<string, unknown>;
  delete nextChannels[params.sectionKey];

  const nextCfg = { ...params.cfg } as Record<string, unknown>;
  if (Object.keys(nextChannels).length > 0) {
    nextCfg.channels = nextChannels;
  } else {
    delete nextCfg.channels;
  }

  return nextCfg as OpenclawConfig;
}

function formatCliCommand(command: string): string {
  return command;
}

export function formatPairingApproveHint(channelId: string): string {
  return `Approve via: ${formatCliCommand(`openclaw pairing list ${channelId}`)} / ${formatCliCommand(`openclaw pairing approve ${channelId} <code>`)}`;
}

export type OpenclawConfig = ImportedOpenClawConfig;
export type ClawdbotConfig = ImportedOpenClawConfig;
export type OpenClawPluginApi = ImportedOpenClawPluginApi;
export type ClawdbotPluginApi = ImportedOpenClawPluginApi;
export type PluginRuntime = ImportedPluginRuntime;
export type WizardPrompter = ImportedWizardPrompter;
export type ChannelAccountSnapshot = OpenClawChannelAccountSnapshot;
export type ChannelConfigSchema = OpenClawChannelConfigSchema;

type CompatSetupChannelsOptions = {
  allowDisable?: boolean;
  allowSignalInstall?: boolean;
  onSelection?: (selection: string[]) => void;
  onPostWriteHook?: (hook: {
    channel: string;
    accountId: string;
    run: (ctx: { cfg: OpenclawConfig; runtime: unknown }) => Promise<void> | void;
  }) => void;
  accountIds?: Partial<Record<string, string>>;
  onAccountId?: (channel: string, accountId: string) => void;
  onResolvedPlugin?: (channel: string, plugin: unknown) => void;
  promptAccountIds?: boolean;
  whatsappAccountId?: string;
  promptWhatsAppAccountId?: boolean;
  onWhatsAppAccountId?: (accountId: string) => void;
  forceAllowFromChannels?: string[];
  skipStatusNote?: boolean;
  skipDmPolicyPrompt?: boolean;
  skipConfirm?: boolean;
  quickstartDefaults?: boolean;
  initialSelection?: string[];
  secretInputMode?: "plaintext" | "ref";
};

export type ChannelOnboardingDmPolicy = {
  label: string;
  channel: string;
  policyKey: string;
  allowFromKey: string;
  resolveConfigKeys?: (cfg: OpenclawConfig, accountId?: string) => {
    policyKey: string;
    allowFromKey: string;
  };
  getCurrent: (cfg: OpenclawConfig, accountId?: string) => unknown;
  setPolicy: (cfg: OpenclawConfig, policy: unknown, accountId?: string) => OpenclawConfig;
  promptAllowFrom?: (params: {
    cfg: OpenclawConfig;
    prompter: WizardPrompter;
    accountId?: string;
  }) => Promise<OpenclawConfig>;
};

export type ChannelOnboardingAdapter = {
  channel: string;
  getStatus: (ctx: {
    cfg: OpenclawConfig;
    options?: CompatSetupChannelsOptions;
    accountOverrides: Partial<Record<string, string>>;
  }) => Promise<{
    channel: string;
    configured: boolean;
    statusLines: string[];
    selectionHint?: string;
    quickstartScore?: number;
  }>;
  configure: (ctx: {
    cfg: OpenclawConfig;
    runtime: unknown;
    prompter: WizardPrompter;
    options?: CompatSetupChannelsOptions;
    accountOverrides: Partial<Record<string, string>>;
    shouldPromptAccountIds: boolean;
    forceAllowFrom: boolean;
  }) => Promise<{ cfg: OpenclawConfig; accountId?: string }>;
  configureInteractive?: (ctx: unknown) => Promise<{ cfg: OpenclawConfig; accountId?: string } | "skip">;
  configureWhenConfigured?: (ctx: unknown) => Promise<{ cfg: OpenclawConfig; accountId?: string } | "skip">;
  afterConfigWritten?: (ctx: {
    previousCfg: OpenclawConfig;
    cfg: OpenclawConfig;
    accountId: string;
    runtime: unknown;
  }) => Promise<void> | void;
  dmPolicy?: ChannelOnboardingDmPolicy;
  onAccountRecorded?: (accountId: string, options?: CompatSetupChannelsOptions) => void;
  disable?: (cfg: OpenclawConfig) => OpenclawConfig;
};

export type ChannelSetupWizardAdapter = ChannelOnboardingAdapter;

export type ChannelPlugin<ResolvedAccount = any, Probe = unknown, Audit = unknown> =
  OpenClawChannelPlugin<ResolvedAccount, Probe, Audit> & {
    onboarding?: ChannelOnboardingAdapter;
    setupWizard?: ChannelSetupWizardAdapter;
  };

export type ChannelConfig = any;
export type AgentInterface = any;
export type RuntimeManager = any;
export type AccountConfig = any;
