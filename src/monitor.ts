/**
 * YZJ Robot Webhook 监听器
 *
 * 提供 Webhook 处理器，接收来自 YZJ Robot 的消息
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import type { YZJIncomingMessage, YZJResponse, MessageType } from './types.js';
import type { PluginRuntime, OpenclawConfig } from './compat.js';
import type { ResolvedYZJAccount } from './types.js';
import { getYZJRuntime } from './runtime.js';
import { verifySignature } from './signature.js';

type YZJWebhookTarget = {
  account: ResolvedYZJAccount;
  config: OpenclawConfig;
  runtime: {
    log?: (message: string) => void;
    error?: (message: string) => void;
  };
  core: PluginRuntime;
  path: string;
  statusSink?: (patch: { lastInboundAt?: number; lastOutboundAt?: number }) => void;
};

/**
 * 发送消息到 YZJ Robot
 */
async function sendYZJMessage(target: YZJWebhookTarget, operatorOpenid: string, text: string): Promise<void> {
  const { account } = target;
  const sendMsgUrl = account.sendMsgUrl;

  if (!sendMsgUrl) {
    target.runtime.error?.(`[yzj] sendMsgUrl 未配置，无法发送消息`);
    return;
  }

  try {
    const payload = {
      msgtype: 2, // MessageType.TEXT
      content: text,
      notifyParams: [] as { type: string; values: string[] }[],
    };

    if (operatorOpenid) {
      payload.notifyParams.push({
        type: "openIds",
        values: [operatorOpenid]
      });
    }

    const response = await fetch(sendMsgUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorText = await response.text();
      target.runtime.error?.(`[yzj] 发送消息失败: HTTP ${response.status} - ${errorText}`);
    } else {
      target.runtime.log?.(`[yzj] 消息已发送: ${text.slice(0, 50)}${text.length > 50 ? '...' : ''}`);
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    target.runtime.error?.(`[yzj] 发送消息时发生错误: ${errorMsg}`);
  }
}

/**
 * 启动 Agent 处理入站消息
 */
async function startAgentForInbound(
  target: YZJWebhookTarget,
  msg: YZJIncomingMessage
): Promise<void> {
  const { account, config, core } = target;

  const operatorOpenid = msg.operatorOpenid?.trim() || 'unknown';
  const operatorName = msg.operatorName?.trim() || '未知用户';
  const content = msg.content?.trim() || '';
  const robotId = msg.robotId?.trim() || 'unknown';
  const chatId = robotId;

  // 解析 Agent 路由
  const route = core.channel.routing.resolveAgentRoute({
    cfg: config,
    channel: 'yzj',
    accountId: account.accountId,
    peer: { kind: 'group', id: chatId },
  });

  target.runtime.log?.(`[yzj] starting agent processing (agentId=${route.agentId}, peerId=${chatId}) operatorOpenid=${operatorOpenid} content="${content.slice(0, 50)}${content.length > 50 ? '...' : ''}"`);

  // 构建会话存储路径
  const storePath = core.channel.session.resolveStorePath(config.session?.store, {
    agentId: route.agentId,
  });

  // 获取 Envelope 格式选项和之前的时间戳
  const envelopeOptions = core.channel.reply.resolveEnvelopeFormatOptions(config);
  const previousTimestamp = core.channel.session.readSessionUpdatedAt({
    storePath,
    sessionKey: route.sessionKey,
  });

  // 格式化 Agent Envelope
  const body = core.channel.reply.formatAgentEnvelope({
    channel: 'YZJ',
    from: `user:${operatorOpenid}`,
    previousTimestamp,
    envelope: envelopeOptions,
    body: content,
  });

  // 构建入站上下文
  const ctxPayload = core.channel.reply.finalizeInboundContext({
    Body: body,
    RawBody: content,
    CommandBody: content,
    From: `yzj:${operatorOpenid}`,
    To: `yzj:${robotId}`,
    SessionKey: route.sessionKey,
    AccountId: route.accountId,
    ChatType: 'direct',
    ConversationLabel: `user:${operatorOpenid}`,
    SenderName: operatorName,
    SenderId: operatorOpenid,
    Provider: 'yzj',
    Surface: 'yzj',
    MessageSid: msg.msgId,
    OriginatingChannel: 'yzj',
    OriginatingTo: `yzj:${robotId}`,
  });

  // 记录入站会话
  await core.channel.session.recordInboundSession({
    storePath,
    sessionKey: ctxPayload.SessionKey ?? route.sessionKey,
    ctx: ctxPayload,
    onRecordError: (err) => {
      target.runtime.error?.(`[yzj] failed updating session meta: ${String(err)}`);
    },
  });

  // 解析 Markdown 表格模式
  const tableMode = core.channel.text.resolveMarkdownTableMode({
    cfg: config,
    channel: 'yzj',
    accountId: account.accountId,
  });

  // 分发 Agent 处理
  await core.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx: ctxPayload,
    cfg: config,
    dispatcherOptions: {
      deliver: async (payload) => {
        const text = core.channel.text.convertMarkdownTables(payload.text ?? '', tableMode);
        await sendYZJMessage(target, operatorOpenid, text);
        target.statusSink?.({ lastOutboundAt: Date.now() });
      },
      onError: (err, info) => {
        const errorMsg = `抱歉,处理您的消息时遇到问题: ${err instanceof Error ? err.message : String(err)}`;
        target.runtime.error?.(`[${account.accountId}] yzj ${info.kind} reply failed: ${String(err)}`);
        sendYZJMessage(target, operatorOpenid, errorMsg);
      },
    },
  });
}

const webhookTargets = new Map<string, YZJWebhookTarget[]>();

function normalizeWebhookPath(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "/";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  if (withSlash.length > 1 && withSlash.endsWith("/")) return withSlash.slice(0, -1);
  return withSlash;
}

function resolvePath(req: IncomingMessage): string {
  const url = new URL(req.url ?? "/", "http://localhost");
  return normalizeWebhookPath(url.pathname || "/");
}

async function readJsonBody(req: IncomingMessage, maxBytes: number) {
  const chunks: Buffer[] = [];
  let total = 0;
  return await new Promise<{ ok: boolean; value?: unknown; error?: string }>((resolve) => {
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        resolve({ ok: false, error: "payload too large" });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        if (!raw.trim()) {
          resolve({ ok: false, error: "empty payload" });
          return;
        }
        resolve({ ok: true, value: JSON.parse(raw) as unknown });
      } catch (err) {
        resolve({ ok: false, error: err instanceof Error ? err.message : String(err) });
      }
    });
    req.on("error", (err) => {
      resolve({ ok: false, error: err instanceof Error ? err.message : String(err) });
    });
  });
}

/**
 * 从 IncomingMessage 中提取 HTTP 头
 */
function getHeader(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name.toLowerCase()];
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

function jsonOk(res: ServerResponse, body: unknown): void {
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

export function registerYZJWebhookTarget(target: YZJWebhookTarget): () => void {
  const key = normalizeWebhookPath(target.path);
  const normalizedTarget = { ...target, path: key };
  const existing = webhookTargets.get(key) ?? [];
  const next = [...existing, normalizedTarget];
  webhookTargets.set(key, next);
  return () => {
    const updated = (webhookTargets.get(key) ?? []).filter((entry) => entry !== normalizedTarget);
    if (updated.length > 0) webhookTargets.set(key, updated);
    else webhookTargets.delete(key);
  };
}

export async function handleYZJWebhookRequest(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const path = resolvePath(req);
  const targets = webhookTargets.get(path);
  if (!targets || targets.length === 0) return false;

  const firstTarget = targets[0]!;
  firstTarget.runtime.log?.(`[yzj] incoming ${req.method} request on ${path}`);

  if (req.method === "GET") {
    // 健康检查
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("OK");
    return true;
  }

  if (req.method !== "POST") {
    res.statusCode = 405;
    res.setHeader("Allow", "GET, POST");
    res.end("Method Not Allowed");
    return true;
  }

  const body = await readJsonBody(req, 1024 * 1024);
  if (!body.ok) {
    firstTarget.runtime.error?.(`[yzj] POST body read failed: ${body.error}`);
    res.statusCode = body.error === "payload too large" ? 413 : 400;
    res.end(body.error ?? "invalid payload");
    return true;
  }

  const msg = body.value as YZJIncomingMessage;

  // 验证必填字段
  if (!msg.content) {
    res.statusCode = 400;
    res.end("missing required fields");
    return true;
  }

  // 签名验证：只要配置了 secret 就启用验证
  const secret = firstTarget.account.secret;

  if (secret && msg.robotId != 'test-robotId') {
    // 从请求头中提取签名
    const sign = getHeader(req, "sign");
    if (!sign) {
      firstTarget.runtime.error?.(`[yzj] 请求头中缺少 sign 签名`);
      res.statusCode = 401;
      res.end("missing sign header");
      return true;
    }

    // 验证签名
    const verificationResult = verifySignature(msg, sign, secret);
    if (!verificationResult.valid) {
      firstTarget.runtime.error?.(`[yzj] 签名验证失败：${verificationResult.error}`);
      res.statusCode = 401;
      res.end("invalid signature");
      return true;
    }

    firstTarget.runtime.log?.(`[yzj] 签名验证通过`);
  }

  // 更新状态
  firstTarget.statusSink?.({ lastInboundAt: Date.now() });

  // 立即返回确认响应
  const response: YZJResponse = {
    success: true,
    data: {
      type: 2 as MessageType,
      content: ""
    }
  };
  jsonOk(res, response);

  // 在后台启动 Agent 处理
  let core: PluginRuntime | null = null;
  try {
    core = getYZJRuntime();
  } catch (err) {
    firstTarget.runtime.error?.(`[yzj] runtime not ready, skipping agent processing: ${String(err)}`);
    return true;
  }

  if (core) {
    const enrichedTarget: YZJWebhookTarget = { ...firstTarget, core };
    startAgentForInbound(enrichedTarget, msg).catch((err) => {
      const errorMsg = err instanceof Error ? err.message : String(err);
      enrichedTarget.runtime.error?.(`[${firstTarget.account.accountId}] yzj agent failed: ${errorMsg}`);
      // 发送错误提示给用户
      sendYZJMessage(enrichedTarget, msg.operatorOpenid, `抱歉，处理您的消息时遇到问题: ${errorMsg}`);
    });
  }

  return true;
}
