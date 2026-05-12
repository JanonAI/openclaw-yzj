/**
 * YZJ Robot Webhook 监听器
 *
 * 提供 Webhook 处理器，接收来自 YZJ Robot 的消息
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import type { YZJIncomingMessage, YZJResponse } from "./types.ts";
import { dispatchInboundMessage } from "./inbound-dispatcher.ts";
import { verifySignature } from "./signature.ts";
import type { YZJInboundTarget } from "./inbound-dispatcher.ts";

type YZJWebhookTarget = YZJInboundTarget & {
  path: string;
};

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

function getHeader(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name.toLowerCase()];
  if (Array.isArray(value)) return value[0];
  return value;
}

function jsonOk(res: ServerResponse, body: unknown): void {
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function isValidIncomingMessage(value: unknown): value is YZJIncomingMessage {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return typeof record.type === "number"
    && typeof record.robotId === "string"
    && typeof record.robotName === "string"
    && typeof record.operatorOpenid === "string"
    && typeof record.operatorName === "string"
    && typeof record.time === "number"
    && typeof record.msgId === "string"
    && typeof record.content === "string"
    && record.content.trim().length > 0
    && typeof record.groupType === "number"
    && (record.groupId === undefined || typeof record.groupId === "string");
}

export function registerYZJWebhookTarget(target: YZJWebhookTarget): () => void {
  const key = normalizeWebhookPath(target.path);
  const normalizedTarget = { ...target, path: key };
  const existing = webhookTargets.get(key) ?? [];
  webhookTargets.set(key, [...existing, normalizedTarget]);

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
  firstTarget.runtime.info?.(`[yzj] incoming ${req.method} request on ${path}`);

  if (req.method === "GET") {
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

  if (!isValidIncomingMessage(body.value)) {
    res.statusCode = 400;
    res.end("missing required fields");
    return true;
  }
  const msg = body.value;

  const sign = getHeader(req, "sign");
  const acceptedTargets = targets.filter((target) => {
    const secret = target.account.secret;
    if (!secret) return true;

    if (!sign) {
      target.runtime.error?.(`[yzj] 请求头中缺少 sign 签名`);
      return false;
    }

    const verificationResult = verifySignature(msg, sign, secret);
    if (!verificationResult.valid) {
      target.runtime.error?.(`[yzj] 签名验证失败：${verificationResult.error}`);
      return false;
    }

    target.runtime.info?.(`[yzj] 签名验证通过`);
    return true;
  });

  if (acceptedTargets.length === 0) {
    res.statusCode = 401;
    res.end(sign ? "invalid signature" : "missing sign header");
    return true;
  }

  const response: YZJResponse = {
    success: true,
    data: {
      type: 2,
      content: "",
    },
  };
  jsonOk(res, response);

  void Promise.all(
    acceptedTargets.map(async (target) => {
      try {
        await dispatchInboundMessage(target, msg, "webhook");
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        target.runtime.error?.(`[${target.account.accountId}] yzj webhook agent failed: ${errorMsg}`);
      }
    }),
  );

  return true;
}
