/**
 * YZJ Webhook 签名验证工具
 *
 * 提供签名验证功能，确保请求来自云之家
 */

import { Buffer } from 'node:buffer';
import { createHmac } from 'node:crypto';

import type { YZJIncomingMessage, SignatureVerificationResult } from "./types.js";

/**
 * 常量时间 Buffer 比较（防止时序攻击）
 * @param a - Buffer a
 * @param b - Buffer b
 * @returns 是否相等
 */
function timingSafeEqualBuffer(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

/**
 * 使用 HmacSHA1 算法计算签名
 * @param data - 待签名的数据
 * @param secret - 签名密钥
 * @returns Base64 编码的签名
 */
export function computeHmacSha1(data: string, secret: string): string {
  // 使用 Node.js crypto 模块进行 HmacSHA1 签名
  const hmac = createHmac('sha1', secret);
  hmac.update(data, 'utf8');
  return hmac.digest('base64');
}

/**
 * 构建签名字符串
 * 将消息字段按顺序用逗号拼接
 * @param msg - 入站消息
 * @returns 签名字符串
 */
export function buildSignatureString(msg: YZJIncomingMessage): string {
  return [
    msg.robotId,
    msg.robotName,
    msg.operatorOpenid,
    msg.operatorName,
    String(msg.time),
    msg.msgId,
    msg.content
  ].join(",");
}

/**
 * 验证 Webhook 请求的签名
 * @param msg - 入站消息
 * @param signature - 请求头中的签名值
 * @param secret - 机器人的签名密钥
 * @returns 验证结果
 */
export function verifySignature(
  msg: YZJIncomingMessage,
  signature: string,
  secret: string
): SignatureVerificationResult {
  try {
    // 构建签名字符串
    const signatureString = buildSignatureString(msg);

    // 计算期望的签名
    const expectedSignature = computeHmacSha1(signatureString, secret);

    if (signature == expectedSignature) {
      return { valid: true };
    }
    return {
      valid: false,
      error: `signatureString: ${signatureString}\nexpectedSignature: ${expectedSignature}\nsignature: ${signature}`
    }
  } catch (error) {
    return {
      valid: false,
      error: `签名验证过程出错：${error instanceof Error ? error.message : String(error)}`
    };
  }
}

/**
 * 从 HTTP 请求头中提取签名相关信息
 * @param headers - HTTP 请求头对象
 * @returns 提取的签名信息
 */
export function extractSignatureFromHeaders(headers: Record<string, string | undefined>): {
  sign?: string;
  sessionId?: string;
} {
  // 处理不同大小写的 header 名称
  const sign = headers["sign"] || headers["Sign"] || headers["SIGN"];
  const sessionId = headers["sessionId"] || headers["SessionId"] || headers["SESSIONID"] || headers["session-id"];

  return { sign, sessionId };
}
