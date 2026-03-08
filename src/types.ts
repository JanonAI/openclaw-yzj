/**
 * YZJ Robot Webhook 类型定义
 *
 * 提供与云之家 (YZJ) Robot Webhook API 交互所需的接口定义
 */

/**
 * 消息类型枚举
 */
export enum MessageType {
  /** 文本消息 */
  TEXT = 2
}

/**
 * YZJ Robot Webhook 接收的消息格式
 */
export interface YZJIncomingMessage {
  /** 消息类型 */
  type: number;
  /** 机器人 ID */
  robotId: string;
  /** 机器人名称 */
  robotName: string;
  /** 发送者 OpenID */
  operatorOpenid: string;
  /** 发送者姓名 */
  operatorName: string;
  /** 时间戳 */
  time: number;
  /** 消息 ID */
  msgId: string;
  /** 消息内容 */
  content: string;
}

/**
 * YZJ 发送消息的请求格式
 */
export interface YZJOutgoingMessage {
  /** 消息类型 */
  msgtype: MessageType;
  /** 消息内容 */
  content: string;
}

/**
 * YZJ 发送消息的响应格式
 */
export interface YZJResponse {
  /** 是否成功 */
  success: boolean;
  /** 响应数据 */
  data: {
    /** 消息类型 */
    type: number;
    /** 消息内容 */
    content: string;
  };
  /** 错误信息（可选） */
  error?: string;
}

/**
 * YZJ 账户配置
 */
export interface YZJAccountConfig {
  /** 是否启用 */
  enabled?: boolean;
  /** 账户名称 */
  name?: string;
  /** 发送消息的 URL（必需） */
  sendMsgUrl?: string;
  /** Webhook 路径（可选，默认 /yzj/webhook） */
  webhookPath?: string;
  /** 超时时间（可选，默认 10 秒） */
  timeout?: number;
  /** 签名验证密钥（用于验证来自云之家的请求） */
  secret?: string;
}

/**
 * YZJ 通道配置
 */
export interface YZJConfig {
  /** 是否启用 */
  enabled?: boolean;
  /** 默认账户 ID */
  defaultAccount?: string;
  /** 发送消息的 URL（全局配置） */
  sendMsgUrl?: string;
  /** Webhook 路径（全局配置） */
  webhookPath?: string;
  /** 超时时间（全局配置） */
  timeout?: number;
  /** 多账户配置 */
  accounts?: Record<string, YZJAccountConfig>;
}

/**
 * 解析后的 YZJ 账户信息
 */
export interface ResolvedYZJAccount {
  /** 账户 ID */
  accountId: string;
  /** 账户名称 */
  name?: string;
  /** 是否启用 */
  enabled: boolean;
  /** 是否已配置 */
  configured: boolean;
  /** 发送消息的 URL */
  sendMsgUrl: string;
  /** Webhook 路径 */
  webhookPath: string;
  /** 超时时间 */
  timeout: number;
  /** 签名验证密钥 */
  secret?: string;
  /** 原始配置 */
  config: YZJAccountConfig;
}

/**
 * Webhook 请求头中的签名信息
 */
export interface YZJWebhookHeaders {
  /** 签名值 */
  sign?: string;
  /** 会话 ID */
  sessionId?: string;
  /** 内容类型 */
  "content-type"?: string;
}

/**
 * 签名验证结果
 */
export interface SignatureVerificationResult {
  /** 验证是否通过 */
  valid: boolean;
  /** 错误信息（如果验证失败） */
  error?: string;
}
