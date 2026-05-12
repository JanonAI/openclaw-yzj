/**
 * YZJ 配置 Schema 定义
 *
 * 定义云之家(YZJ) Robot Channel 的配置验证规则
 *
 */

import type { ChannelConfigSchema } from "./compat.ts";

const accountSchema = {
  type: "object",
  properties: {
    name: { type: "string" },
    enabled: { type: "boolean" },
    endpoint: { type: "string" },
    appId: { type: "string" },
    appSecret: { type: "string" },
    sendMsgUrl: { type: "string" },
    webhookPath: { type: "string" },
    timeout: { type: "number" },
    inboundMode: { type: "string", enum: ["webhook", "websocket"] },
    mediaLocalRoots: {
      type: "array",
      items: { type: "string" },
    },
    secret: { type: "string" },
  },
  additionalProperties: false,
};

export const yzjConfigSchema: ChannelConfigSchema = {
  schema: {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    properties: {
      name: { type: "string" },
      enabled: { type: "boolean" },
      endpoint: { type: "string", default: "https://yunzhijia.com" },
      appId: { type: "string" },
      appSecret: { type: "string" },
      sendMsgUrl: { type: "string" },
      webhookPath: { type: "string", default: "/yzj/webhook" },
      timeout: { type: "number", default: 10 },
      inboundMode: { type: "string", enum: ["webhook", "websocket"], default: "webhook" },
      mediaLocalRoots: {
        type: "array",
        items: { type: "string" },
      },
      defaultAccount: { type: "string" },
      accounts: {
        type: "object",
        additionalProperties: accountSchema,
      },
    },
    additionalProperties: false,
  },
};
