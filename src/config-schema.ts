/**
 * YZJ 配置 Schema 定义
 *
 * 定义云之家(YZJ) Robot Channel 的配置验证规则
 *
 */

import type { ChannelConfigSchema } from "./compat.js";

const accountSchema = {
  type: "object",
  properties: {
    name: { type: "string" },
    enabled: { type: "boolean" },
    sendMsgUrl: { type: "string" },
    webhookPath: { type: "string" },
    timeout: { type: "number" },
    secret: { type: "string" },
  },
  required: ["sendMsgUrl"],
  additionalProperties: false,
};

export const yzjConfigSchema: ChannelConfigSchema = {
  schema: {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    properties: {
      name: { type: "string" },
      enabled: { type: "boolean" },
      sendMsgUrl: { type: "string" },
      webhookPath: { type: "string", default: "/yzj/webhook" },
      timeout: { type: "number", default: 10 },
      defaultAccount: { type: "string" },
      accounts: {
        type: "object",
        additionalProperties: accountSchema,
      },
    },
    // 条件必需验证
    if: {
      required: ["accounts"]
    },
    then: {
      // 有 accounts 时：sendMsgUrl 可选
      required: []
    },
    else: {
      // 无 accounts 时：sendMsgUrl 必需
      required: ["sendMsgUrl"]
    },
    additionalProperties: false,
  },
};
