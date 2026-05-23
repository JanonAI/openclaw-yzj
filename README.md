# YZJ Robot Channel Plugin for OpenClaw

云之家（YunZhiJia）群组对话机器人通道插件，通过 HTTP API + Webhook / WebSocket 实现双向消息通信。

> 📘 **完整教程**：查看 [云之家集成教程](./docs/tutorial.md) 了解如何在公有云上部署 OpenClaw 并集成云之家机器人。

## 功能特性

- **HTTP API 集成**：通过云之家 API 发送消息
- **应用机器人集成（新增）**：配置 `appId`、`appSecret` 后，插件可接收应用机器人消息，并支持发送文本、文件、图片和 mp4 视频
- **Webhook 接收**：接收云之家机器人的消息推送
- **WebSocket 接收**：从 `sendMsgUrl` 自动推导 WebSocket 长连接地址并接收入站消息
- **应用机器人 WebSocket（新增）**：应用机器人也支持长连接接收
- **双入口去重**：当 Webhook 和 WebSocket 同时收到同一条消息时，按 `msgId` 自动去重
- **主动发消息**：支持主动向指定用户发送消息（通过 OpenID 指定接收者）
- **媒体发送（新增）**：应用机器人可发送文件、图片和 mp4 视频；个人机器人 `sendMsgUrl` 模式仍只支持文本
- **OpenClaw HTTP 处理器**：使用 OpenClaw 内置的 HTTP 处理器（Node.js 原生 http 模块）
- **多账户支持**：支持配置多个云之家机器人账户
- **完整类型支持**：TypeScript 类型安全
- **双平台兼容**：同时支持 OpenClaw 和 ClawDBot

## 前置要求

在安装插件前，你需要先获取云之家机器人。

### 个人机器人

#### 1. 登录云之家

打开云之家官网：https://www.yunzhijia.com/

使用你的云之家账号完成登录。

#### 2. 进入个人机器人页面

登录完成后，直接访问以下地址：

https://www.yunzhijia.com/im/personalRobotCreate

### 群组对话机器人

### 1. 创建群组中的对话机器人

参考 [云之家集成教程](./docs/tutorial.md)

## 安装

### 方式 A：本地安装

上传 release中的openclaw-yzj.zip到服务器上，不需要解压

```bash
openclaw plugins install ./openclaw-yzj.zip
openclaw plugins enable yzj
openclaw gateway restart
```

### 方式 B：通过对话安装

如果你已经能在 OpenClaw 的 WebUI 或终端里正常和助手对话，直接告诉 OpenClaw 这几句话就行，OpenClaw 就会自己帮你配好：

```text
1. 看一下这个地址：https://github.com/JanonAI/openclaw-yzj
2. 配置 yzj channel，使用 websocket 模式
3. sendMsgUrl 是：https://www.yunzhijia.com/gateway/robot/webhook/send?yzjtype=0&yzjtoken=xxxxxxxxxxxxxxxxxx
```

如果希望它直接通过 ZIP 安装，也可以把第 1 句换成：

```text
1. 看一下这个地址：https://github.com/JanonAI/openclaw-yzj/archive/refs/heads/main.zip
```

如果当前环境禁止助手执行命令或访问网络，请改用下面的命令行安装方式。

### 方式 C：从 GitHub 安装

> ⚠️ **重要**：仓库与 GitHub archive 包均不含 `dist/` 目录（已被 `.gitignore` 排除）。
> 从源码安装前**必须先执行 `npm install && npm run build`** 生成 `dist/index.js`，
> 否则会报错 `extension entry not found: ./dist/index.js`。
> 如需开箱即用的预构建包，请使用 [Release 资源](https://github.com/JanonAI/openclaw-yzj/releases) 中的 `openclaw-yzj.zip`（参见方式 A）。

**方法 1：克隆仓库**

```bash
# 克隆仓库
git clone https://github.com/JanonAI/openclaw-yzj.git
cd openclaw-yzj

# 安装依赖并构建（必须，生成 dist/index.js）
npm install
npm run build

# 安装插件
cd ..
openclaw plugins install ./openclaw-yzj
openclaw plugins enable yzj
openclaw gateway restart
```

**方法 2：下载 ZIP 压缩包**

GitHub 自动打包的 archive zip 同样不含 `dist/`，需要解压后构建：

```bash
# 下载并解压
wget https://github.com/JanonAI/openclaw-yzj/archive/refs/heads/main.zip
unzip main.zip
cd openclaw-yzj-main

# 安装依赖并构建
npm install
npm run build

# 安装插件（指向已构建目录，而非 zip）
cd ..
openclaw plugins install ./openclaw-yzj-main
openclaw plugins enable yzj
openclaw gateway restart
```

或者使用 curl：

```bash
curl -L https://github.com/JanonAI/openclaw-yzj/archive/refs/heads/main.zip -o main.zip
unzip main.zip
cd openclaw-yzj-main && npm install && npm run build && cd ..
openclaw plugins install ./openclaw-yzj-main
openclaw plugins enable yzj
openclaw gateway restart
```

**安装特定版本**：

```bash
# 下载特定分支或标签
wget https://github.com/JanonAI/openclaw-yzj/archive/refs/heads/develop.zip
# 或 wget https://github.com/JanonAI/openclaw-yzj/archive/refs/tags/v2026.3.6.zip

# 同样需要解压 → npm install && npm run build → 再 install 目录
unzip develop.zip
cd openclaw-yzj-develop && npm install && npm run build && cd ..
openclaw plugins install ./openclaw-yzj-develop
```

### 方式 D：本地开发（link）

```bash
# 首次或源码变更后均需重新构建
cd extensions/yzj
npm install
npm run build
cd ../..

openclaw plugins install --link extensions/yzj
openclaw plugins enable yzj
openclaw gateway restart
```

### 方式 E：WorkBuddy 直接配置（推荐中国区用户）

如果你是通过腾讯 WorkBuddy (Claw) 使用本插件，可以直接在 WorkBuddy 设置中添加云之家通道，无需手动安装 ZIP 包或运行命令行。

#### 配置步骤

1. 打开 WorkBuddy 设置 → 插件管理
2. 确认 `yzj` 插件已启用（如果没有请先安装）
3. 进入「通道」配置，添加云之家（YZJ）通道
4. 选择 **WebSocket** 作为入站模式（推荐，自动维持长连接）
5. 在「发送消息地址」中填入你的云之家机器人 Webhook 地址，格式为：
   ```
   https://www.yunzhijia.com/gateway/robot/webhook/send?yzjtype=0&yzjtoken=你的机器人Token
   ```
   > 机器人 Token（`yzjtoken` 参数）请替换为你自己的，从云之家管理后台的机器人配置页面获取。
6. 保存配置，WorkBuddy 会自动重连

#### 对应配置文件（供参考）

如果你需要手动编辑 WorkBuddy 的 `settings.json`，配置如下：

```json
{
  "enabledPlugins": {
    "yzj@codebuddy-plugins-official": true
  },
  "channels": {
    "yzj": {
      "enabled": true,
      "inboundMode": "websocket",
      "sendMsgUrl": "https://www.yunzhijia.com/gateway/robot/webhook/send?yzjtype=0&yzjtoken=你的机器人Token",
      "webhookPath": "/yzj/webhook",
      "timeout": 10000
    }
  }
}
```

> **重要说明**：
> - `sendMsgUrl` 中的 Token 请务必替换为你自己的云之家机器人 Token，切勿使用他人的 Token。
> - WebSocket 模式下，WorkBuddy 会自动从 `sendMsgUrl` 推导长连接地址，无需额外配置 WebSocket URL。
> - 如果使用 Webhook 模式（公网可达时），需要额外配置公网可访问的 Webhook 接收地址。

#### 获取云之家机器人 Token

1. 登录 [云之家管理后台](https://www.yunzhijia.com/)
2. 进入「应用管理」→「机器人」，创建或查看已有机器人的 Token
3. 复制机器人的 Webhook 地址，填入上面的配置中

## 配置

### 基本配置（单账户）

```yaml
channels:
  yzj:
    enabled: true
    # 入站模式（可选：webhook | websocket，默认 webhook）
    inboundMode: "webhook"
    # 发送消息的 API URL（必需）
    sendMsgUrl: "https://www.yunzhijia.com/robot/send"
    # Webhook 路径（可选，默认 /yzj/webhook）
    webhookPath: "/yzj/webhook"
    # 超时时间，单位秒（可选，默认 10）
    timeout: 10
```

### 应用机器人配置（新增）

如果需要应用机器人长连接和媒体发送能力，再配置 `appId/appSecret`：

```yaml
channels:
  yzj:
    enabled: true
    appId: "your-app-id"
    appSecret: "your-app-secret"
    # 应用机器人使用 websocket
    inboundMode: "websocket"
    webhookPath: "/yzj/webhook"
    timeout: 10
```

### 多账户配置

`accounts` 用来同时配置多个机器人账号。原来的 `sendMsgUrl` 多账户方式仍然可用；如果同时接入应用机器人，建议把 `appId/appSecret` 和 `sendMsgUrl` 放到不同账户，避免入站来源和出站回复链路串线。

```yaml
channels:
  yzj:
    enabled: true
    # 默认账户（可选）
    defaultAccount: "bot1"
    # 通道级默认入站模式（可被账户覆盖）
    inboundMode: "webhook"
    # 全局默认配置（可选）
    webhookPath: "/yzj/webhook"
    timeout: 10

    accounts:
      bot1:
        name: "生产环境机器人"
        enabled: true
        sendMsgUrl: "https://www.yunzhijia.com/robot/send"
        inboundMode: "webhook"
        webhookPath: "/yzj/bot1"
        timeout: 10

      bot2:
        name: "测试环境机器人"
        enabled: true
        sendMsgUrl: "https://test.yunzhijia.com/robot/send"
        inboundMode: "webhook"
        webhookPath: "/yzj/bot2"
        timeout: 5

      app:
        name: "应用机器人"
        enabled: true
        appId: "your-app-id"
        appSecret: "your-app-secret"
        inboundMode: "websocket"
        timeout: 10
```

兼容说明：如果历史配置把通道顶层的 `appId/appSecret` 和 `sendMsgUrl` 同时填了，插件会在运行时把它们视为两个账号：`app` 和 `personal`。新配置建议显式写到 `accounts`，更容易看日志和排查问题。

显式配置 `accounts` 后，插件只会启动这些真实账号，不会再额外启动 `default` 虚账号。账户只继承 `webhookPath`、`timeout`、`inboundMode` 等共享运行配置，不继承顶层的 `appId/appSecret/sendMsgUrl/secret` 身份字段。这样从 `personal` 账号收到的消息只会用 `sendMsgUrl` 回复，从 `app` 账号收到的消息只会用应用机器人接口回复。

### 网络绑定配置

由于需要接收云之家的 Webhook 推送，需要配置 OpenClaw Gateway 绑定到局域网：

```yaml
gateway:
  bind: "lan"  # 或 "0.0.0.0"
```

配置向导会自动设置此项。

## 配置说明

### 通道级别配置

| 配置项 | 类型 | 必填 | 默认值 | 说明 |
|--------|------|------|--------|------|
| `enabled` | boolean | 否 | - | 是否启用该通道 |
| `name` | string | 否 | - | 通道名称 |
| `appId` | string | 应用机器人必填 | - | 云之家应用 appId |
| `appSecret` | string | 应用机器人必填 | - | 云之家应用密钥 |
| `sendMsgUrl` | string | 个人机器人必填 | - | 机器人发送消息接口地址 |
| `inboundMode` | string | 否 | `webhook` | 入站模式：`webhook` 或 `websocket` |
| `webhookPath` | string | 否 | `/yzj/webhook` | Webhook 接收路径 |
| `timeout` | number | 否 | `10` | 请求超时时间（秒） |
| `defaultAccount` | string | 否 | - | 默认账户 ID |
| `accounts` | object | 否 | - | 多账户配置对象 |

*注：`appId/appSecret` 对应应用机器人；`sendMsgUrl` 对应个人机器人。两者如果代表不同机器人，应放在不同 `accounts` 里。

媒体能力说明：只有应用机器人账号能上传并发送文件、图片和 mp4 视频。个人机器人 `sendMsgUrl` 账号只能发送文本；如果用户要求发送媒体，插件会回复：`当前个人机器人只支持发送文本，暂不支持上传图片、文件或视频。`

### 账户级别配置（accounts）

| 配置项 | 类型 | 必填 | 默认值 | 说明 |
|--------|------|------|--------|------|
| `name` | string | 否 | - | 账户名称 |
| `enabled` | boolean | 否 | - | 是否启用该账户 |
| `appId` | string | 应用机器人必填 | - | 云之家应用 appId |
| `appSecret` | string | 应用机器人必填 | - | 云之家应用密钥 |
| `sendMsgUrl` | string | 个人机器人必填 | - | 机器人发送消息接口地址 |
| `inboundMode` | string | 否 | 继承通道级配置 | 入站模式：`webhook` 或 `websocket` |
| `webhookPath` | string | 否 | - | Webhook 接收路径（继承通道级别配置） |
| `timeout` | number | 否 | - | 请求超时时间（秒，继承通道级别配置） |
| `secret` | string | 否 | - | 签名验证密钥（配置后自动启用签名验证） |

注：配置 `secret` 后会自动启用签名验证，不配置则不进行签名验证。

注：使用 `accounts` 多账户时，`appId/appSecret/sendMsgUrl/secret` 是账户身份字段，必须写在对应账号下面。顶层同名字段只用于旧单账号配置或历史兼容，不会注入到显式账号。

## WebSocket 模式

当 `inboundMode: websocket` 时：

- 插件仍然使用 `sendMsgUrl` 发送回复
- 插件会从 `sendMsgUrl` 中提取机器人 token 和 host，自动推导 WebSocket 地址
- `webhookPath` 仍然保留，作为并行兜底入口
- 两个入口若收到相同 `msgId`，插件只处理一次

新增说明：应用机器人模式使用 `appId/appSecret` 建立长连接，可发送文本、图片、文件和 mp4 视频。也就是说，原来的 `sendMsgUrl` 配置方式仍然可用；应用机器人是在此基础上的新增能力。

## 签名验证

### 概述

为了确保请求来自云之家，避免仿冒请求，插件支持签名验证功能。当启用签名验证时，插件会验证每个 Webhook 请求的签名。

### 签名算法

云之家使用 HmacSHA1 算法进行签名：

1. **构建签名字符串**：将消息字段按顺序用逗号拼接
   ```
   robotId,robotName,operatorOpenid,operatorName,time,msgId,content
   ```

2. **计算签名**：使用 `secret` 作为密钥，对签名字符串进行 HmacSHA1 签名

3. **Base64 编码**：将签名结果进行 Base64 编码得到最终签名值

### 配置签名验证

配置 `secret` 后会自动启用签名验证：

```yaml
channels:
  yzj:
    enabled: true
    sendMsgUrl: "https://www.yunzhijia.com/robot/send"
    webhookPath: "/yzj/webhook"

    # 多账户配置
    accounts:
      bot1:
        name: "生产环境机器人"
        enabled: true
        sendMsgUrl: "https://www.yunzhijia.com/robot/send"
        webhookPath: "/yzj/bot1"
        # 签名验证密钥（配置后自动启用验证）
        secret: "your-app-secret-here"
```

### 禁用签名验证

如果仅在受信任的内网环境部署，不配置 `secret` 即可禁用签名验证：

```yaml
channels:
  yzj:
    enabled: true
    sendMsgUrl: "https://www.yunzhijia.com/robot/send"
    accounts:
      bot1:
        name: "内网机器人"
        enabled: true
        sendMsgUrl: "https://intranet.yunzhijia.com/robot/send"
        # 不配置 secret，不进行签名验证
```

### 签名验证流程

```
1. 云之家发起请求
   ↓
2. 插件接收请求，读取 body
   ↓
3. 检查是否配置了 secret
   ↓
4. 从请求头中提取 sign
   ↓
5. 使用相同的算法计算期望签名
   ↓
6. 比较签名是否一致
   ↓
7. 验证通过：处理消息 | 验证失败：返回 401 错误
```

### 测试签名验证

使用以下命令测试 Webhook（需要正确的签名）：

```bash
# 示例：使用正确的签名
curl -X POST http://localhost:3000/yzj/webhook \
  -H "Content-Type: application/json" \
  -H "sign: <computed-signature>" \
  -d '{
    "type": 2,
    "robotId": "test_bot",
    "robotName": "测试",
    "operatorOpenid": "test_user",
    "operatorName": "测试用户",
    "time": 1678901234567,
    "msgId": "test_msg",
    "content": "测试消息"
  }'
```

### 签名验证错误处理

| 错误情况 | HTTP 状态码 | 说明 |
|----------|-------------|------|
| 缺少 sign 头 | 401 | 请求头中缺少签名信息 |
| 签名不匹配 | 401 | 签名值与计算结果不一致 |
| 未配置 secret | 500 | 启用了签名验证但未配置密钥 |

## 消息格式

### 接收消息（Webhook）

云之家通过 Webhook 推送消息到 OpenClaw：

```typescript
{
  "type": 2,                    // 消息类型（2=文本）
  "robotId": "bot_001",         // 机器人ID
  "robotName": "助手",           // 机器人名称
  "operatorOpenid": "user_123", // 发送者OpenID
  "operatorName": "张三",        // 发送者姓名
  "time": 1678901234567,        // 时间戳
  "msgId": "msg_456",           // 消息ID
  "content": "你好"             // 消息内容
}
```

### 发送消息（API）

OpenClaw 通过云之家 API 发送消息：

**基本格式**：
```typescript
{
  "msgtype": 2,     // 消息类型（2=文本）
  "content": "您好！有什么可以帮助您的吗？"
}
```

**带指定接收者**（主动发消息）：
```typescript
{
  "msgtype": 2,
  "content": "这是一条主动推送的消息",
  "notifyParams": [{
    "type": "openIds",
    "values": ["user_openid_123"]  // 指定接收者的 OpenID
  }]
}
```

### 应用机器人发送消息（新增）

应用机器人模式使用 `msgType`，并可附带回复参数、文件、图片、视频等媒体参数。插件会根据消息类型自动组装发送 body。

```typescript
{
  "msgType": 2,
  "toOpenId": "user_openid_123",
  "content": "这是一条回复消息",
  "param": {
    "replyOpenId": "user_openid_123",
    "replyMsgId": "msg_456",
    "replyRootMsgId": "msg_456",
    "replySummary": "用户原消息摘要",
    "replyPersonName": "张三",
    "replyTitle": "",
    "notifyTo": ["user_openid_123"]
  }
}
```

### 响应格式

```typescript
{
  "success": true,
  "data": {
    "type": 2,
    "content": "消息已发送"
  }
}
```

## 使用向导

运行配置向导自动设置：

```bash
openclaw onboard yzj
```

向导会引导你完成：

1. 配置云之家机器人（登录云之家管理后台）
2. 设置 Webhook URL
3. 获取发送消息的 URL
4. 配置 OpenClaw 通道
5. 如使用应用机器人，再补充 `appId/appSecret`

## 云之家后台配置

### 1. 在群组中创建对话机器人

**前提条件**：需要群组管理员权限

1. 打开云之家客户端，进入需要添加机器人的群组
2. 点击群组设置，进入「群管理」
3. 找到「智能机器人」或「对话机器人」选项
4. 点击「新建对话机器人」或「添加机器人」
5. 填写机器人基本信息：
   - 机器人名称：如"智能助手"
   - 机器人描述：根据需要填写
   - 机器人头像：上传或选择默认头像
6. 保存创建

### 2. 配置消息接收地址（Webhook）

1. 创建完成后，进入机器人详情页
2. 找到「消息接收地址」或「回调地址」配置项
3. 填写 OpenClaw YZJ Robot 的 Webhook 地址：

   **格式**：`http://your-server:port/yzj/webhook`

   **示例**：
   - 本地开发：`http://localhost:3000/yzj/webhook`
   - 局域网：`http://192.168.1.100:3000/yzj/webhook`
   - 公网：`https://your-domain.com/yzj/webhook`

4. 保存配置

### 3. 获取发送消息的 URL（sendMsgUrl）

1. 保存 Webhook 配置后，刷新页面或重新进入机器人详情页
2. 在机器人信息中查看完整信息，会显示该机器人的 **发送消息接口地址**
3. 复制该地址（格式类似：`https://www.yunzhijia.com/robot/send` 或自定义域名）
4. 将该地址填写到 OpenClaw YZJ Robot 配置中的 `sendMsgUrl` 字段

**配置示例**：

```yaml
channels:
  yzj:
    enabled: true
    # 步骤 3 中复制的发送消息接口地址
    sendMsgUrl: "https://www.yunzhijia.com/robot/send"
    # 步骤 2 中配置的 Webhook 地址路径
    webhookPath: "/yzj/webhook"
    timeout: 10
```

### 4. 配置应用机器人凭证

如果需要应用机器人长连接和媒体发送能力，再补充 `appId` 和 `appSecret`。不使用应用机器人时，可以只配置上一步的 `sendMsgUrl`。

1. 在云之家开放平台准备应用 `appId` 和 `appSecret`
2. 确认应用已开通机器人 WebSocket 和发送消息相关权限
3. 在 OpenClaw YZJ Robot 配置中填写 `appId`、`appSecret`
4. 插件会自动建立长连接，出站可发送文本和媒体

**配置示例**：

```yaml
channels:
  yzj:
    enabled: true
    appId: "your-app-id"
    appSecret: "your-app-secret"
    inboundMode: "websocket"
    webhookPath: "/yzj/webhook"
    timeout: 10
```

### 5. 配置注意事项

- **Webhook 地址必须可访问**：确保云之家服务器能够访问到你的 OpenClaw Gateway
- **本地开发需要内网穿透**：使用 ngrok、frp 等工具将本地服务暴露到公网
- **生产环境建议使用 HTTPS**：更安全，且某些企业环境可能要求
- **测试配置**：在群组中 @机器人 发送测试消息，查看 OpenClaw 日志确认是否收到

## 消息类型支持

目前支持的消息类型：

| 类型 | 值 | 说明 |
|------|-----|------|
| 文本 | `2` | 纯文本消息 |
| 文件 | `8` | 应用机器人支持 |
| 视频 | `8` | 应用机器人支持，mp4 按文件消息发送 |
| 富文本 | `23` | 应用机器人支持，可用于图片等内容 |

说明：个人机器人 `sendMsgUrl` 模式只支持文本；文件、图片、mp4 视频需要应用机器人模式。

## 核心功能实现

### 1. 账户管理（accounts.ts）

支持灵活的多账户配置：

- **单账户模式**：直接在通道级别配置 `sendMsgUrl`；需要应用机器人能力时再配置 `appId/appSecret`
- **多账户模式**：通过 `accounts` 对象配置多个机器人
- **配置合并**：账户配置继承全局默认配置
- **账户解析**：自动解析默认账户和指定账户

关键函数：
- `listYZJAccountIds()` - 列出所有账户 ID
- `resolveDefaultYZJAccountId()` - 解析默认账户
- `resolveYZJAccount()` - 解析完整账户信息
- `mergeYZJAccountConfig()` - 合并账户配置
- `listEnabledYZJAccounts()` - 列出已启用账户

### 2. 消息处理流程

```
┌─────────────┐
│ 云之家用户  │
└──────┬──────┘
       │ 发送消息
       ▼
┌─────────────────────┐
│ Webhook 推送        │
│ (POST /yzj/webhook) │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────────┐
│ monitor.ts              │
│ handleYZJWebhookRequest │
└──────┬──────────────────┘
       │
       ▼
┌─────────────────────────┐
│ 解析消息                │
│ - 验证消息格式          │
│ - 提取元数据            │
└──────┬──────────────────┘
       │
       ▼
┌─────────────────────────┐
│ startAgentForInbound    │
│ - 构建 Agent Envelope   │
│ - 分发到 Agent 处理     │
└──────┬──────────────────┘
       │
       ▼
┌─────────────────────────┐
│ Agent 处理响应          │
│ - 生成回复消息          │
└──────┬──────────────────┘
       │
       ▼
┌─────────────────────────┐
│ sendYZJMessage          │
│ - 调用云之家 API        │
│ - 发送回复消息          │
└──────┬──────────────────┘
       │
       ▼
┌─────────────┐
│ 云之家用户  │
└─────────────┘
```

### 3. 通道能力配置

通过 `src/channel.ts` 实现的 Channel 接口支持：

**支持的功能：**
- ✅ 私聊消息（DM）
- ✅ 群聊消息
- ✅ 文本消息发送
- ✅ 媒体消息发送（文件、图片、mp4 视频；应用模式）
- ✅ 主动消息推送（通过 OpenID 指定接收者）
- ✅ 多账户管理

**不支持的功能：**
- ❌ 表情符号
- ❌ 线程回复
- ❌ 投票功能
- ❌ 原生命令
- ❌ 流式响应（云之家 API 限制）

**安全策略：**
- 私聊消息策略：`pairing`（配对模式）
- 不支持 `allowFrom` 配置

## 故障排查

### Webhook 无法接收消息

**症状**：在云之家发送消息，OpenClaw 没有响应。

**解决方法**：

1. 检查通道是否启用：
   ```bash
   openclaw config get channels.yzj.enabled
   ```

2. 确认 Gateway 绑定配置：
   ```bash
   openclaw config get gateway.bind
   # 应该是 "lan" 或 "0.0.0.0"
   ```

3. 检查 Webhook 路径是否正确：
   ```bash
   openclaw config get channels.yzj.webhookPath
   ```

4. 确认云之家后台 Webhook URL 配置正确

5. 查看 Gateway 日志：
   ```bash
   openclaw logs --follow
   ```

### API 发送失败

**症状**：OpenClaw 无法发送消息到云之家。

**解决方法**：

1. 个人机器人先检查 `sendMsgUrl` 是否配置：
   ```bash
   openclaw config get channels.yzj.sendMsgUrl
   ```

2. 验证 URL 是否可访问：
   ```bash
   curl -X POST https://api.yunzhijia.com/robot/send \
     -H "Content-Type: application/json" \
     -d '{"msgtype":2,"content":"测试"}'
   ```

3. 应用机器人再检查 `appId/appSecret` 是否配置：
   ```bash
   openclaw config get channels.yzj.appId
   ```

4. 如果应用机器人发送媒体失败，确认应用有发送消息、上传文件和 WebSocket 相关权限。

5. 检查网络连接和防火墙设置。

6. 查看错误日志：
   ```bash
   openclaw logs --follow | grep yzj
   ```

### 配置多账户后无法工作

**症状**：配置了多个账户后，消息无法发送。

**解决方法**：

1. 确认 `defaultAccount` 配置正确：
   ```bash
   openclaw config get channels.yzj.defaultAccount
   ```

2. 检查各账户配置是否完整：
   ```bash
   openclaw config get channels.yzj.accounts
   ```

3. 查看启用的账户：
   ```bash
   openclaw channels list
   ```

## 架构说明

```
yzj/
├── src/
│   ├── types.ts          # 类型定义：消息格式、配置结构、接口定义
│   ├── config-schema.ts  # JSON Schema 配置验证
│   ├── compat.ts         # OpenClaw SDK 兼容层
│   ├── accounts.ts       # 账户配置解析和 app/personal 拆分
│   ├── auth-token.ts     # 应用凭证获取与缓存
│   ├── app-message.ts    # 应用机器人 message/send 出站
│   ├── media-message.ts  # 文件上传与图片/文件/mp4 发送
│   ├── inbound-dispatcher.ts # 入站消息分发、去重和出站队列
│   ├── websocket-client.ts   # WebSocket 长连接、ack、pong、重连
│   ├── onboarding.ts     # 配置向导
│   ├── monitor.ts        # Webhook 处理器
│   └── channel.ts        # 通道插件实现
├── index.ts              # 插件入口（20 行）- 插件注册和初始化
├── package.json          # 包配置（ESM 模块）
├── openclaw.plugin.json  # OpenClaw 插件元数据
├── clawdbot.plugin.json  # ClawDBot 插件元数据
└── README.md             # 本文档
```

### 模块依赖关系

```
index.ts (入口)
  ├── channel.ts (通道插件实现)
  │     ├── accounts.ts (账户管理)
  │     ├── config-schema.ts (配置验证)
  │     ├── auth-token.ts (应用凭证)
  │     ├── app-message.ts (应用机器人出站)
  │     ├── media-message.ts (媒体上传和发送)
  │     ├── websocket-client.ts (长连接入站)
  │     ├── inbound-dispatcher.ts (入站分发)
  │     ├── onboarding.ts (配置向导)
  │     └── monitor.ts (Webhook 处理)
  │           └── types.ts (类型定义)
  ├── compat.ts (平台兼容)
  ├── runtime.ts (运行时)
  └── types.ts (类型定义)
```

## 技术栈

- **运行时**: Node.js (ESM 模块系统)
- **开发语言**: TypeScript
- **HTTP 处理**: Node.js 原生 `http` 模块（`IncomingMessage`, `ServerResponse`）
- **类型验证**: TypeBox v0.34 + JSON Schema
- **平台支持**: OpenClaw / ClawDBot（双平台兼容）
- **依赖管理**: npm

### 版本信息

- **当前版本**: 2026.4.9
- **包名**: yzj

## 开发

### 本地测试

1. Link 插件到本地：
   ```bash
   openclaw plugins install --link /path/to/yzj
   ```

2. 启用并重启：
   ```bash
   openclaw plugins enable yzj
   openclaw gateway restart
   ```

3. 查看 Webhook 日志：
   ```bash
   openclaw logs --follow
   ```

### 调试 Webhook

使用 curl 测试 Webhook 接收：

```bash
curl -X POST http://localhost:3000/yzj/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "type": 2,
    "robotId": "test_bot",
    "robotName": "测试",
    "operatorOpenid": "test_user",
    "operatorName": "测试用户",
    "time": 1678901234567,
    "msgId": "test_msg",
    "content": "测试消息"
  }'
```

### 代码结构要点

#### 类型系统（src/types.ts）

```typescript
// 消息类型枚举
enum MessageType {
  TEXT = 2
}

// 接收消息接口（Webhook）
interface YZJIncomingMessage {
  type: MessageType;           // 消息类型
  robotId: string;             // 机器人ID
  robotName: string;           // 机器人名称
  operatorOpenid: string;      // 发送者OpenID
  operatorName: string;        // 发送者姓名
  time: number;                // 时间戳
  msgId: string;               // 消息ID
  content: string;             // 消息内容
}

// 个人机器人发送消息接口（sendMsgUrl）
interface YZJSendMsgUrlMessage {
  msgtype: MessageType;        // 消息类型
  content: string;             // 消息内容
}

// 应用机器人发送消息接口
interface YZJAppMessage {
  msgType: MessageType;        // 消息类型
  toOpenId: string;            // 接收者 OpenID
  content: string;             // 消息内容
}
```

#### 配置验证（src/config-schema.ts）

使用 JSON Schema 进行配置验证：

- 支持条件验证：有 `accounts` 时 `sendMsgUrl` 可选
- 默认值自动设置：`webhookPath`、`timeout`
- 类型安全：通过 TypeBox 进行运行时验证

#### 平台兼容（src/compat.ts）

`src/compat.ts` 统一导入 `openclaw/plugin-sdk` 类型，并在本地保留账户 ID 规范化、空配置 schema、setup wizard 兼容类型等运行时辅助逻辑，避免不同 OpenClaw 版本的 SDK 子路径变化影响插件加载。

### 限制说明

- 个人机器人模式需要有效的 `sendMsgUrl`
- 应用机器人模式需要有效的 `appId/appSecret`
- Webhook 需要可被云之家访问（公网或内网穿透）
- 文件、图片和 mp4 视频发送依赖应用机器人能力
- 个人机器人 `sendMsgUrl` 模式只支持文本，不支持上传文件、图片或视频
- 不支持流式响应（云之家 API 限制）
- 消息大小限制：1MB
- 主动发消息需要获取用户的 OpenID

## 与 WeCom 插件的对比

| 特性 | YZJ | WeCom |
|------|-----|-------|
| 消息加密 | 无 | AES 加密 |
| 签名验证 | HmacSHA1（可选） | Token 签名 |
| 主动发送 | ✅ 支持 | ❌ 仅回调回复 |
| 流式响应 | ❌ 不支持 | ✅ 支持 |
| Webhook 验证 | 无需验证 | 需验证签名 |
| 配置复杂度 | 简单 | 中等 |

## 项目元数据

**包信息**
- **包名**: yzj
- **版本**: 2026.4.9
- **描述**: OpenClaw YZJ (Yunzhijia) intelligent bot channel plugin
- **模块类型**: ESM
- **插件 ID**: yzj
- **通道标签**: YZJ Robot

**插件配置**
- OpenClaw 插件元数据: `openclaw.plugin.json`
- ClawDBot 插件元数据: `clawdbot.plugin.json`
- 文档路径: `/channels/yzj`
- 支持的扩展: `./dist/index.js`（由 `npm run build` 从 `index.ts` 编译生成）

**统计信息**
- 核心模块数: 20+ 个
- 支持的出站消息类型: 文本、文件、图片、mp4 视频、交互卡片 payload
- 平台兼容性: OpenClaw + ClawDBot

## 许可证

MIT

## 贡献

欢迎提交 Issue 和 Pull Request！

### 开发规范

1. **代码风格**: 遵循 TypeScript 最佳实践
2. **提交信息**: 使用清晰的提交描述
3. **测试**: 确保功能正常后再提交
4. **文档**: 更新相关文档和注释

## 相关链接

- [云之家开放平台](https://open.yunzhijia.com/)
- [OpenClaw 文档](https://docs.openclaw.dev/)
- [ClawDBot 文档](https://docs.clawdbot.dev/)
