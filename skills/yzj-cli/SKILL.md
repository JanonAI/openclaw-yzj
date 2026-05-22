---
name: yzj-cli
description: "云之家 CLI（yzj-cli）操作技能。当用户需要使用 yzj-cli 登录、指定 endpoint、查通讯录、查/建日程会议、查会议室、操作知识库/文档/文档块、更新 CLI、排查 yzj-cli 报错，或在知识库/文档操作前检查用户授权时使用。"
metadata:
  requires:
    bins: ["yzj-cli"]
  cliHelp: "yzj-cli --help"
---

# 云之家 CLI

通过 `yzj-cli` 操作云之家环境。所有 CLI 操作统一按用户身份执行，优先使用 CLI 完成登录检查、通讯录、日程会议、知识库和文档等操作。

## 基本执行流程

用户要使用 `yzj-cli` 做云之家操作时，按下面顺序处理。

1. 先确认本机是否安装 CLI：

```cmd
where yzj-cli
```

如果找不到命令，再安装：

```cmd
npm install -g @yunzhijia/cli --registry=http://npm.yzjop.com
```

2. 确定 endpoint：

- 用户明确指定 endpoint 时，用用户指定的值。
- 用户没有指定 endpoint 时，默认用 `https://yunzhijia.com`。
- 命令里显式带 `--endpoint <ENDPOINT>`，并放在子命令前。

3. 在执行用户要做的 CLI 操作前，先检查当前是否已经登录：

```cmd
yzj-cli --endpoint <ENDPOINT> contact user get
```

4. 根据登录检查结果决定下一步：

- 如果 `contact user get` 返回当前授权人信息，说明已经登录，继续执行用户要做的 CLI 操作。
- 如果 `contact user get` 返回错误、认证失败、token 过期、没有凭据、没有用户信息，说明当前没有可用的用户登录态。执行 `yzj-cli --endpoint <ENDPOINT> auth login --device` 获取登录地址和授权码，发给用户，并要求用户完成授权后提醒。
- 如果任何业务命令返回 `no credentials found -- run 'yzj-cli auth login' first`，按未登录处理，执行 `yzj-cli --endpoint <ENDPOINT> auth login --device`，把 CLI 输出的登录地址和授权码发给用户，并要求用户完成授权后提醒。

设备码登录命令：

```cmd
yzj-cli --endpoint <ENDPOINT> auth login --device
```

执行设备码登录命令后，CLI 会输出登录地址和授权码，并进入“等待用户授权中...”轮询状态。拿到登录地址和授权码后，本轮只把它们发给用户。

当前 OpenClaw 消息会话不能稳定依赖后台登录进程在同一轮内继续推进。拿到登录地址后，必须回复用户完成授权后提醒；不要承诺本轮会自动继续创建、修改或删除。

用户主动说“已授权”“已登录”或类似表达后，立即执行 `contact user get` 检查登录态；检查通过后继续原操作，检查失败再说明登录未完成。

设备码登录后的恢复方式：

- 判断用户是否真的登录，只看 `contact user get` 的结果，不靠用户口头说已经登录。
- 不循环执行原业务命令，尤其是创建、删除、更新这类有副作用命令，避免重复创建或重复修改。
- 不要为了等待 `auth login --device` 返回“授权成功”而阻塞当前会话；用户下一条消息提醒已授权后，再执行 `contact user get`，通过后继续原操作。
- 如果 `auth login --device` 返回“设备码已过期，请重试”，告诉用户授权码已过期，需要重新执行设备码登录；不要继续原业务命令。
- 如果 `auth login --device` 返回其他错误，保留关键错误信息，说明登录未完成；不要继续原业务命令。

## 执行口径

- 执行任何业务命令前先确认本机有 `yzj-cli`；如果没有安装，执行 `npm install -g @yunzhijia/cli --registry=http://npm.yzjop.com`。
- 默认 endpoint：`https://yunzhijia.com`。用户指定其他 endpoint 时，按用户指定值执行。
- 每条业务命令显式带上 `--endpoint <ENDPOINT>`，且 `--endpoint` 放在子命令前：`yzj-cli --endpoint <ENDPOINT> <command>`。
- 命令里不额外加本地配置名参数，默认使用 CLI 的默认登录配置。
- 当前 CLI 链路优先使用用户指定 endpoint 或默认 `https://yunzhijia.com`，避免默认走 `https://api.yunzhijia.com` 导致非 JSON 404。
- 回复里隐藏 `accessToken`、`refreshToken` 等敏感信息；不要求用户提供应用凭据。
- 写入、移动、删除、取消日程、更新 CLI 等有副作用操作，先展示操作摘要并获得用户明确确认。
- 参数不确定时先跑 `yzj-cli <command> --help`，再选择参数。
- 普通业务命令报错时，可以用同一 endpoint 加 `--verbose` 重试一次，再给出完整错误和下一步。
- 如果是用户登录态问题，优先走 `contact user get` 和 `auth login --device` 的流程。

## 分文档索引

处理任务前先按任务类型读取对应分文档获取对应的CLI操作；不要只看主文档就执行或回复。

| 任务 | 分文档 |
|---|---|
| 全局命令格式、执行流程、危险操作确认 | `references/global.md` |
| 用户登录和 Token 过期处理 | `references/auth.md` |
| 搜索用户、按 openId 查用户、获取当前授权人 | `references/contact.md` |
| 日程会议、会议室 | `references/calendar.md` |
| 知识库、文档、文档块 | `references/doc.md` |
| 更新 CLI | `references/update.md` |
| 错误码和排障口径 | `references/errors.md` |

## 当前未实现或不应编造

- 当前未看到 `chat` / `im` 相关命令实现。
- 当前未看到独立的组织/部门搜索、组织列表、组织详情命令。
- 当前未看到独立的视频会议创建、会议链接、会议号创建命令。
- 当前命令定义里没有 `doc upload`、`doc download`，不要使用。
- 当前没有 `schema` 命令。
