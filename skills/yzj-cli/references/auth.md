# 用户登录与 Token 处理

## 登录方式

所有 `yzj-cli` 业务操作统一使用用户身份。登录、查询当前授权人、通讯录、日程、会议室、知识库、文档和文档块都按同一个用户登录态执行。

用户登录命令：

```cmd
yzj-cli --endpoint <ENDPOINT> auth login --device
```

退出登录：

```cmd
yzj-cli auth logout
```

登录信息保存在本机 `C:\Users\kingdee\.yzj-cli\config.json`。回复里不要输出 `accessToken`、`refreshToken` 明文。

## 用户登录检查

执行 CLI 业务操作前，先检查当前登录态：

```cmd
yzj-cli --endpoint <ENDPOINT> contact user get
```

处理规则：

- 如果检查命令返回当前授权人信息，说明已经登录，可以继续执行原业务命令。
- 如果检查命令返回错误、认证失败、token 过期、没有凭据或没有用户信息，说明当前没有可用用户登录态。
- 没有可用用户登录态时，执行设备码登录命令获取登录地址和授权码，发给用户，并要求用户完成授权后再次发消息提醒。
- `auth login --device` 会输出登录地址和授权码，并进入“等待用户授权中...”轮询状态；当前 OpenClaw 消息会话不能稳定依赖后台登录进程在同一轮内继续推进。
- 拿到登录地址后，本轮只回复登录地址和授权码；必须要求用户授权完成后再次发消息提醒。不要在同一轮里等待授权完成、后台轮询后继续业务，也不要承诺本轮会自动继续创建、修改或删除。
- 用户说“已授权”“已登录”或类似表达后，立即执行 `contact user get` 检查登录态；检查通过后继续原操作，检查失败再说明登录未完成。
- 不要为了等待 `auth login --device` 返回“授权成功”而阻塞当前会话；用户下一条消息提醒已授权后，再执行 `contact user get` 检查，检查通过后再继续原业务命令。
- 如果 `auth login --device` 返回“设备码已过期，请重试”，说明用户没有在有效期内完成授权。告诉用户授权码已过期，需要重新执行设备码登录；不要继续原业务命令。
- 如果 `auth login --device` 返回其他错误，保留关键错误信息，说明登录未完成；不要继续原业务命令。
- 判断用户是否真的登录，只看 `contact user get` 的结果。
- 不循环执行原业务命令；有副作用命令只在登录检查通过后执行一次。

## Token 过期处理

Token 刷新由 `yzj-cli` 代码处理，skill 只负责按流程调用 CLI。

| 场景 | 处理 |
|---|---|
| `token refresh failed` | 重新执行 `auth login --device`。 |
| `login session expired` | 重新执行 `auth login --device`。 |
| `no credentials found` | 执行 `auth login --device`。 |

重试时保持同一个 `--endpoint <ENDPOINT>`。
