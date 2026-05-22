# 错误处理

- `error decoding response body`：检查命令是否带了用户指定的 `--endpoint <ENDPOINT>`，确认没有走默认 `https://api.yunzhijia.com`。
- `no credentials found`：先执行对应 endpoint 的用户登录命令：`auth login --device`。
- `token refresh failed`：设备码登录的刷新失败，重新执行 `auth login --device`。
- `login session expired`：当前登录态已过期，重新执行 `auth login --device`。
- 用户登录检查失败：执行 `auth login --device` 获取登录地址和授权码，发给用户，并要求用户完成授权后再次发消息提醒；用户提醒后，再用 `contact user get` 检查登录态。
- `设备码已过期，请重试`：用户没有在有效期内完成授权。告诉用户授权码已过期，需要重新执行设备码登录；不要继续原业务命令。
- `10000401`、`10000404`、`1001001` 出现在知识库/文档链路时：按当前没有可用用户登录态处理，先走设备码登录流程。
- 重试保持同一个 `--endpoint <ENDPOINT>`。
