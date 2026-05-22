# 全局命令与执行流程

## 全局命令格式

安装检查：

```cmd
where yzj-cli
npm install -g @yunzhijia/cli --registry=http://npm.yzjop.com
```

只有 `where yzj-cli` 找不到命令时才执行安装。安装后再执行 `yzj-cli --version` 或 `yzj-cli --help` 确认可用。

```cmd
yzj-cli --endpoint <ENDPOINT> <PRODUCT> <RESOURCE> <ACTION> [flags]
```

全局 flags：

| Flag | 说明 |
|---|---|
| `--endpoint <ENDPOINT>` | 显式传；默认用 `https://yunzhijia.com`，用户指定则用用户指定值 |
| `--verbose` | 报错后重试时使用，输出更多诊断信息 |
| `--debug` | 需要调试底层日志时使用 |

示例：

```cmd
yzj-cli --endpoint https://yunzhijia.com contact user search --keyword "张三"
yzj-cli --endpoint https://dev.kdweibo.cn contact user search --keyword "张三"
```

## 执行流程

1. 先确定 endpoint：用户指定则用用户指定值，未指定则用 `https://yunzhijia.com`。
2. 先执行 `where yzj-cli`；如果未安装，执行 `npm install -g @yunzhijia/cli --registry=http://npm.yzjop.com`。
3. 所有业务命令都显式带 `--endpoint <ENDPOINT>`。
4. 命令里不要加本地配置名参数。
5. 所有 CLI 业务操作都按用户身份执行；执行前先用 `contact user get` 检查当前用户登录态。
6. 检查失败、认证失败、token 过期、没有凭据或没有用户信息时，执行 `auth login --device` 获取登录地址和授权码，发给用户，并要求用户授权完成后再次发消息提醒。
7. 未登录时统一走设备码登录；拿到登录地址后本轮结束，不在同一轮里等待授权完成或继续原业务命令。
8. 操作前用 `yzj-cli --help` 或子命令 `--help` 核对参数。
9. 读操作直接执行；写/删/移动/取消/更新先确认。
10. 输出结果时保留关键 ID、名称、状态；隐藏 token 和 secret。

如果目标命令是 `doc ...`，先执行 `where yzj-cli` 和 `yzj-cli --endpoint <ENDPOINT> contact user get`。检查返回当前授权人信息后，再继续原 `doc ...` 操作；检查失败时先走设备码登录流程，发出登录地址和授权码后等待用户下一条消息提醒。

## 危险操作确认

执行以下命令前先确认：

| 命令 | 风险 |
|---|---|
| `calendar event create/update/delete` | 创建、修改或取消真实日程/会议日程 |
| `doc workspace create` | 创建真实知识库 |
| `doc create/rename/move/delete` | 创建、改名、移动或删除真实文档节点 |
| `doc block insert/update/delete` | 修改真实文档内容 |
| `update` / `update --force` | 替换本机 CLI 版本 |

确认口径：

```text
准备执行：
命令：
影响：
是否确认继续？
```
