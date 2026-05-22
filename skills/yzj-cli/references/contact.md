# 通讯录

## 命令表

| 能力 | 命令 | 说明 |
|---|---|---|
| 搜索用户 | `contact user search --keyword <KEYWORD>` | 搜索员工/同事。 |
| 按部门范围搜索用户 | `contact user search --keyword <KEYWORD> --org-id <ORG_ID>` | `--org-id` 只是限定搜索范围，不是搜索部门。 |
| 按 openId 获取用户 | `contact user get --open-id <OPEN_ID>` | `--open-id` 可重复传多个。 |
| 获取当前授权人 | `contact user get` | 用于检查当前用户登录态。 |

`contact user get` 不传 `--open-id` 用于证明当前是用户授权。命令失败时，按用户登录检查流程处理，先走 `auth login --device` 获取登录地址和授权码；发给用户后等待用户下一条消息提醒。

## 命令示例

```cmd
yzj-cli --endpoint <ENDPOINT> contact user search --keyword "<KEYWORD>"
yzj-cli --endpoint <ENDPOINT> contact user search --keyword "<KEYWORD>" --org-id <ORG_ID>
yzj-cli --endpoint <ENDPOINT> contact user get --open-id <OPEN_ID>
yzj-cli --endpoint <ENDPOINT> contact user get --open-id <OPEN_ID_1> --open-id <OPEN_ID_2>
yzj-cli --endpoint <ENDPOINT> contact user get
```

当前未看到独立的组织/部门搜索、组织列表、组织详情命令。
