# 日程会议与会议室

当前 CLI 没有独立 `meeting` 命令。创建会议使用 `calendar event create` 创建日程/会议日程；如果用户要视频会议链接、会议号，当前代码未看到该能力。

日程/会议统一使用当前用户身份。执行前先用 `contact user get` 检查当前用户登录态；未登录时先执行设备码登录，发出登录地址和授权码后等待用户下一条消息提醒。

## 日程查询

| 能力 | 命令 | 说明 |
|---|---|---|
| 列出日程 | `calendar event list --start <START> --end <END>` | 时间支持日期、ISO-8601、Unix 秒/毫秒；超过 30 天自动分片。 |
| 获取日程详情 | `calendar event get --id <EVENT_ID>` | 按日程 ID 查询。 |
| 查看参与人 | `calendar event participants --id <EVENT_ID>` | 别名：`calendar event attendees`。 |

命令：

```cmd
yzj-cli --endpoint <ENDPOINT> calendar event list --start "2026-05-21" --end "2026-05-21"
yzj-cli --endpoint <ENDPOINT> calendar event list --start "2026-05-21T09:00:00+08:00" --end "2026-05-21T18:00:00+08:00"
yzj-cli --endpoint <ENDPOINT> calendar event get --id <EVENT_ID>
yzj-cli --endpoint <ENDPOINT> calendar event participants --id <EVENT_ID>
yzj-cli --endpoint <ENDPOINT> calendar event attendees --id <EVENT_ID>
```

## 日程创建、修改、取消

| 能力 | 命令 | 说明 |
|---|---|---|
| 创建日程/会议 | `calendar event create --title <TITLE> --start <START> --end <END> --meet-organizer-open-ids <OPEN_ID>` | 有副作用；会真实创建。 |
| 修改日程 | `calendar event update --id <EVENT_ID> [flags]` | 有副作用；只传需要修改的字段。 |
| 取消日程 | `calendar event delete --id <EVENT_ID>` | 有副作用；默认软取消。 |
| 彻底删除日程 | `calendar event delete --id <EVENT_ID> --hard` | 高风险；彻底删除。 |

创建支持参数：

| Flag | 说明 |
|---|---|
| `--title <TITLE>` | 必填，主题 |
| `--start <START>` | 必填，开始时间 |
| `--end <END>` | 必填，结束时间 |
| `--meet-organizer-open-ids <OPEN_ID>` | 必填，主持人 openId，可重复传多个 |
| `--attendee-open-ids <OPEN_ID>` | 参会人 openId，可重复传多个 |
| `--description <TEXT>` | 内容/描述 |
| `--room-id <ROOM_ID>` | 会议室 ID |
| `--calendar-id <CALENDAR_ID>` | 日历 ID，省略则使用主日历 |

修改支持参数：

| Flag | 说明 |
|---|---|
| `--id <EVENT_ID>` | 必填，日程 ID |
| `--title <TITLE>` | 新主题 |
| `--start <START>` | 新开始时间 |
| `--end <END>` | 新结束时间 |
| `--description <TEXT>` | 新内容/描述 |
| `--room-id <ROOM_ID>` | 会议室 ID |
| `--add-attendee-open-ids <OPEN_ID>` | 新增参会人，可重复传多个 |
| `--remove-attendee-open-ids <OPEN_ID>` | 移除参会人，可重复传多个 |
| `--calendar-id <CALENDAR_ID>` | 日历 ID |

命令：

```cmd
yzj-cli --endpoint <ENDPOINT> calendar event create --title "产品评审" --start "2026-05-21T09:00:00+08:00" --end "2026-05-21T10:00:00+08:00" --meet-organizer-open-ids <OPEN_ID> --attendee-open-ids <ATTENDEE_OPEN_ID>
yzj-cli --endpoint <ENDPOINT> calendar event create --title "产品评审" --start "2026-05-21T09:00:00+08:00" --end "2026-05-21T10:00:00+08:00" --meet-organizer-open-ids <OPEN_ID> --room-id <ROOM_ID>
yzj-cli --endpoint <ENDPOINT> calendar event update --id <EVENT_ID> --title "产品评审-已修改" --description "CLI update test"
yzj-cli --endpoint <ENDPOINT> calendar event update --id <EVENT_ID> --add-attendee-open-ids <OPEN_ID>
yzj-cli --endpoint <ENDPOINT> calendar event update --id <EVENT_ID> --remove-attendee-open-ids <OPEN_ID>
yzj-cli --endpoint <ENDPOINT> calendar event delete --id <EVENT_ID>
yzj-cli --endpoint <ENDPOINT> calendar event delete --id <EVENT_ID> --hard
```

## 会议室

| 能力 | 命令 | 说明 |
|---|---|---|
| 查询可用会议室 | `calendar room find --start <START> --end <END>` | 只查询空闲会议室，不预定。 |
| 查询可用会议室别名 | `calendar room search --start <START> --end <END>` | `search` 是 `find` 的别名。 |

命令：

```cmd
yzj-cli --endpoint <ENDPOINT> calendar room find --start "2026-05-21T09:00:00+08:00" --end "2026-05-21T18:00:00+08:00"
yzj-cli --endpoint <ENDPOINT> calendar room search --start "2026-05-21T09:00:00+08:00" --end "2026-05-21T18:00:00+08:00"
```
