# 知识库、文档与文档块

以下写操作会真实创建、修改、移动或删除数据，执行前先确认。

写操作确认顺序：

1. `contact user get` 检查通过。未登录时先执行设备码登录，发出登录地址和授权码后等待用户下一条消息提醒，不在同一轮里继续写操作。
2. 给用户展示操作摘要。
3. 用户明确确认。
4. 执行对应 `doc ...` 命令。

## 知识库

| 能力 | 命令 | 说明 |
|---|---|---|
| 列出知识库 | `doc workspace list` | 列出当前登录可访问的知识库。 |
| 获取知识库详情 | `doc workspace get --id <WORKSPACE_ID>` | 按知识库 ID 查询。 |
| 创建知识库 | `doc workspace create --name <NAME>` | 有副作用；可选 `--description`。 |

命令：

```cmd
yzj-cli --endpoint <ENDPOINT> doc workspace list
yzj-cli --endpoint <ENDPOINT> doc workspace get --id <WORKSPACE_ID>
yzj-cli --endpoint <ENDPOINT> doc workspace create --name "CLI测试知识库" --description "CLI test"
```

## 文档节点

| 能力 | 命令 | 说明 |
|---|---|---|
| 列出文档 | `doc list --workspace <WORKSPACE_ID>` | 支持分页。 |
| 获取文档详情 | `doc info --id <DOC_ID>` | 按文档 ID 查询。 |
| 创建文档 | `doc create --workspace <WORKSPACE_ID> --title <TITLE> --file-suffix <SUFFIX>` | 有副作用；当前代码只定义创建文档文件。 |
| 重命名文档/目录 | `doc rename --id <DOC_ID> --title <TITLE>` | 有副作用。 |
| 移动文档/目录 | `doc move --id <DOC_ID> --target-parent-id <PARENT_ID>` | 有副作用；省略目标父节点表示移动到根级。 |
| 删除文档/目录 | `doc delete --id <DOC_ID>` | 高风险；删除节点。 |

命令：

```cmd
yzj-cli --endpoint <ENDPOINT> doc list --workspace <WORKSPACE_ID> --page 1 --page-size 20
yzj-cli --endpoint <ENDPOINT> doc info --id <DOC_ID>
yzj-cli --endpoint <ENDPOINT> doc create --workspace <WORKSPACE_ID> --title "CLI测试文档" --file-suffix otl
yzj-cli --endpoint <ENDPOINT> doc create --workspace <WORKSPACE_ID> --title "CLI测试多维表格" --file-suffix dbt
yzj-cli --endpoint <ENDPOINT> doc create --workspace <WORKSPACE_ID> --title "CLI测试文档" --parent-id <PARENT_ID> --file-suffix otl
yzj-cli --endpoint <ENDPOINT> doc rename --id <DOC_ID> --title "CLI测试文档-已重命名"
yzj-cli --endpoint <ENDPOINT> doc move --id <DOC_ID> --target-parent-id <TARGET_PARENT_ID>
yzj-cli --endpoint <ENDPOINT> doc move --id <DOC_ID>
yzj-cli --endpoint <ENDPOINT> doc delete --id <DOC_ID>
```

## 文档块

| 能力 | 命令 | 说明 |
|---|---|---|
| 查询文档块 | `doc block list --id <DOC_ID>` | 可选 `--block-id`，默认文档根块。 |
| 插入文档块 | `doc block insert --id <DOC_ID> --element <JSON_ARRAY>` | 有副作用；可选父块和位置。 |
| 批量更新文档块 | `doc block update --id <DOC_ID> --operations <JSON_ARRAY>` | 有副作用。 |
| 批量删除文档块 | `doc block delete --id <DOC_ID> --delete-ops <JSON_ARRAY>` | 高风险。 |

命令：

```cmd
yzj-cli --endpoint <ENDPOINT> doc block list --id <DOC_ID>
yzj-cli --endpoint <ENDPOINT> doc block list --id <DOC_ID> --block-id <BLOCK_ID>
yzj-cli --endpoint <ENDPOINT> doc block insert --id <DOC_ID> --element "[{\"type\":\"text\",\"text\":\"CLI测试内容\"}]"
yzj-cli --endpoint <ENDPOINT> doc block insert --id <DOC_ID> --block-id <BLOCK_ID> --index 0 --element "[{\"type\":\"text\",\"text\":\"CLI测试内容\"}]"
yzj-cli --endpoint <ENDPOINT> doc block update --id <DOC_ID> --operations "[{\"blockId\":\"<BLOCK_ID>\",\"type\":\"text\",\"text\":\"CLI更新内容\"}]"
yzj-cli --endpoint <ENDPOINT> doc block delete --id <DOC_ID> --delete-ops "[{\"blockId\":\"<BLOCK_ID>\"}]"
```
