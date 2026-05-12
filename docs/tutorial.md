# 公有云OpenClaw与云之家集成教程

## 1.购买云服务器

公有云这里以阿里云服务器为例。附：[阿里云-轻量云服务器购买地址](https://www.aliyun.com/benefit/scene/moltbot)

![image-20260308182754401](./imgs/image-20260308182754401.png)

## 2.部署最新版本OpenClaw

- 进入服务器实例

![image-20260308183452192](./imgs/image-20260308183452192.png)

- 重置系统-获取最新版本OpenClaw镜像

![image-20260308183615834](./imgs/image-20260308183615834.png)

- 确认重置 - 等待约1分钟后 - 重置成功

![image-20260308184217050](./imgs/image-20260308184217050.png)

依次点击【端口放通】-【配置OpenClaw】(配置LLM API Key) - 【公网访问】 - 【模型配置】- 【重启OpenClaw网关】- 【访问WebUI面板】可在公网访问OpenClaw的WebUI。

![image-20260308184842561](./imgs/image-20260308184842561.png)

- 打开WebUI - 聊天 - 能正常对话则代表OpenClaw部署成功。

![image-20260308184945740](./imgs/image-20260308184945740.png)

## 3.OpenClaw与云之家集成

> 当前插件同时支持 `webhook` 和 `websocket` 两种入站模式。个人机器人按原流程配置 `sendMsgUrl` 即可收发文本消息；如果额外配置应用机器人 `appId/appSecret`，还可以使用应用机器人长连接和媒体发送能力。

- 远程连接服务器终端

  ![image-20260308185708627](./imgs/image-20260308185708627.png)

- 下载openclaw-yzj-main.zip安装包

  > 有时在服务器上wget网络超时，可直接本地下载，再手动上传到服务器。

  ![image-20260308190236707](./imgs/image-20260308190236707.png)

- 安装openclaw-yzj-main.zip

  ![image-20260308190548667](./imgs/image-20260308190548667.png)

  > :star:要注意这一步安装是否成功，如果报错如图，则需要手动更新插件依赖，否则后续无法配置yzj插件。​
  >
  > ```shell
  > #进入报错目录
  > cd /home/admin/.openclaw/extensions/yzj/
  > #更新依赖(阿里云服务器上pnpm比npm更好使)
  > pnpm install
  > ```
  >
  > ![image-20260308190910292](./imgs/image-20260308190910292.png)
  >
  > 依赖安装成功后，重启openclaw gateway
  >
  > ```shell
  > #重启openclaw gateway
  > openclaw gateway restart
  > #检查yzj插件安装是否成功
  > openclaw plugins list
  > ```
  >
  > ![image-20260308191158409](./imgs/image-20260308191158409.png)

- 配置yzj插件

  > 若openclaw plugins list中的YZJ是error状态时，WebUI中是不会出现YZJ Robot的。

  ![image-20260308191253884](./imgs/image-20260308191253884.png)

  ![image-20260308192706923](./imgs/image-20260308192706923.png)

  > 可以按需选择：
  >
  > - `inboundMode: webhook`：仅通过 `webhookPath` 接收入站消息
  > - `inboundMode: websocket`：个人机器人会从 `sendMsgUrl` 推导 WebSocket 地址建立长连接，同时保留 `webhookPath` 作为兜底入口；应用机器人会使用 `appId/appSecret` 建立长连接

- Save - OpenClaw Gateway会自动重启，待重启成功后

```shell
#浏览器访问以下地址，如果显示【OK】则可以去云之家群组创建【对话型机器】人了
http://${你的OpenClaw WebUI公网IP及端口}/yzj/webhook
```

![image-20260308192813777](./imgs/image-20260308192813777.png)

- 创建【对话型机器人】

    <img src="./imgs/image-20260308194537071.png" alt="image-20260308194537071" style="zoom:50%;" />

  > 消息接收地址：填写`http://${你的OpenClaw WebUI公网IP及端口}/yzj/webhook`，这时就能创建成功了。

   <img src="./imgs/image-20260308194615935.png" alt="image-20260308194615935" style="zoom:50%;" />

   <img src="./imgs/image-20260308194757828.png" alt="image-20260308194757828" style="zoom:50%;" />

- 机器人创建成功后，将发送消息接口地址回填至 OpenClaw YZJ 插件中的 `sendMsgUrl`，否则机器人不会回复你的消息。

    <img src="./imgs/image-20260308194953809.png" alt="image-20260308195140392" style="zoom:50%;" />

​	复制发送消息接口地址回填到 `sendMsgUrl` 中，就配置完成了。

  > 如果你使用应用机器人，还可以额外填写 `appId` 和 `appSecret`，并选择 `websocket` 入站模式。应用机器人支持文本、文件、图片和 mp4 视频发送。

![image-20260308195239741](./imgs/image-20260308195239741.png)

## 4.云之家群聊测试

![image-20260308195646381](./imgs/image-20260308195646381.png)

到这里，公有云 OpenClaw 与云之家集成就完成了。
