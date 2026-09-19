# TrustedBridgeAuth

用于 PKUMC 与 THUnion 之间的跨服身份验证。玩家绑定正版账号后，可以在两服之间跳转：进入 THUnion 使用正版身份，返回 PKUMC 使用原角色。

需要 Minecraft 1.20.5+ 客户端。插件适配 Velocity 4.2.1-b31；THUnion 保持正版认证，PKUMC 需配套皮肤站绑定 API。

## 玩家使用

在 PKUMC 皮肤站提交正版名，用正版客户端连接 PKUMC，再将游戏中显示的验证码填回皮肤站。绑定完成后即可跨服，目标服务器的白名单等准入规则照常生效。

## 配置与部署

两端安装相同版本的插件，将对应示例放到 `plugins/trusted-bridge-auth/config.properties`：

| 服务端 | 配置示例 | 身份模式 |
| --- | --- | --- |
| PKUMC | [连接端配置](examples/pkumc/config.properties) | `local`，使用皮肤站角色 |
| THUnion | [监听端配置](examples/thunion/config.properties) | `premium`，使用正版身份 |

按实际部署修改地址：`bridge-host` 是 THUnion 的桥接地址，`transfer-host` 和 `transfer-port` 是玩家可访问的**对方服务器**地址与端口。

1. 运行 `python3 provision-tls.py keys`，将生成的 `keys/pkumc`、`keys/thunion` 分别放到对应端的 `plugins/trusted-bridge-auth/tls`。
2. 两端 Velocity 根目录放置相同的 `trusted-bridge.secret`，内容为随机生成的 64 位十六进制密钥。
3. PKUMC 配置皮肤站 API 地址，并将皮肤站的 `storage/app/trusted-bridge-api.secret` 放到插件目录，命名为 `skin-api.secret`。
4. 两端 Velocity 开启 `accepts-transfers`，在服务器列表中添加与 `peer-id` 同名的入口；玩家选择该入口时会跳转到对方服务器。
5. 确认桥接端口互通，重启两端 Velocity。

## 构建与测试

需要 Java 21+，通过 `VELOCITY_JAR` 指定 Velocity JAR 路径。

```sh
./build.sh
python3 integration-test.py
```

构建产物位于 `build/libs/`。
