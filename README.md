## 连接端配置

```properties
network-id=pkumc
peer-id=thunion
bridge-role=connect
bridge-host=bridge-b.example.com
bridge-port=27000
handoff-secret-file=trusted-bridge.secret
transfer-host=play-b.example.com
transfer-port=25565
handoff-ttl-seconds=30
timeout-millis=5000
identity-mode=local
skin-api-url=https://skin.chancelethay.top/api/trusted-bridge/
skin-api-secret-file=skin-api.secret
```

## 监听端配置

```properties
network-id=thunion
peer-id=pkumc
bridge-role=listen
bridge-listen-address=0.0.0.0
bridge-port=27000
handoff-secret-file=trusted-bridge.secret
transfer-host=play-a.example.com
transfer-port=25565
handoff-ttl-seconds=30
timeout-millis=5000
identity-mode=premium
```

## 身份验证

两端使用 TBL4 控制协议。PKUMC 使用 `local`，THUnion 使用 `premium`。
`source` 或静态 `mapped` 不提供正版绑定验证。
THUnion 的普通登录必须使用 Mojang 正版认证，不能把任意外置认证当作正版认证。

PKUMC 的原角色名和 UUID 保持不变。跨服票据包含客户端原登录名、本站 UUID、
正版 GameProfile 和绑定验证方式；THUnion 使用正版名字与 UUID。
返程会实时核验绑定，并恢复明确的原角色；无返程角色且存在多个角色时拒绝登录。
绑定验证方式支持 `legacy` 和 `login_code`。
这里证明的是已验证的账号绑定，不要求每次跨服都通过 Microsoft 登录。

`skin-api.secret` 是独立的 64 位十六进制密钥，仅 PKUMC 与皮肤站持有，
放在插件数据目录，权限 0600；对应皮肤站的 `storage/app/trusted-bridge-api.secret`。
API 只使用 HTTPS，不跟随重定向。THUnion 不需要也不应获取此密钥。
未绑定、解绑、封禁、身份服务不可用时拒绝跨服。

账号绑定：在皮肤站提交正版名，用该正版账号在 Minecraft 1.20.5+ 连接 PKUMC，
连接会在正版会话验证后结束并显示一次性验证码。回到已登录的皮肤站输入验证码
才会创建绑定。验证码为六位数字（可以以 0 开头），有效期 10 分钟、绑定申请有效期 15 分钟。
同一正版账号累计输错 5 次后锁定验证码，更换皮肤站账号或重新申请不能重置次数；
需要用正版客户端重新进服获取新码，新码会替换旧码。已完成的绑定不受影响。
未绑定、缺少角色、多个角色、账号不可用及身份服务故障会显示对应提示。
白名单由目标服务器检查，其拒绝提示不由本插件管理。

## 部署与验证

皮肤站运行 `install-premium.php` 初始化绑定数据表，并配置 API 密钥。
部署皮肤站文件后重启 PHP-FPM；两端安装插件 JAR 后重启 Velocity。
每端仅保留一个插件 JAR。

验证：`./build.sh`、`python3 integration-test.py`；皮肤站执行
`php plugins/yggdrasil-api/tests/premium-regression.php`（内存数据库、模拟 Mojang）。
