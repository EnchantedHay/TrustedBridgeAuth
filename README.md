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
identity-mode=source
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
identity-mode=source
```
