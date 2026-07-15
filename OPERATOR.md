# Firefox VPN Client Operator Notes

这里记录的是维护、部署和排障步骤；只建议在你自己的授权账号和机器上使用。

## 基本能力

- 登录 Firefox Account，获取 OAuth token 和 Guardian proxy pass。
- 本地暴露 SOCKS5 CONNECT 代理。
- 上游使用 HTTP/2 或 HTTP/3 CONNECT session；高并发时可开启上游 session 池。
- proxy pass 后台续期时优先原地更新 session token，避免周期性更换出口；session 确认损坏时才重建并重试。
- Linux 可通过 systemd 常驻运行，附带健康检查和自动重启。

## 手动运行

先在本机登录一次，token 会写到当前用户 home 目录：

```bash
go run ./cmd/proxy-demo -login -print-info
```

启动本地 SOCKS5：

```bash
go run ./cmd/proxy-demo -listen 127.0.0.1:1088
```

常用参数：

```bash
-proxy HOST:PORT              # 指定出口 proxy；systemd 未指定时会持久化首次成功选择
-proxy-state-file PATH        # 保存自动选择的 proxy，重启后优先复用
-h3                           # 使用 HTTP/3/QUIC
-timeout 20s                  # 上游拨号、握手、CONNECT 打开阶段超时
-handshake-timeout 10s        # 客户端 SOCKS5 握手超时
-idle-timeout 0               # 已建立隧道的空闲超时，0 表示关闭限制
-max-conns 256                # 最大并发客户端连接数，0 表示关闭限制
-upstream-conns 1             # 上游 proxy session 数量；单用户/sing-box 建议保持 1
-status-file PATH             # 写入运行状态，systemd 健康检查用来判断 proxy pass 是否过期
-verbose                      # 打印完整 CONNECT 目标，默认会打码
```

启动后日志会打印当前出口和本机到出口的建连延迟：

```text
INFO  exit selected country="Japan" country_code=JP city="Tokyo" city_code=tyo proxy=jp.example:443 local_to_exit_latency=183ms
```

`local_to_exit_latency` 是建立上游 HTTP/2/TLS 或 HTTP/3/QUIC session 的耗时，不是 ICMP ping。

## 出口延迟与 Fastly 内部路径

如果 VPS 到 Fastly 入口很近，但 `local_to_exit_latency` 或经代理访问目标的延迟明显偏高，问题可能在 Fastly 内部路径，而不在 VPS 机房出口。

典型现象：

```text
VPS -> 本地交换中心/Fastly 入口: <1ms
Fastly 内部静默跳点
到 MASQUE/CONNECT 终端: 100ms+
```

这表示流量很快进入了 Fastly 网络，但 Fastly 可能把 Firefox VPN 的 CONNECT/MASQUE 流量转发到某个远端 gateway 再出网。这个 gateway 不一定和 VPS 所在城市相同，也不一定是最近的普通 CDN 边缘节点。

排查建议：

- 不要只看 `mtr` 中间跳；Fastly 内部跳点可能静默，ICMP 也不等同于 CONNECT/MASQUE 实际路径。
- 以程序日志里的 `local_to_exit_latency`、经 SOCKS 访问目标站的 RTT、下载速度作为主要判断依据。
- `PROXY=` 为空时首次启动会随机选择 CONNECT server；systemd 会保存到 `PROXY_STATE_FILE`，后续重启优先复用同一节点。持久化节点连续 3 次启动失败后才会清除并重新选择，避免一次临时丢包触发出口漂移。
- 需要稳定出口时，优先固定一个实测延迟低的 `PROXY=HOST:PORT`。
- 如果同一国家的多个节点全部高延迟，通常是 Fastly 对当前 VPS 线路的内部调度问题，客户端侧很难强制它落到本地 gateway。

## systemd 部署

脚本位置：

```bash
scripts/install-systemd.sh
```

推荐第一次部署：

```bash
sudo LISTEN=127.0.0.1:1088 ./scripts/install-systemd.sh install-login
```

这会：

- 构建二进制到 `/usr/local/bin/firefox-vpn-proxy`
- 创建系统用户 `firefox-vpn`
- 保存 token 到 `/var/lib/firefox-vpn-client/.firefox-vpn-tokens.json`
- 安装 `firefox-vpn-client.service`
- 安装 `firefox-vpn-client-health.timer`
- 健康检查失败时自动重启服务

常用管理命令：

```bash
sudo ./scripts/install-systemd.sh status
sudo ./scripts/install-systemd.sh health
sudo ./scripts/install-systemd.sh restart
sudo journalctl -u firefox-vpn-client.service -f
sudo journalctl -u firefox-vpn-client-health.service -n 50 --no-pager
```

修改配置：

```bash
sudoedit /etc/default/firefox-vpn-client
sudo systemctl restart firefox-vpn-client.service
```

可用环境变量：

```bash
LISTEN=127.0.0.1:1088
PROXY=
PROXY_STATE_FILE=/var/lib/firefox-vpn-client/proxy-selection.json
TIMEOUT=20s
HANDSHAKE_TIMEOUT=10s
IDLE_TIMEOUT=0
MAX_CONNS=256
UPSTREAM_CONNS=1
USE_H3=0
VERBOSE=0
HEALTH_INTERVAL=30s
HEALTH_TIMEOUT=5
HEALTH_VERBOSE=0
HEALTH_TARGET=
HEALTH_TARGETS=www.google.com:443,example.com:443
HEALTH_FAILURE_THRESHOLD=3
HEALTH_FAILURE_STATE=/var/lib/firefox-vpn-client/health-failures
HEALTH_STATUS_GRACE=30
STATUS_FILE=/var/lib/firefox-vpn-client/status.json
EXTRA_ARGS=
```

## 性能调优

默认配置偏保守，适合单用户或低并发。作为 sing-box 出口或多客户端共享时，可以先从下面的配置开始：

```bash
MAX_CONNS=1024
UPSTREAM_CONNS=1
IDLE_TIMEOUT=5m
VERBOSE=0
```

调优建议：

- `UPSTREAM_CONNS` 大于 1 时，SOCKS5 服务会按客户端 IP 把连接粘滞到一个上游 session，同一客户端不会逐请求轮询出口；session 失败时才切换到其他 session。
- 对单个 sing-box 或单个浏览器，多个上游 session 不会叠加带宽，而且 Fastly 仍可能在出口侧改变地址族或出口 IP，因此默认建议 `UPSTREAM_CONNS=1`。只有多个独立客户端 IP 共享服务，或确实需要故障冗余时，才考虑设为 2-4。
- `MAX_CONNS` 需要小于系统文件句柄上限；systemd unit 默认设置 `LimitNOFILE=65535`。
- `IDLE_TIMEOUT=5m` 会清理长时间无流量的已建立隧道，避免客户端或 sing-box 遗留连接占满并发槽；默认 `0` 更适合 SSH、WebSocket 等长连接。
- `VERBOSE=1` 会增加日志 IO 和锁竞争，只建议临时排障开启。
- 性能差时优先固定实测低延迟的 `PROXY=`；未固定时会复用 `PROXY_STATE_FILE` 中上次成功的自动选择。

## 稳定性策略

- proxy pass 正常续期只更新现有 H2/H3 session 的 bearer token，不会周期性重建连接池；只有 session 已过期、认证失败或确认损坏时才换 session。
- H2 空闲 30 秒会发送 PING，15 秒未收到响应会关闭半开连接。
- 同一个目标反复 502/超时不会触发换出口；同一 session 上至少 3 个不同目标连续失败才判定为 session 级故障。
- 双向转发发生异常错误时会立即关闭两端；正常半关闭最多排空 2 分钟，防止连接和 `MAX_CONNS` 槽位永久泄漏。
- systemd 自动选点会持久化；节点连续 3 次启动失败后才重新选择。

## 升级

拉取新代码后重新安装即可。token 和 `/etc/default/firefox-vpn-client` 里的现有配置默认保留；如果执行安装命令时显式传入同名环境变量，则以本次传入值为准。

```bash
git pull
sudo ./scripts/install-systemd.sh install
sudo systemctl restart firefox-vpn-client.service
```

如果 token 失效：

```bash
sudo ./scripts/install-systemd.sh login
```

## 健康检查

timer 默认每 30 秒运行一次。

检查逻辑：

1. 确认 `firefox-vpn-client.service` 处于 active。
2. 如果有 `python3`，读取 `STATUS_FILE`，确认当前 proxy pass 没有超过 `proxy_pass_expires_at + HEALTH_STATUS_GRACE`。
3. 连接 `LISTEN` 地址。
4. 如果有 `python3`，执行 SOCKS5 greeting，并通过代理 CONNECT 到 `HEALTH_TARGETS` 里的每个目标；443 域名还会完成 TLS 握手和轻量 HTTP 数据探测。
5. 没有 `python3` 时退化为本地 TCP 端口检查，不验证 proxy pass 过期和上游出口。
6. 单个目标失败只记录告警；所有目标连续失败 `HEALTH_FAILURE_THRESHOLD` 次才重启服务。
7. 重启前会清除 systemd start-limit 计数，避免控制面临时故障后服务长期停留在 failed 状态。

`HEALTH_TARGET` 是旧的单目标配置；如果设置了 `HEALTH_TARGETS`，优先使用 `HEALTH_TARGETS`。建议保留至少两个相互独立的稳定目标，避免把单站点故障误判成整个代理失效。

如果主服务处于 `inactive`，健康检查会认为它是被手动停止的，不会通过 timer 重新拉起。

默认健康成功不会刷日志；需要成功日志时设置：

```bash
HEALTH_VERBOSE=1
```

## 日志约定

运行期日志格式：

```text
2026-07-02T12:00:00+08:00 INFO  message
```

默认不会打印 CONNECT 目标域名，日志里显示：

```text
target=<redacted; use -verbose>
```

只有排障时才建议开启 `VERBOSE=1` 或 `-verbose`，因为这会把访问目标写入日志。

## 常见故障

`guardian returned HTTP 403`

程序会尝试自动激活 Guardian；如果仍失败，先确认账号在 Firefox 浏览器内的 VPN 能正常开启。

`no refresh token available for background renewal`

服务用户没有 token，或 token 文件不在服务用户 HOME。systemd 默认 HOME 是：

```text
/var/lib/firefox-vpn-client
```

重新登录：

```bash
sudo ./scripts/install-systemd.sh login
```

出口国家显示 `unknown`

通常是手动 `-proxy` 指定了不在 server list 里的 host，或者拉取 server list 失败。代理仍可运行，只是无法标注国家/城市。

出口延迟异常高

如果 `mtr` 显示 VPS 到本地 Fastly 入口很低，但最终到 `*.m1.fastly-masque.net` 或出口路径突然增加 100ms 以上，通常是 Fastly 内部把 CONNECT/MASQUE 流量转到了远端 gateway。优先处理：

- 用 `-print-info` 查看可用节点。
- 手动指定多个同区域节点测试。
- 把最低延迟的节点写入 `/etc/default/firefox-vpn-client` 的 `PROXY=`。
- 重启服务后确认日志里的 `exit selected ... proxy=... local_to_exit_latency=...`。

服务启动后立即重启

查看日志：

```bash
sudo journalctl -u firefox-vpn-client.service -n 100 --no-pager
```

优先检查：

- `/etc/default/firefox-vpn-client`
- `/var/lib/firefox-vpn-client/.firefox-vpn-tokens.json`
- `LISTEN` 端口是否被占用
- `PROXY` 是否可达

## 卸载

保留 token/state：

```bash
sudo ./scripts/install-systemd.sh uninstall
```

同时删除 state 和服务用户：

```bash
sudo PURGE=1 ./scripts/install-systemd.sh uninstall
```

## 注意事项

- 不要把监听地址暴露到公网；默认使用 `127.0.0.1`。
- token 文件等同长期登录凭据，权限应保持 `0600`。
- `-verbose` 会暴露访问目标，生产环境谨慎开启。
- 这个项目依赖 Mozilla 相关接口行为，接口或服务策略变化时可能需要跟进修复。
