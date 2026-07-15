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
go run ./cmd/proxy-demo -country US -listen 127.0.0.1:1088
```

首次选点必须明确指定 `-country` 或 `-proxy`。程序不会再从全球节点中随机选择国家；选定结果写入 `-proxy-state-file` 后，后续启动会优先复用该 hostname。

常用参数：

```bash
-country US                   # 按 Mozilla server list 的国家代码或名称选择位置
-proxy HOST:PORT              # 精确指定上游 proxy；与 -country 互斥
-proxy-state-file PATH        # 保存选择的 proxy hostname，重启后优先复用
-verify-exit=true             # 通过代理验证实际公网出口 IP/国家；失败不影响服务
-exit-check-timeout 10s       # 出口数据面探测超时
-h3                           # 使用 HTTP/3/QUIC
-timeout 20s                  # 上游拨号、握手、CONNECT 打开阶段超时
-handshake-timeout 10s        # 客户端 SOCKS5 握手超时
-idle-timeout 0               # 已建立隧道的空闲超时，0 表示关闭限制
-max-conns 256                # 最大并发客户端连接数，0 表示关闭限制
-upstream-conns 1             # 上游 proxy session 数量；单用户/sing-box 建议保持 1
-status-file PATH             # 写入运行状态，systemd 健康检查用来判断 proxy pass 是否过期
-verbose                      # 打印完整 CONNECT 目标，默认会打码
```

启动后会分别记录配置位置、上游 session 建连耗时和真实出口探测：

```text
INFO  upstream selected configured_country="Japan" configured_country_code=JP configured_city="Japan" configured_city_code=RJTF proxy=rjtf770.m1.fastly-masque.net:2499 selection_source=configured_country upstream_session_establish_latency=183ms
INFO  exit verified ip=203.0.113.10 country_code=JP data_path_probe_latency=241ms probe_host=www.cloudflare.com
```

`configured_country` 来自 Mozilla server list，只表示请求选择的位置。`upstream_session_establish_latency` 是建立上游 HTTP/2/TLS 或 HTTP/3/QUIC session 的耗时。`exit verified` 才是数据面实际看到的公网出口；`data_path_probe_latency` 包含经 VPN 出口访问探测站点的完整耗时，不等于 ICMP ping 或到某台 gateway 的纯 RTT。

## Fastly POP、配置位置与实际出口

这三个概念不能混为一谈：

- Mozilla server list 中选择的 VPN 国家和 hostname。
- 流量进入 Fastly 网络时使用的 POP、site 和网络路径。
- CONNECT/MASQUE 数据面最终使用的公网出口 IP。

Fastly 的[官方 POP 文档](https://www.fastly.com/documentation/guides/getting-started/concepts/using-fastlys-global-pop-network/)说明，普通 Fastly 服务通常会把流量送到网络距离最近的 POP；一个 POP 可能包含多个物理 site，故障时路由也可能改变。该文档描述的是 Fastly 通用 CDN/反向代理模型，并没有确认 Mozilla MASQUE 使用集中式 gateway、标准 clustering 或 shielding。

例如 `lfpb115.m1.fastly-masque.net` 中的 `LFPB115` 被 Fastly 官方列表列为 Paris metro POP 的一个物理 site。美国 VPS 选择法国位置后出现约 100ms 以上延迟，首先应解释为选择了远端服务位置，而不是直接断言 Fastly 在本地入口后又绕到集中式 gateway。

排查建议：

- 不要用 `mtr` 某两个 hop 的 RTT 差值直接推导 Fastly 内部增加了多少延迟；ICMP 限速、隐藏 hop 和回程不对称都会干扰结果。
- 优先比较 `upstream_session_establish_latency`、`data_path_probe_latency`、经 SOCKS 访问多个目标的耗时和下载速度。
- `PROXY_STATE_FILE` 只固定 hostname 和位置元数据，不能保证固定 Fastly 机器、物理 site、网络路径或公网出口 IP。
- 需要稳定位置时设置 `COUNTRY=US` 等明确国家；需要固定精确 hostname 时设置 `PROXY=HOST:PORT`。
- 只有在同一配置位置、多个 hostname、多个目标和多个时间段都复现异常后，才把 Fastly 内部路径或服务端 gateway 调度列为可能原因。

## systemd 部署

脚本位置：

```bash
scripts/install-systemd.sh
```

推荐第一次部署：

```bash
sudo COUNTRY=US LISTEN=127.0.0.1:1088 ./scripts/install-systemd.sh install-login
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
COUNTRY=US
PROXY_STATE_FILE=/var/lib/firefox-vpn-client/proxy-selection.json
TIMEOUT=20s
HANDSHAKE_TIMEOUT=10s
IDLE_TIMEOUT=0
MAX_CONNS=256
UPSTREAM_CONNS=1
USE_H3=0
VERIFY_EXIT=1
EXIT_CHECK_URL=https://www.cloudflare.com/cdn-cgi/trace
EXIT_CHECK_TIMEOUT=10s
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
- 性能差时先确认 `COUNTRY` 是预期位置，再比较同一国家的 hostname；需要精确复用时设置 `PROXY=`。`PROXY_STATE_FILE` 只能提供 hostname 级别的尽力复用。

## 稳定性策略

- proxy pass 正常续期只更新现有 H2/H3 session 的 bearer token，不会周期性重建连接池；只有 session 已过期、认证失败或确认损坏时才换 session。
- H2 空闲 30 秒会发送 PING，15 秒未收到响应会关闭半开连接。
- 同一个目标反复 502/超时不会触发换出口；同一 session 上至少 3 个不同目标连续失败才判定为 session 级故障。
- 双向转发发生异常错误时会立即关闭两端；正常半关闭最多排空 2 分钟，防止连接和 `MAX_CONNS` 槽位永久泄漏。
- systemd 会持久化选中的 hostname；连续 3 次启动失败后才清除选择并按 `COUNTRY` 重新选择，但这不承诺固定物理节点或公网出口 IP。

## 升级

拉取新代码后重新安装即可。token 和 `/etc/default/firefox-vpn-client` 里的现有配置默认保留；如果执行安装命令时显式传入同名环境变量，则以本次传入值为准。

旧版本已经生成 `PROXY_STATE_FILE` 时可以继续启动，但建议尽快在环境文件中补上明确的 `COUNTRY`。如果旧的持久化选择连续启动失败并被清除，没有 `COUNTRY` 的新版本会拒绝重新随机选择全球节点。

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

`selecting proxy failed: multiple VPN countries are available`

首次启动没有配置位置。手动运行时加 `-country US`，systemd 则在 `/etc/default/firefox-vpn-client` 设置 `COUNTRY=US`。也可以用 `PROXY=HOST:PORT` 精确指定 hostname。

配置位置显示 `unknown`

通常是手动 `-proxy` 指定了不在 Mozilla server list 里的 host，或者启动时无法获取位置元数据。代理仍可运行；以 `exit verified` 的实际探测结果为准。

`exit verification failed`

出口验证是非致命探测，不会阻止 SOCKS5 服务启动。先检查目标站是否可达；如果不希望依赖外部探测，设置 `VERIFY_EXIT=0`。关闭后程序只会报告配置位置和上游 session 建连耗时，不会声称已经确认实际出口。

出口延迟异常高

如果 `*.m1.fastly-masque.net` 建连或数据面探测增加 100ms 以上，先确认没有选择远离 VPS 的配置国家。仅凭 `mtr` 不能证明 Fastly 使用集中式 MASQUE gateway。优先处理：

- 用 `-print-info` 查看可用节点。
- 检查 `COUNTRY`、`configured_country_code` 和 `exit verified country_code` 是否一致。
- 手动指定同一国家的多个 hostname 测试。
- 把最低延迟的节点写入 `/etc/default/firefox-vpn-client` 的 `PROXY=`。
- 重启服务后同时比较 `upstream_session_establish_latency` 和 `data_path_probe_latency`。

服务启动后立即重启

查看日志：

```bash
sudo journalctl -u firefox-vpn-client.service -n 100 --no-pager
```

优先检查：

- `/etc/default/firefox-vpn-client`
- `/var/lib/firefox-vpn-client/.firefox-vpn-tokens.json`
- `LISTEN` 端口是否被占用
- `COUNTRY` 或 `PROXY` 是否已配置
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
