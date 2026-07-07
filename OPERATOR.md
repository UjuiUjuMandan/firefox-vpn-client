# Firefox VPN Client Operator Notes

这里记录的是维护、部署和排障步骤；只建议在你自己的授权账号和机器上使用。

## 基本能力

- 登录 Firefox Account，获取 OAuth token 和 Guardian proxy pass。
- 本地暴露 SOCKS5 CONNECT 代理。
- 上游使用单条 HTTP/2 或 HTTP/3 CONNECT session。
- proxy pass 后台续期；OpenTunnel 失败时会重建上游 session 并重试。
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
-proxy HOST:PORT              # 指定出口 proxy，不指定则随机选择 CONNECT 服务器
-h3                           # 使用 HTTP/3/QUIC
-timeout 20s                  # 上游拨号、握手、CONNECT 打开阶段超时
-handshake-timeout 10s        # 客户端 SOCKS5 握手超时
-max-conns 256                # 最大并发客户端连接数，0 表示关闭限制
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
- `PROXY=` 为空时会随机选择 CONNECT server，可能选到跨洲或内部绕路严重的节点。
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
TIMEOUT=20s
HANDSHAKE_TIMEOUT=10s
MAX_CONNS=256
USE_H3=0
VERBOSE=0
HEALTH_INTERVAL=30s
HEALTH_TIMEOUT=5
HEALTH_VERBOSE=0
EXTRA_ARGS=
```

## 升级

拉取新代码后重新安装即可。token 和配置默认保留。

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
2. 连接 `LISTEN` 地址。
3. 如果有 `python3`，执行 SOCKS5 greeting 检查。
4. 没有 `python3` 时退化为 TCP 端口检查。
5. 失败则执行 `systemctl restart firefox-vpn-client.service`。

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
