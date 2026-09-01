# agent-netx

<p align="center">
<pre>
        ⚡ agent-netx · 自然语言驱动的网络工具
</pre>
</p>

> 说人话，让 AI 帮你调网络。`tui` 启动后，用中文描述需求——"把 Google 走 ss-1"、
> "把本机日志上传到 prod 服务器"——agent 自动把自然语言翻译成配置、规则、代理分组，
> 直接写进 `config.yml` 并生效。

底层是一个全功能的网络工具集：6 种远程代理协议、3 种代理分组、7 种规则类型，
外加 forward 端口转发、n2n P2P、STUN/TURN VPN、WireGuard、TUN 透明代理、
MITM HTTPS、Web Dashboard、DNS、SCP、**netdiag 网络诊断**。

可以当 CLI 工具单独跑，也可以交给 agent 一句话完成。

---

## 🚀 快速开始

```powershell
# 安装（推荐）
powershell -Command "irm https://github.com/yejinlei/agent-netx/releases/latest/download/install.ps1 | iex"

# 生成示例配置
agent-netx init

# 一条命令启动（快速模式）
agent-netx start --proxy ss://aes-256-gcm:password@server:port
agent-netx start --proxy http://user:pass@server:port
agent-netx start --proxy trojan://password@server:port?sni=example.com

# 或完整配置模式
agent-netx start -c config.yml

# 或最推荐 —— 自然语言交互
agent-netx tui
```

---

## 🧠 Agent 交互模式（tui）

```powershell
agent-netx tui              # 新对话
agent-netx tui --continue   # 续写上次对话
agent-netx tui --continue my-session   # 续写指定会话
```

启动后直接用中文描述需求：

| 你说 | Agent 做的 |
|------|-----------|
| "把 google 走 ss-1" | 写入规则并 `switch_group` |
| "把 google.com 加到 Auto 分组" | 调用 `add_rule` |
| "把本机 C:\app.log 上传到 prod 服务器" | 调 `file_copy`（HIL 记一次凭据） |
| "测一下所有代理延迟" | 调 `ping_proxies` |
| "列出当前所有网络端口" | 调 `net_connections` |
| "把这次对话保存到调试记录" | 调 `session_save` |

Agent 走 OpenAI 兼容 API（任意兼容端点均可），配置在 `agent.yml` 中。

### TUI 内置命令

```
/sessions            列出所有已保存的会话
/session <name|id>   切换到某会话续写
/new [name]          新建会话
/rename <name>       重命名当前会话
/delete <name|id>    删除某会话
/clear               清空当前会话
/help                查看命令帮助
/help                查看命令帮助
/<subcommand>     直接运行 agent-netx 子命令 (不离开 TUI)
/help                查看命令帮助
TUI 快捷命令 (/xxx → agent-netx xxx):
  /init        生成示例配置     /start       启动所有启用的服务
  /status      显示当前配置     /proxy       仅启动 HTTP/SOCKS5 代理
  /ping        测试代理延迟     /dns         仅启动本地 DNS
  /use         切换手动分组     /web         仅启动 Web 仪表盘
  /sysproxy    系统代理 on/off  /tun         仅启动 TUN 设备
  /forward     端口转发         /n2n         仅启动 n2n 节点
  /scp         SSH 文件拷贝     /stunvpv     仅启动 STUN/TURN VPN
  /run         本地/远端执行命令  /wireguard   仅启动 WireGuard
  /netdiag     网络诊断         /wireguard/frp/tinc/socat/corsproxy
/help                查看命令帮助
```

---

## 📐 架构

![agent-netx 架构](docs/architecture.svg)

完整分层速览与交互版全景图见 [MANUAL.md §2.1](MANUAL.md) 和 [docs/panorama.html](docs/panorama.html)。

## 📚 交互式架构文档

访问 **[yejinlei.github.io/agent-netx/](https://yejinlei.github.io/agent-netx/)**
浏览 16 张交互式架构图（由 Archify 渲染，支持 pan/zoom/search/focus）。

---

## 🧩 功能全景

| 类别 | 已实现 | 规划中 |
|------|--------|--------|
| 远程代理 | HTTP / HTTPS / SOCKS5 ✦UDP / SS / Trojan / VMess / **VLESS+Reality ★uTLS** | — |
| 代理分组 | selector / url-test / round-robin / **chain (代理链式)** / **failover (故障切换)** / **load-balance (负载均衡)** | — |
| 代理模式 | direct / global / rule | — |
| 规则类型 | DOMAIN / SUFFIX / KEYWORD / IP-CIDR / GEOIP / MATCH / **REGEX** / **PORT-RANGE** | — |
| 本地监听 | HTTP / SOCKS5 / **TProxy (Linux, iptables TPROXY)** | — |
| 端口转发 | forward: -L local / -R remote / -D dynamic / -U udp / tls | — |
| 系统代理 | sysproxy on/off/status (Win 注册表 + Linux gsettings) | — |
| 透明代理 | TUN (wintun / /dev/net/tun) + 自动桥接 n2n/stunvpv | — |
| 隧道 | n2n P2P / STUN/TURN VPN / **WireGuard** + tunnel.Peer 接缝 | — |
| 网络诊断 | **netdiag** — 连接 / 监听 / 抓包 / 聚合统计（netstat / ss / tcpdump 等价） | — |
| 会话管理 | **session** — TUI 内置 + Agent 工具，持久化 + 切换 + 续写 + **导出/导入 (session-export/import)** | — |
| 特殊能力 | forward 劫持 / MITM CA / 流量统计 | — |
| 运维 | ping / status / use / Web Dashboard / REST API / DNS(DoH/DoT) / LLM Agent TUI / gen_config / SCP | — |

★ = uTLS 指纹伪装   ✦ = 支持 UDP (PacketProxy)

### 用法决策图

```mermaid
flowchart TD
    App["App 不走代理?"]
    A1["系统代理 + rule<br/>条件: App 走 WinINet<br/>App 配合: ❌<br/>改 hosts: ❌"]
    A2["TUN 模式 (P0)<br/>条件: 任意 App<br/>App 配合: ❌<br/>改 hosts: ❌"]
    A3["MITM CA (P0)<br/>条件: 任意 App + hosts<br/>App 配合: ❌<br/>改 hosts: ✅"]
    A4["forward 命令<br/>条件: 任意 App + hosts<br/>App 配合: ❌<br/>改 hosts: ✅"]

    App -->|WinINet 代理生效| A1
    App -->|任意 App, 无需配置| A2
    App -->|需要 hosts| A3
    App -->|需要 hosts| A4
```

---

## ⌨️ 命令总览

```
agent-netx [command]

命令：
  start        启动代理（-c 配置文件 / --proxy 快速模式）—— 一键全开所有启用项
  init         生成示例配置
  status       显示当前配置
  ping         hping3 风格探测：ICMP/TCP/UDP 三模式 + traceroute（无需配置）
  socat        TCP/UDP 双向中继，socat 风格地址（无需配置）
  use          切换手动分组
  sysproxy     一键开关系统代理 (on/off/status)
  forward      SSH 风格端口转发 (-L / -R / -D / -U / tls)
  proxy        仅启动 HTTP/SOCKS5 代理（独立运行）
  dns          仅启动本地 DNS（独立运行）
  web          仅启动 Web 仪表盘（独立运行）
  tun          仅启动 TUN 设备（独立运行）
  n2n          仅启动 n2n 虚拟局域网节点（独立运行）
  stunvpv      仅启动 STUN/TURN VPN 节点（独立运行）
  tui          启动 LLM Agent 交互模式（自然语言驱动所有功能）
  scp          SSH 文件拷贝（记住 --alias）
  run          本地/远端执行 shell 命令（local cmd.exe/sh; remote SSH）
  netdiag      查看进程网络端口和数据包 (netstat / ss / tcpdump 等价)

全局选项：
  -c, --config  配置文件路径
```

每个 `proxy`/`dns`/`web`/`tun`/`n2n`/`stunvpv` 子命令都只跑一块，前台运行、`Ctrl-C` 退出——
排障或按需起服务很方便。`start` 则会把所有 `enable: true` 的子服务一起拉起。

详细用法见 [MANUAL.md](MANUAL.md)。

---

## 📋 配置示例

```yaml
listen:
  http: 7890
  socks5: 7891
  # tproxy: 7892      # Linux TProxy 透明监听端口
  # tproxy-mark: 1    # 自动下发的 fwmark（0 = 不自动下发，用户自管）
  # tproxy-table: 100 # 自动下发的 ip route local 表号

mode: rule

proxies:
  - name: ss-1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: my-secret

  - name: trojan-1
    type: trojan
    server: 5.6.7.8
    port: 443
    password: trojan-pass
    sni: example.com

  - name: forward-multica
    type: forward
    server: 192.168.0.77
    port: 8080

proxy-groups:
  - name: Auto
    type: url-test
    proxies: [ss-1, trojan-1]
    url: https://www.gstatic.com/generate_204
    interval: 300

  - name: Manual
    type: selector
    proxies: [ss-1, trojan-1, DIRECT]
    default: ss-1

rules:
  - DOMAIN,api.multica.ai,forward-multica
  - DOMAIN-SUFFIX,.google.com,Auto
  - IP-CIDR,8.8.8.8/32,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT
```

---

## 🛠️ netdiag 网络诊断

媲美 `netstat` / `ss` / `tcpdump` 的内置网络诊断工具，CLI 与 Agent 双通道可用。

```powershell
agent-netx netdiag conns       # 所有进程连接表
agent-netx netdiag listeners   # TCP 监听端口
agent-netx netdiag stats       # 按状态聚合统计（类似 ss -s）
agent-netx netdiag packets     # 原始套接字抓包（需管理员/root）
```

Agent 内可一句话调用：`"查看 8080 端口的连接"` → 自动调 `net_connections`。

---

## 📦 深度功能挖掘

| 优先级 | 功能 | 说明 | 状态 |
|--------|------|------|------|
| **P0** | TUN 模式 | 内核级网络接管，所有 App 无感走代理 | ✅ |
| **P0** | 系统代理一键管理 | sysproxy on/off/status (Win/Linux) | ✅ |
| **P0** | MITM + 自签 CA 自动安装 | HTTPS→HTTP 劫持，自动装证书 | ✅ |
| **P1** | 端口转发 -L/-R/-D/-U/tls | SSH 风格 5 模式 + --proxy | ✅ |
| **P1** | 代理链式 | proxyA → proxyB → 目标 | ✅ |
| **P1** | 流量统计 + 日志 | statsConn 自动计量上下行字节 + 活跃连接 | ✅ |
| **P2** | Web UI 仪表盘 + REST API | 可视化统计、切分组、看日志 | ✅ |
| **P2** | DNS 代理 | 本地 DNS 解析，DoH/DoT + FakeDNS | ✅ |
| **P2** | VLESS / Reality | uTLS 指纹伪装 + X25519 + ShortID | ✅ |
| **P2** | 网络诊断 netdiag | 连接 / 监听 / 抓包 / 聚合，媲美 netstat / ss / tcpdump | ✅ |
| **P2** | 会话管理 session | TUI + Agent 持久化 + 切换 + 续写 + 导出/导入 | ✅ |
| **P2** | 规则类型扩展 | REGEX 正则 + PORT-RANGE 端口段 | ✅ |
| **P2** | 代理分组扩展 | failover (故障切换) + load-balance (负载均衡) | ✅ |
| **P3** | TProxy 透明监听 | Linux iptables TPROXY 目标，无需改 App 配置 | ✅ |
| **P3** | 运行时动态配置 | /add-proxy /add-rule 会话内动态更新，无需重启 | ✅ |
| **P3** | TUI TAB 补全 | 会话 `/` 命令按前缀自动补全 | ✅ |
| **P3** | P2P 隧道 | n2n P2P / STUN/TURN 跨 NAT 组网 | ✅ |
| **P3** | WebRTC / UDP 代理 | SOCKS5 UDP ASSOCIATE + forward -U | ✅ |
| P3 | WireGuard 隧道 | tunnel.Peer 接缝已就绪，实现即插 | ✅ |
| P3 | HTTP/3 (QUIC) | 下一代 HTTP 代理 | ✅ |

---

## 📚 依赖

| 包 | 用途 |
|----|------|
| github.com/spf13/cobra | CLI 框架 |
| gopkg.in/yaml.v3 | 配置解析 |
| github.com/charmbracelet/lipgloss | TUI 排版与着色 |
| github.com/quic-go/quic-go | HTTP/3 (QUIC) 代理 (`type: http3`) |
| golang.org/x/crypto | SS 加密 (ChaCha20-Poly1305) |
| github.com/shirou/gopsutil/v3 | 进程网络连接查询 (netdiag) |
| net.ListenPacket (stdlib) | 原始套接字抓包 (netdiag packets) |

---

## 🗺️ 路线图

- [x] 6 种远程代理
- [x] 3 种分组
- [x] 规则路由
- [x] forward 劫持
- [x] TUN 模式 (P0)
- [x] MITM + 自签 CA 自动安装 (P0)
- [x] Web Dashboard + REST API (P2)
- [x] DNS 代理 + DoH/DoT + FakeDNS (P2)
- [x] P2P 隧道 — n2n 虚拟局域网 (P3)
- [x] STUN/TURN 标准协议 VPN (P3)
- [x] LLM Agent + TUI 自然语言驱动 (P3)
- [x] 系统代理一键管理 (sysproxy, P0)
- [x] 端口转发 -L/-R/-D/-U/tls (P1)
- [x] 流量统计 + 日志 (statsConn, P1)
- [x] 代理链式 chain (P1)
- [x] VLESS / Reality (uTLS 指纹, P2)
- [x] P2P 隧道 (n2n / STUN/TURN, P3)
- [x] WebRTC / UDP 代理 (SOCKS5 UDP ASSOCIATE + forward -U, P3)
- [x] WireGuard 隧道
- [x] HTTP/3 (QUIC) 代理
- [x] 网络诊断 (netdiag: conns/listeners/packets/stats)
- [x] 会话管理 (session: TUI 内置命令 + Agent 工具 + 导出/导入)
- [x] 规则类型 REGEX / PORT-RANGE
- [x] 代理分组 failover / load-balance
- [x] TProxy 透明监听 (Linux)
- [x] 运行时动态配置 (/add-proxy /add-rule)
- [x] TUI TAB 命令补全

---

<p align="center">
  <a href="https://github.com/yejinlei/agent-netx">github.com/yejinlei/agent-netx</a>
  ·
  <a href="https://github.com/yejinlei/agent-netx/releases">Releases</a>
  ·
  <a href="https://yejinlei.github.io/agent-netx/">架构文档</a>
</p>
