# 功能分类总览 (FEATURES)

agent-netx 的所有能力按 **OSI / TCP-IP 分层** 组织，方便记忆：知道你想在哪一层动手，就知道用哪个命令。每一层往下都更接近物理网络，往上都更接近应用。

```
┌─────────────────────────────────────────────────────────────────┐
│  L7 应用层   App 流量  ·  MITM HTTPS 拦截  ·  gen_config  ·  TUI  │
├─────────────────────────────────────────────────────────────────┤
│  L4 传输层   HTTP/SOCKS5 监听  ·  端口转发(-L/-R/-D/-U/tls) · 链式│
├─────────────────────────────────────────────────────────────────┤
│  L3 网络层   TUN 透明代理  ·  n2n P2P VLAN  ·  STUN/TURN VPN      │
├─────────────────────────────────────────────────────────────────┤
│  代理协议    HTTP/HTTPS/SOCKS5/SS/Trojan/VMess/VLESS+Reality     │
├─────────────────────────────────────────────────────────────────┤
│  控制面      规则路由  ·  分组(selector/url-test/rr) · 流量统计    │
├─────────────────────────────────────────────────────────────────┤
│  运维面      Web Dashboard  ·  REST API  ·  DNS(DoH/DoT)  ·  sysproxy│
└─────────────────────────────────────────────────────────────────┘
```

---

## L7 · 应用层

贴近 App 与用户意图。这一层解决"App 不配合怎么办"和"配置太难写怎么办"。

| 功能 | 命令 / 入口 | 作用 | 状态 |
|------|------------|------|------|
| **MITM HTTPS 拦截** | `forward tls` + 自签 CA | 终止 TLS、改写/记录明文 HTTP，自动安装 CA | ✅ |
| **LLM Agent TUI** | `agent-netx tui` | 自然语言驱动所有功能，调用工具完成 | ✅ |
| **gen_config 工具** | TUI 内 | 从自然语言描述生成完整 YAML（区别于 update_config 的覆写） | ✅ |
| **update_config 工具** | TUI 内 | 用新 YAML 覆写配置（写入前校验） | ✅ |

**应用场景**：某 App 写死了域名、不读系统代理 → `forward tls` 劫持 + hosts 指向；不想背命令 → `tui` 直接说"把 google 走 ss-1"。

---

## L4 · 传输层

面向连接 / 数据报的转发与代理。这一层是 SSH 风格端口转发的主场。

### 4.1 本地监听代理

| 功能 | 命令 | 说明 | 状态 |
|------|------|------|------|
| HTTP 代理 | `proxy` / `start` | 监听 HTTP CONNECT | ✅ |
| SOCKS5 代理 | `proxy` / `start` | 监听 SOCKS5 CONNECT + **UDP ASSOCIATE** | ✅ |
| 系统代理一键 | `sysproxy on/off/status` | Win 注册表 / Linux env / GNOME | ✅ |

### 4.2 端口转发（SSH 风格，5 种模式）

| 模式 | 命令 | 含义 | 状态 |
|------|------|------|------|
| `forward local` (-L) | `forward local <listen> <dst>` | 本地监听 → 固定目标 | ✅ |
| `forward remote` (-R) | `forward remote <sshAlias> <rListen> <dst>` | 远程 SSH 主机上的监听 → 本地目标 | ✅ |
| `forward dynamic` (-D) | `forward dynamic <listen>` | 本地 SOCKS5 监听 → 任意目标 | ✅ |
| `forward udp` (-U) | `forward udp <listen> <dst>` | 本地 UDP 监听 → 固定 UDP 目标（DNS/QUIC） | ✅ |
| `forward tls` | `forward tls <listen> <dst> [sni]` | HTTPS 监听 → 明文 HTTP 后端（TLS 终止） | ✅ |

所有 TCP 模式都支持 `--proxy <name>`：目标拨号走配置文件里指定的代理，于是转发可以**经代理链式**出去。

### 4.3 代理链式 (Chain)

```yaml
proxies:
  - name: hop
    type: chain
    proxies: [ss-1, trojan-1]   # ss-1 → trojan-1 → 目标
```

`Connect` 逐段拨号：经 p[0] 连到 p[1] 的服务器，…… 最后连到目标。链本身是一个 Proxy，可被规则 / 转发 / 分组像普通代理一样引用。

**应用场景**：`forward udp :1053 1.1.1.1:53 --proxy prod-socks5` —— 把本地 DNS 经 SOCKS5 的 UDP ASSOCIATE 代理出去。

---

## L3 · 网络层

内核级 / 虚拟网卡层面接管流量。这一层实现"任意 App 无感走代理"和"跨 NAT 组网"。

| 功能 | 命令 | 作用 | 状态 |
|------|------|------|------|
| **TUN 透明代理** | `tun` / `start`(+tun.enable) | 虚拟网卡读写真实 IP 包，按 dst IP 路由到隧道 | ✅ (Linux/Win) |
| **n2n P2P VLAN** | `n2n` | 自定义协议 P2P 虚拟局域网，NAT 打洞 | ✅ |
| **STUN/TURN VPN** | `stunvpv` | 标准协议(RFC 5389/5766) 中继 VPN | ✅ |
| **TUN ↔ 隧道桥接** | `start` 自动 | TUN 收到的包 → n2n/stunvpv 发给对端；对端包 → 写回 TUN | ✅ |

### 架构：tunnel.Peer 接缝

```
   App ──► TUN 设备 (wintun / /dev/net/tun)
              │  Read: 解析 IP 包 dst
              ▼
         tunnel.Peer 接口  ◄── 结构化适配，新增隧道类型只需实现它
              │  SendTo(dstIP, data)
      ┌───────┴────────┐
      ▼                ▼
   n2n.Edge        stunvpv.Client     (未来: WireGuard …)
      │                │
      ▼                ▼
   P2P / TURN 中继 → 对端 TUN → 对端 App
```

`tun.Peer` 接口（`OnData`/`SendTo`/`VirtualIP`）让 TUN 不依赖任何具体隧道包——这是"设计好架构、方便后续添加功能"的接缝。新增 WireGuard 等只需实现 `Peer`。

**应用场景**：两台不同 NAT 后的机器互访内网 → 各跑一个 `stunvpv` client + `tun.enable`，`ping <对端虚拟IP>` 即通。

---

## 代理协议层

可插拔的远程代理协议，统一实现 `proxy.Proxy` 接口（`Connect/Latency/Close`）；支持 UDP 的再实现可选的 `proxy.PacketProxy`（`ConnectUDP`）。

| 协议 | 类型 | UDP | 特性 | 状态 |
|------|------|-----|------|------|
| HTTP | `http` | — | 明文 CONNECT | ✅ |
| HTTPS | `https` | — | TLS CONNECT | ✅ |
| SOCKS5 | `socks5` | ✅ | CONNECT + UDP ASSOCIATE | ✅ |
| Shadowsocks | `ss` | — | ChaCha20-Poly1305 等 | ✅ |
| Trojan | `trojan` | — | TLS 伪装 HTTPS | ✅ |
| VMess | `vmess` | — | UUID + AEAD | ✅ |
| **VLESS + Reality** | `vless` | — | uTLS 指纹伪装 + X25519 + ShortID | ✅ |
| Chain | `chain` | 继承 | 多跳串联 | ✅ |

### VLESS + Reality

Reality 让 TLS 握手看起来像真实浏览器（Chrome/Firefox/iOS/Edge/Randomized 的 ClientHello），绕过 SNI / JA3 指纹封锁：

```yaml
- name: vless-reality
  type: vless
  server: example.com
  port: 443
  uuid: 你的-uuid
  public-key: 服务器curve25519公钥(base64url,43字符)
  short-id: 8位hex
  fingerprint: chrome        # chrome/firefox/ios/edge/random
  sni: example.com
```

`fingerprint` 为空 → 退回普通 crypto/tls；非空 → 走 uTLS 指纹路径。

---

## 控制面 · 路由与调度

决定"这条流量走哪个代理"。

| 功能 | 说明 | 状态 |
|------|------|------|
| 模式 | direct / global / rule | ✅ |
| 规则 | DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / GEOIP / **REGEX** (正则) / **PORT-RANGE** (端口段) / MATCH | ✅ |
| 分组 | selector (手选) / url-test (最快 + 故障切换) / round-robin (轮询) / chain (链式) / **failover** (按序 fallback) / **load-balance** (随机分发) | ✅ |
| **流量统计** | 每代理上/下行字节 + 活跃连接数，经 statsConn 自动计量 | ✅ |

### 规则类型速览

```yaml
rules:
  - DOMAIN,google.com,proxyA              # 精确域名
  - DOMAIN-SUFFIX,.google.com,proxyA      # 后缀
  - DOMAIN-KEYWORD,google,proxyA          # 关键字
  - IP-CIDR,8.8.8.8/32,DIRECT             # 网段
  - GEOIP,CN,DIRECT                       # 内网/私有/CN
  - REGEX,^api\..+\.example\.com$,proxyA  # 正则匹配主机名
  - PORT-RANGE,80-443,DIRECT              # 目标端口段 (含两端)
  - MATCH,DIRECT                          # 兜底
```

**REGEX**: 用 Go `regexp` 语法匹配目标主机名（不含端口），例如 `^api\..+\.example\.com$`。
**PORT-RANGE**: `80-443` 或单端口 `443`，命中客户端请求的目标端口；当端口为 0（无法识别时）会退化为匹配。

流量统计在 `listener` 的 relay 路径自动生效（`Options.Stats` 接一个 `web.StatsTracker`），无需改业务代码；`/api/stats` 端点可读。

---

## 运维面

| 功能 | 命令 / 入口 | 作用 | 状态 |
|------|------------|------|------|
| Web Dashboard | `web` / `start` | 可视化统计、切分组、看日志 | ✅ |
| REST API | 同上进程 | 外部程序控制分组切换、读统计 | ✅ |
| DNS 服务器 | `dns` | 本地 DNS，DoH/DoT/直连 + FakeDNS | ✅ |
| 系统代理 | `sysproxy on/off/status` | 一键启停系统代理 | ✅ |
| ping | `ping <target>` | hping3 风格探测：ICMP/TCP/UDP 三模式 + traceroute，无需配置文件 | ✅ |
| socat | `socat <addr1> <addr2>` | TCP/UDP 双向中继，socat 风格地址，无需配置文件 | ✅ |
| status | `status` | 显示当前配置 | ✅ |
| use | `use <分组> <代理>` | 切手动分组 | ✅ |
| init | `init` | 生成示例 config.yml | ✅ |
| scp | `scp` | SSH 文件拷贝（forward remote 复用其主机解析） | ✅ |
| run | `run <local\|remote>` | 本地/远端执行 shell 命令，配合 scp + file_copy 实现一键部署 n2n/frp/wireguard | ✅ |
| netdiag | `netdiag` | 连接/监听/抓包/聚合 | ✅ |
| logs | `logs [--tail n] [--follow]` | 读共享日志文件 | ✅ |
| validate | `validate` | 语义校验 config | ✅ |
| stop / restart | `stop <name|all>` / `restart <name|all>` | 通过 PID 文件跨进程启停 | ✅ |

### TUI 会话内扩展命令

| 命令 | 作用 |
|------|------|
| `/add-proxy <name> <type> <server> <port> [key=val ...]` | 运行时新增代理，写入 `~/.agent-netx/dynamic.yml` 覆盖层，下次 `buildRouter` 生效 |
| `/add-rule <TYPE,PATTERN,TARGET>` | 运行时新增规则，写到同一覆盖层，最高优先级 |
| `/session-export [<idOrName>] <dst>` | 导出当前会话（或指定 id/name）到 JSON 文件 |
| `/session-import <src>` | 从 JSON 文件导入会话，生成新 UUID，保存到 store |
| `/run <local|remote>` | 本地/远端执行命令（agent 工具 `run_local` / `run_remote` 也在 TUI 内可用） |

TAB 键对 `/` 命令按前缀自动补全；唯一匹配时直接补齐，多个匹配时循环。

---

## 分层速记口诀

> **L7 改应用，L4 转端口，L3 接网卡，协议可换，路由决定走谁，运维看面板。**

## 一键部署链路（n2n / frp / wireguard 通用）

在 TUI 里告诉 agent 远端中心机的 SSH 信息，然后一句"在 prod 部署 n2n VPN"即可完成整条链路：

1. **记 SSH**：告诉 agent 主机地址/用户/密码 → `remember` 工具存到 `~/.agent-netx/memory.json`，下次 `--alias prod` 即可免输。
2. **生成配置**：`gen_config` 生成含 n2n supernet 的 `config.yml`。
3. **传文件**：`file_copy`（复用 `scp` 底层）把 `agent-netx` 二进制 + `config.yml` 传到 `/opt/agent-netx/`。
4. **起服务**：`run_remote --alias prod "cd /opt/agent-netx && ./agent-netx start -c config.yml"`，远端 session 流式回传输出。
5. **看状态**：`run_remote --alias prod "agent-netx status"` 或 `logs_tail(n=20)`。

CLI 等价：`agent-netx run remote --alias prod --cmd "cd /opt/agent-netx && ./agent-netx start -c config.yml"`。

需要新增功能时，先问"它属于哪一层"：
- 改 / 拦截 App 流量 → L7
- 转发 / 监听 / 串联连接 → L4
- 虚拟网卡 / 跨 NAT 组网 → L3
- 新增一种远程代理 → 协议层（实现 `Proxy` 接口，注册一个 case）
- 决定流量去向 → 控制面
- 给人看 / 给程序调 → 运维面
