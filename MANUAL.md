# agent-netx 用户手册

> 交互式架构文档 (Archify 渲染,支持 pan/zoom/search/focus):
> **[yejinlei.github.io/agent-netx/](https://yejinlei.github.io/agent-netx/)**
>
> 本项目地址: **github.com/yejinlei/agent-netx** · Releases: **github.com/yejinlei/agent-netx/releases**

---

## 0. 一句话定位

**一个可以当瑞士军刀用的网络代理 + 组网工具**,把 HTTP/SOCKS5/SS/Trojan/VMess/VLESS+Reality 这些代理协议、端口转发、TUN 透明代理、n2n/STUN/TURN/WireGuard/Tinc 组网、netstat/tcpdump 类诊断,以及 LLM Agent 全部塞进一个二进制。

- 想"全局翻墙" → 配 `proxies` + `start`
- 想"只劫持一个 App" → `forward tls` 或 `mitm`
- 想"两台机器互通内网" → `n2n` / `stunvpv` / `wireguard` / `tinc`
- 想"像 SSH 一样端口转发" → `forward -L/-R/-D/-U/tls/reverse`
- 想"临时 TCP/UDP 中转" → `socat`
- 想"看本机连接/抓包" → `netdiag`
- 想"用自然语言驱动所有功能" → `tui`

---

## 1. 安装

```powershell
# 一键安装最新版(Windows)
powershell -Command "irm https://github.com/yejinlei/agent-netx/releases/latest/download/install.ps1 | iex"

# 或从源码构建
go mod tidy
go build -ldflags "-s -w" -o agent-netx.exe .
```

支持平台:linux-amd64 / linux-arm64 / darwin-amd64 / darwin-arm64 / windows-amd64 / windows-arm64。

首次使用:

```powershell
agent-netx init          # 生成 config.yml 和 agent.yml
```

---

## 2. 全景总览(分层 × 功能)

按 **TCP/IP 层** 组织所有能力,知道你想在哪一层动手就知道用哪个命令。

```
┌──────────────────────────────────────────────────────────────────────────┐
│ L7 应用层   │ MITM HTTPS 拦截 · gen_config · TUI Agent · Web 面板 · CORS │
├──────────────────────────────────────────────────────────────────────────┤
│ L4 传输层   │ forward(-L/-R/-D/-U/tls/-reverse) · 代理监听 · 代理链 chain│
│             │ socat · frp · socks5 UDP ASSOCIATE                         │
├──────────────────────────────────────────────────────────────────────────┤
│ L3 网络层   │ TUN 透明代理 · TProxy(Linux)· TProxy(WinDivert)· n2n · STUN│
│             │ VPN · WireGuard · Tinc                                      │
├──────────────────────────────────────────────────────────────────────────┤
│ 代理协议    │ http · https · socks5 ✦UDP · ss · trojan · vmess · vless    │
│             │ vless+Reality ★uTLS · forward · http3 · chain              │
├──────────────────────────────────────────────────────────────────────────┤
│ 控制面      │ 规则路由 · 分组(selector/url-test/rr/failover/lb) · 流量统计│
├──────────────────────────────────────────────────────────────────────────┤
│ 运维面      │ sysproxy · ping(hping3) · netdiag(netstat/ss/tcpdump) ·    │
│             │ DNS(DoH/DoT) · status · use · init · scp · run · logs      │
└──────────────────────────────────────────────────────────────────────────┘
   ★ = uTLS 指纹伪装   ✦ = 支持 UDP
```

**分层速记口诀**

> **L7 改应用,L4 转端口,L3 接网卡,协议可换,路由决定走谁,运维看面板。**

LLM Agent 是横贯所有层的能力:一句话驱动上面任意层。

详细分类见 `docs/FEATURES.md`。

---

## 3. 配置详解(config.yml)

一次 `init` 生成的 `config.yml` 是所有功能的起点(除 ping / socat / run 等纯命令行工具外)。

### 3.1 顶层结构

```yaml
listen:
  http: 7890          # HTTP 代理监听端口
  socks5: 7891        # SOCKS5 代理监听端口
  # tproxy: 7892      # 透明代理监听(需要路由/WinDivert 配合)
  # tproxy-mark: 1    # fwmark(Linux 自动装路由环用,0 = 手动)
  # tproxy-table: 100 # ip route local table 号

mode: rule             # global | rule | direct

proxies: [...]         # 代理列表
proxy-groups: [...]    # 分组(手动/自动/轮询/故障切换/负载均衡)
rules: [...]           # 路由规则

# 可选子模块(默认 enable: false)
tun:    {...}          # TUN 透明代理
dns:    {...}          # 本地 DNS
web:    {...}          # Web 仪表盘
mitm:   {...}          # HTTPS 拦截
n2n:    {...}          # n2n 虚拟局域网
stunvpv:{...}          # STUN/TURN VPN
wireguard: {...}       # WireGuard P2P VPN
agent:  {...}          # LLM Agent 配置(迁移到 agent.yml,保留兼容)
```

### 3.2 代理 (proxies)

| 类型 | 必选字段 | 可选字段 | UDP | 备注 |
|------|---------|---------|-----|------|
| `http` | server, port | username, password | — | 明文 CONNECT |
| `https` | server, port | sni, alpn | — | TLS CONNECT |
| `socks5` | server, port | username, password | ✅ | CONNECT + UDP ASSOCIATE |
| `ss` / `shadowsocks` | server, port, cipher, password | — | — | ChaCha20-Poly1305 等 |
| `trojan` | server, port, password | sni, alpn | — | TLS 伪装 HTTPS |
| `vmess` | server, port, uuid | alterId, method | — | UUID + AEAD |
| `vless` | server, port, uuid | sni, alpn, public-key, short-id, fingerprint | — | Reality + uTLS 指纹 |
| `forward` | server, port | sni | — | HTTP 前置代理(可透传 HTTPS) |
| `http3` | server, port | — | ✅ | QUIC/HTTP3 代理 |

`forward` 类型:当作一个"本地直连到某 HTTP 代理"的透传代理,常用来桥接到公司内网代理,或把流量从 TUN 透传给一个已有的 SS 前端。

`vless` 加 `fingerprint` / `public-key` / `short-id` 即启用 **Reality**,详见 §5.3。

### 3.3 代理分组 (proxy-groups)

| 类型 | 行为 | 常用场景 |
|------|------|---------|
| `selector` | 手动切换 | 想随时换线路 |
| `url-test` / `urltest` | 每 `interval` 秒自动测速,选最快;失败自动切下一跳 | 自动选最快 |
| `round-robin` / `roundrobin` | 轮询 | 简单分流 |
| `chain` | 多跳串联:p[0] → p[1] → 目标 | 代理接力,绕反代封锁 |
| `failover` | 按序尝试,首个失败自动切下条 | 主备切换 |
| `load-balance` / `loadbalance` | 随机分发 | 减轻单跳负载 |

```yaml
proxy-groups:
  - name: Auto
    type: url-test
    proxies: [ss-1, trojan-1]
    url: https://www.gstatic.com/generate_204
    interval: 300
    default: ss-1

  - name: Manual
    type: selector
    proxies: [ss-1, trojan-1, DIRECT, REJECT]
    default: ss-1

  - name: Hop
    type: chain
    proxies: [ss-1, trojan-1]        # ss-1 → trojan-1 → 目标

  - name: Fallback
    type: failover
    proxies: [ss-1, trojan-1]
    url: https://www.gstatic.com/generate_204
    interval: 10
```

所有分组本身也是一个 `Proxy`,可以出现在规则 target、`--proxy`、`use` 命令里。

### 3.4 规则 (rules)

按顺序匹配,第一条命中即生效。`MATCH` 是兜底。

| 类型 | 示例 | 语义 |
|------|------|------|
| `DOMAIN` | `DOMAIN,google.com,Auto` | 精确主机名 |
| `DOMAIN-SUFFIX` | `DOMAIN-SUFFIX,.google.com,Auto` | 后缀(带点或补点) |
| `DOMAIN-KEYWORD` | `DOMAIN-KEYWORD,youtube,Auto` | 包含关键字 |
| `IP-CIDR` | `IP-CIDR,8.8.8.8/32,DIRECT` | 网段 |
| `GEOIP` | `GEOIP,CN,DIRECT` | 内网/私有/本地(当前实现不接 GeoIP 库,等同 IsLoopback/IsPrivate) |
| `REGEX` | `REGEX,^api\..+\.example\.com$,Auto` | 正则匹配主机名(不含端口) |
| `PORT-RANGE` | `PORT-RANGE,80-443,DIRECT` | 目标端口段(含两端;端口未知时退化为命中) |
| `MATCH` | `MATCH,Auto` | 兜底 |

规则 target 可以是代理名、分组名、`DIRECT`(直连)、`REJECT`(拒绝)。

### 3.5 TUN 透明代理

让**任意 App 无感走代理**:内核开一个虚拟网卡,读写真实 IP 包。

**原理图**:
```
┌───┐       ┌──────────────────────────────────────┐       ┌─────┐
│App│──────►│  TUN 设备(wintun / /dev/net/tun)     │─────►│隧道 │
└───┘       │  Read: 解析 dstIP → 决定走哪条       │       └─────┘
            │  Write: 从隧道回来的 IP 包 → 写回内核  │
            └──────────────────────────────────────┘
```

配置:

```yaml
tun:
  enable: true
  device: "net-redirect"
  mtu: 1500
  gateway: "198.18.0.1"
  cidr: "198.18.0.0/16"
  dns: "198.18.0.2"
```

Windows 需先下载 `wintun.dll` 放到程序目录。

**自动桥接**:`tun.enable` + `n2n/stunvpv/wireguard.enable` 时,启动时自动创建 TUN、设 MTU、加路由、把隧道接到 `tunnel.Peer` 接缝。

**机制**:TUN Read 读到真实 IP 包,解析 dstIP → 匹配 overlay CIDR → 交给对应隧道 `peer.SendTo(dstIP, data)`;隧道 `peer.OnData` 回包 → `tun.WritePacket(data)` 写回内核。

**使用步骤**:
1. `tun.enable: true`
2. Windows:把 `wintun.dll` 放到程序同目录
3. 起任意隧道(或单独用 TUN 走代理):`n2n.enable` / `stunvpv.enable` / `wireguard.enable` 或直接把流量导向 `--proxy`
4. `agent-netx start` 自动桥接

### 3.6 DNS 服务器

本地 DNS 服务,支持三种解析后端:

| mode | 后端 |
|------|------|
| `direct` | 本机直连递归 DNS(默认) |
| `doh` | DNS-over-HTTPS(需 `doh-server`) |
| `dot` | DNS-over-TLS(需 `dot-server`) |

```yaml
dns:
  enable: true
  listen: ":53"
  mode: doh
  doh-server: "https://cloudflare-dns.com/dns-query"
  dot-server: "1.1.1.1:853"
  fake-cidr: "198.18.0.0/15"   # FakeDNS 网段(与 TUN CIDR 重叠)
```

**机制**:收到 UDP/TCP 53 请求 → 按 mode 解析 → 返回。若 `fake-cidr` 有值,可对未命中真实解析的域名按 hash 分配一个 fake-cidr 内的地址(FakeDNS,供透明代理在无法走 SNI 时用)。

**使用步骤**:
1. `dns.enable: true`,`mode` 选一个
2. `start` 会一起拉起;或单独 `agent-netx dns`
3. 本机或 App 把 DNS 改成 `127.0.0.1:53`,即可走代理出去
4. TUN 模式下 `dns.dns: 198.18.0.2` 会把虚拟网卡的 DNS 指向本地

### 3.7 Web 仪表盘

```yaml
web:
  enable: true
  port: 9090
  username: ""
  password: ""
```

**机制**:起 HTTP server,暴露 `/api/stats`(REST 端点,返回流量/连接统计)和基础 UI。流量统计由 `Listener.Options.Stats` 接的 `web.StatsTracker` 提供:每个 relay 连接包一层 `statsConn`,读=下载,写=上传,双向累加并跟踪活跃连接数,业务代码零改动。

**使用步骤**:
1. `web.enable: true`,`port` 设一个未被占用的端口
2. `start` 或单独 `agent-netx web`
3. 浏览器打开 `http://127.0.0.1:9090` 看面板;`http://127.0.0.1:9090/api/stats` 拿 JSON

### 3.8 MITM HTTPS 拦截(重要)

**默认关闭**。只拦截白名单(host allowlist)命中的连接。

```yaml
mitm:
  enable: false
  ca-path: "ca.crt"          # 根 CA 证书路径(首次会自动签发)
  cert-dir: "certs"           # 为每个 host 签发的动态证书目录
  http-port: 8081             # MITM 独立监听端口
  allowlist:
    - DOMAIN,example.com
    - DOMAIN-SUFFIX,.example.com
    - IP-CIDR,10.0.0.0/8
  skip-hosts:                 # 即使命中 allowlist 也永不拦截
    - DOMAIN,vault.internal
  verify-upstream: false      # 默认不校验上游真实证书(兼容自签内部主机)
```

**安全红线(三条同时成立)**:
1. `enable: false` 默认关闭,listener 根本不起
2. allowlist 为空 → 即使 `enable: true` 也不拦截
3. 只有 allowlist 命中且未被 `skip-hosts` 排除的 host 才被拦截

**机制**:CONNECT 路径下由 `MITMHandler.ShouldIntercept(host)`(走 `MatchAllow`)+ `SkipHosts` 判定;TProxy 路径下由 `ShouldInterceptIP(ip)` 对原始目的 IP 判定;`SkipHosts` 为两者共用安全阀。

**使用场景**:某 App 写死域名、不读系统代理;需要在局域网出口做 HTTPS 内容检查。

**原理图**:
```
[App]──HTTPS──► [MITM 监听 8081]──TLS终止──► [明文 HTTP 读首包]──重加密──► [真实上游]
                (按 allowlist 签发 per-host 证书)       (SNI=host)
```

**使用步骤**:
1. 确认 App 走不走系统代理;不走的话:
   - 方案 A:用 hosts 把 `example.com` 指向 `127.0.0.1`,`forward tls 0.0.0.0:443 127.0.0.1:8081`
   - 方案 B:WinDivert/Linux TProxy + MITM(见 §7.6 / §7.7)
2. `config.yml`:
   ```yaml
   mitm:
     enable: true
     allowlist:
       - DOMAIN,example.com
   ```
3. `agent-netx start -c config.yml` 自动生成 `ca.crt`
4. 把 `ca.crt` 装进系统/浏览器信任根
5. 用 `--no-proxy localhost,127.0.0.1` 防止 CA 安装本身走代理

### 3.9 n2n 虚拟局域网 (P2P VPN)

```
 Supernode (公网服务器)
   ┌─────────────────┐
   │  IP 分配        │
   │  节点发现        │
   │  NAT 打洞协调    │
   └──────┬──────────┘
          │
    ┌─────┴─────┐
    ▼           ▼
 ┌──────┐   ┌──────┐
 │ Edge │◄──│ Edge │  ← P2P 直连(打洞成功后)
 │ A    │   │ B    │
 └──────┘   └──────┘
```

配置:

```yaml
n2n:
  enable: true
  mode: "supernode"             # "supernode" 或 "edge"
  listen: ":7654"
  supernode: "1.2.3.4:7654"    # edge 模式下指定 supernode 公网地址
  community: "net-redirect"
  password: ""                  # AES-256-GCM 加密密码(可选)
  virtual-cidr: "10.200.0.0/16"
  mtu: 1400
  interval: 30                  # 心跳间隔(秒)
```

**机制**:Supernode 分配虚拟 IP、协调节点发现 + NAT 打洞;Edge 与 Supernode 长连接保持心跳,收到来自其它 Edge 的数据直接 P2P 或经 Supernode 中继;`password` 用 AES-256-GCM 加密。

**使用步骤**:
1. 公网服务器:建一个 `mode: supernode` 的实例,`start` 跑起来
2. 每个客户端:`mode: edge`,`supernode: <公网:端口>`,与 supernode 相同的 `community` / `password`
3. 各自启动后互相 ping 对端的虚拟 IP
4. `tun.enable: true` 时自动把 TUN 接到 n2n 上

### 3.10 STUN/TURN 虚拟局域网 (标准协议 VPN)

与 n2n 不同,`stunvpv` 走**标准协议**(RFC 5389 STUN + RFC 5766 TURN),所有数据默认经 TURN 中继(不依赖 NAT 打洞)。

**原理图**:
```
 ┌──Client A──┐              ┌──Client B──┐
 │ 10.201.0.10│◄───TURN中继──►│ 10.201.0.11│
 └─────┬──────┘              └─────┬──────┘
       │                           │
       └────────┬──────────────────┘
                ▼
      ┌────────────────────┐
      │ TURN Server(公网)   │
      │ listen :3478        │
      │ realm + 用户名密码  │
      └────────────────────┘
```

配置:

```yaml
stunvpv:
  enable: true
  mode: "supernode"               # "supernode" 或 "client"
  listen: ":3478"
  turn-server: "1.2.3.4:3478"    # client 模式下指定 TURN 地址
  realm: "net-redirect"
  username: "vpn-user"
  password: "vpn-pass"
  virtual-cidr: "10.201.0.0/16"
  mtu: 1400
```

**机制**:Supernode 起 STUN/TURN 服务器;Client 向 TURN 申请分配地址、鉴权后通过 TURN 中继收发包。数据默认走 TURN,不依赖 NAT 打洞。

**使用步骤**:
1. 起一个 `mode: supernode`(TURN 服务器)的实例
2. 每个 Client:`mode: client`,`turn-server` 指向 TURN 地址,配 `realm/username/password`
3. 启动后获得虚拟 IP,`ping <对端虚拟IP>` 即通
4. `tun.enable: true` 时自动桥接

### 3.11 WireGuard P2P VPN

标准 WireGuard 协议(DH + ChaCha20-Poly1305),实现 `tunnel.Peer` 接缝,可自动桥接到 TUN。

**原理图**:
```
[App]──► [TUN (wintun)/dev/net/tun]──► [WireGuard Peer]──UDP:51820──► [对端 WireGuard Peer]──► [TUN]──► [App]
         收到 dst 为对端虚拟 IP 的包     加密(DH+ChaCha20-Poly1305)             解密                      写回内核
```

配置:

```yaml
wireguard:
  enable: true
  private: ""                     # 64-hex 私钥(空 = 自动生成)
  public: ""                      # 对端公钥(64-hex)
  preshared: ""                   # 可选 PSK
  listen: ":51820"
  peer-addr: "1.2.3.4:51820"     # 对端 UDP 地址
  virtual-ip: "10.0.0.2"
  keepalive: 25                   # keepalive 间隔(秒)
  handshake: 25                   # 握手超时(秒)
```

**机制**:两端各持私钥 + 对端公钥,UDP:51820 跑 WireGuard 握手(DH key exchange),数据用 ChaCha20-Poly1305 加密。`tunnel.Peer` 接缝把 WireGuard 接到 TUN 或 agent 内部流量。

**使用步骤**:
1. 两端各自跑一次 `agent-netx wireguard --no-tun`,把输出的 64-hex 公钥抄下来
2. 各自填 `config.yml` 的 `wireguard:` 段,`peer-addr` 填对方 UDP 地址,`public` 填对方公钥
3. `tun.enable: true` + `wireguard.enable: true`
4. 两边 `start`,`ping <对端虚拟IP>` 即通
5. 单独 `agent-netx wireguard` 可脱离整体跑;`--no-tun` 只测 UDP 通道,不接 TUN

### 3.12 Tinc P2P VPN

轻量级 P2P VPN,ed25519 加密,配置在 CLI flag(不进 config.yml):

```powershell
agent-netx tinc --private <hex> --name node-a --ca <hex> --listen :655 \
  --endpoint 1.2.3.4:655 --vip 10.0.0.2 --keepalive 25
```

- `--private`:私钥(64-hex)
- `--name`:节点名(节点间识别)
- `--ca`:CA 公钥
- `--endpoint`:对端 `<addr>:<port>`(可重复)
- `--vip`:虚拟 IP
- `--listen`:UDP 监听地址(默认 `:655`)
- `--keepalive`:keepalive 间隔秒数(默认 25)

**使用步骤**:
1. 两端各自生成 ed25519 密钥对
2. 各自指定对方 CA / endpoint / 自己的 vip
3. 两边启动,`ping <对端 vip>`

### 3.13 Agent (LLM) 配置

**推荐**放在独立的 `agent.yml`(与 `config.yml` 同目录),不放进 `config.yml` 的 `agent:` 段(`config.yml` 里的 `agent:` 是兼容旧配置的 fallback)。

```yaml
# agent.yml
base-url: "https://api.openai.com/v1"
api-key: ""                     # 或设环境变量 AGENT_API_KEY
model: "gpt-4o-mini"
# timeout: 120                  # 每次请求超时(秒,默认 120)
# max-retries: 3                # 429/5xx 重试次数(默认 3)
# memory-path: ""               # 持久化记忆文件路径
# system-prompt: ""             # 自定义系统提示
```

### 3.14 语义校验

```powershell
agent-netx validate -c config.yml
```

**机制**:加载 `Config`,跑 `Validate()`,检查 mode 合法性、端口范围(0..65535)、代理类型合法性、分组类型合法性、分组/代理引用、CIDR 可解析性等,返回每条问题一行的错误列表。

---

## 4. 代理协议详解

### 4.1 代理接口

所有代理统一实现 `proxy.Proxy`:

```go
type Proxy interface {
    Name() string
    Connect(ctx, addr) (net.Conn, error)   // TCP 拨号
    Latency(url) (time.Duration, error)     // 测速
    Close() error
}

type PacketProxy interface {
    ConnectUDP(ctx) (net.PacketConn, error) // UDP(SOCKS5 UDP ASSOCIATE)
}
```

新增一个代理协议 = 实现这两个接口 + 在 `proxy/registry.go` 的 `NewProxy` 里注册一个 case。

### 4.2 代理链式 (Chain)

```yaml
- name: hop
  type: chain
  proxies: [ss-1, trojan-1]   # ss-1 → trojan-1 → 目标
```

**机制**:`Connect` 逐段拨号:先经 p[0] 连到 p[1] 的服务器,再由 p[1] 连到目标。链本身也是 `Proxy`,可被规则 / 分组 / `--proxy` 引用。

**使用步骤**:配置 `type: chain` 分组,`proxies` 按顺序写多个代理名,即可当作普通代理使用。

### 4.3 VLESS + Reality

Reality 让 TLS 握手看起来像真实浏览器(**Chrome/Firefox/iOS/Edge/Random 的 ClientHello**),绕过 SNI / JA3 指纹封锁。

**原理图**:
```
[App]──► [agent-netx]──► VLESS+Reality 拨号
                              │
                          TLS 握手(uTLS 指纹伪装 Chrome)
                              │
                          X25519(带 public-key / short-id 认证)
                              │
                              ▼
                         [上游 Reality 服务端]
                              │
                              ▼
                           [外网]
```

配置:

```yaml
- name: vless-reality
  type: vless
  server: example.com
  port: 443
  uuid: 你的-uuid
  public-key: 服务器curve25519公钥(base64url,43字符)
  short-id: 8位hex
  fingerprint: chrome      # chrome / firefox / ios / edge / random
  sni: example.com
```

**机制**:
- `fingerprint` 为空 → 走 Go 标准 `crypto/tls`
- `fingerprint` 非空 → 走 **uTLS 指纹**路径,配合 `public-key`/`short-id` 做 X25519 密钥交换认证

**使用步骤**:
1. 拿到上游提供的 `uuid` / `public-key` / `short-id` / `server:port` / `sni`
2. 按 §3.2 表填 `type: vless`,`fingerprint: chrome`
3. 走一个分组或直接走规则

### 4.4 协议对比速查

| 协议 | 加密 | 伪装 | 指纹 | UDP | 适用 |
|------|------|------|------|-----|------|
| http | 无 | 无 | 无 | — | 简单中转 |
| https | TLS | HTTPS | 有(标准) | — | 加密代理 |
| socks5 | 可选认证 | 无 | 无 | ✅ UDP ASSOCIATE | 万能代理 |
| ss | AES/ChaCha20 | 无 | 无 | — | 轻量加密 |
| trojan | TLS | HTTPS | 有(标准) | — | 伪装 HTTPS |
| vmess | AEAD | 无 | 有 | — | 兼容 clash/v2ray |
| vless | 无(走 TLS) | Reality | uTLS 指纹 | — | 绕过 JA3 封锁 |
| forward | 透传 | 透传 | 透传 | — | 桥接已有代理 |
| http3 | QUIC | 无 | 无 | ✅ | QUIC 代理 |

---

## 5. 路由模式

| mode | 行为 |
|------|------|
| `direct` | 全部直连,不走代理 |
| `global` | 全部走 `proxies` 列表第一个(或分组第一个) |
| `rule` | 按 `rules` 顺序匹配(默认) |

`rules` 从上到下匹配,`MATCH` 兜底。

**机制**:`Router.Pick(addr)` 按 mode 走对应分支;`rule` 模式下逐条 `Rule` 匹配 host/port,首条命中返回 target;`AddRule` 运行时可在开头插入规则(动态生效)。

---

## 6. 命令完整手册

> 全局 flag:`-c/--config <path>` 指定配置文件(默认当前目录 `config.yml`)。
>
> **平台图例**(下文每节开头出现):
> - 🌐 全平台:linux-amd64 / linux-arm64 / darwin-amd64 / darwin-arm64 / windows-amd64 / windows-arm64
> - ⚠️ 提权:需要 Administrator(Windows)或 root(UNIX)
> - 🪟 WinDivert:Windows 需自动装 WinDivert64.sys 驱动
> - 🐧 iptables:Linux 需用户自建 iptables TPROXY 规则

### 6.1 基础命令

| 命令 | 作用 |
|------|------|
| `agent-netx init` | 生成 `config.yml` + `agent.yml` 到当前目录 |
| `agent-netx start -c config.yml` | 完整模式:所有 `enable: true` 的子服务一起拉起 |
| `agent-netx start --proxy ss://...` | 快速模式:URL 直起代理监听,跳过 config |
| `agent-netx status` | 显示当前 config.yml 内容 |
| `agent-netx validate -c config.yml` | 语义校验 config |
| `agent-netx logs [--tail n] [--follow]` | 读共享日志文件 |
| `agent-netx stop <name\|all>` | 通过 PID 文件跨进程停某个子服务 |
| `agent-netx restart <name\|all>` | 停 + 起 |
| `agent-netx use <分组> <代理>` | 切换 `selector` 分组的默认代理(写回 config.yml) |

**平台**:🌐 全平台。

**`start --proxy <url>` 支持的 URL 形式**:
- `ss://aes-256-gcm:password@server:8388`
- `http://user:pass@server:443`
- `https://user:pass@server:443`
- `socks5://user:pass@server:1080`
- `trojan://password@server:443?sni=example.com`

**机制**:快速模式监听端口取 config.yml(若无配置则默认 7890/7891),只解析 URL 起对应代理,跳过所有其它子系统。

### 6.2 独立子服务

🌐 全平台。`--no-tun` 仅用于 `tun/n2n/stunvpv/wireguard`(跳过 TUN 桥接,只测 UDP 通道)。
每个网络子服务都能脱离整体单独跑,便于排障:

```powershell
agent-netx proxy -c config.yml         # 仅代理监听(HTTP+SOCKS5)
agent-netx dns -c config.yml           # 仅本地 DNS
agent-netx web -c config.yml           # 仅 Web 仪表盘
agent-netx tun -c config.yml           # 仅 TUN 设备
agent-netx n2n -c config.yml           # 仅 n2n 节点
agent-netx stunvpv -c config.yml       # 仅 STUN/TURN 节点
agent-netx wireguard -c config.yml     # 仅 WireGuard 节点
agent-netx wireguard --no-tun          # 仅测 UDP 通道,不接 TUN
agent-netx n2n --no-tun                # 仅中继/测试,不接 TUN
agent-netx stunvpv --no-tun            # 仅中继/测试,不接 TUN
agent-netx frp server [port]           # FRP 服务端
agent-netx frp client <local> <remote> --server <addr>  # FRP 客户端
agent-netx tinc --private ... --endpoint ...  # Tinc 节点(纯 CLI flag)
agent-netx corsproxy --port 8080       # CORS 代理
```

### 6.3 端口转发 (forward)

🌐 全平台。`remote` 模式两边都需 SSH 可达。SSH 同款 6 种模式,`--proxy <name>` 让"目标拨号"走配置文件里指定的代理(不指定则直连):

**原理图**:
```
local:      [App]──► [listen]──► [dial dst]
remote:     [remote SSH 主机]──► [本机 listen]──► [本机 dial dst]
dynamic:    [App(SOCKS5)]──► [listen]──► [Socks5 客户端选目标]
udp:        [App]──► [listen UDP]──► [dial dst UDP]
tls:        [App]──HTTPS──► [listen TLS]──TLS终止──► [明文 dial dst]
reverse:    [外部请求]──► [listen]──HTTP reverse proxy──► [target]
```

| 模式 | 命令 | 含义 | 场景 |
|------|------|------|------|
| `local` (-L) | `forward local <listen> <dst>` | 本地监听 → 固定目标 | 把远程数据库端口暴露到本机 |
| `remote` (-R) | `forward remote <sshAlias> <rListen> <dst>` | SSH 主机上开监听 → 本机目标 | 从公网回连内网开发机 |
| `dynamic` (-D) | `forward dynamic <listen>` | 本地 SOCKS5 监听 → 任意目标 | 临时 SOCKS5 代理 |
| `udp` (-U) | `forward udp <listen> <dst>` | 本地 UDP 监听 → 固定 UDP 目标 | 把 DNS 经代理出去(需 `--proxy` 是 SOCKS5) |
| `tls` | `forward tls <listen> <dst> [sni]` | HTTPS 监听 → 明文 HTTP 后端 | MITM/流量观察 |
| `reverse` | `forward reverse <listen> <target>` | HTTP 反向代理:本地端口 → 固定上游 | 把内网服务暴露到公网 |

**机制**:
- `local/remote/udp/reverse`:直接建立 TCP/UDP 通道,`--proxy <name>` 让 dial 目标时走配置文件里指定的代理
- `remote`:额外通过 SSH `ssh.Client.Listen` 在对端开监听,复用 scp 的 host resolution + 凭据记忆 + HIL 交互
- `tls`:在 listen 端跑 TLS server,把 SNI(可选)传给拨号方
- `dynamic`:起一个本地 SOCKS5 监听,充当临时 SOCKS5 代理

**注意**:`--proxy` 在 UDP 模式下指定的代理必须实现 `PacketProxy`(目前仅 SOCKS5 支持 UDP ASSOCIATE);若用非 SOCKS5 代理会明确报错。

**使用步骤**(以 `local` 为例):
1. 确定 `<listen>`(本机监听地址)和 `<dst>`(要连的远端地址)
2. 起:
   ```powershell
   agent-netx forward local 127.0.0.1:3306 db.internal:3306
   ```
3. 应用改连 `127.0.0.1:3306` 即连到 `db.internal:3306`
4. 如想走代理出去,加 `--proxy <代理名>`

**其他模式示例**:

```powershell
agent-netx forward local 127.0.0.1:3306 db.internal:3306 --proxy prod-ss
agent-netx forward remote prod :9090 127.0.0.1:8080
agent-netx forward dynamic 1080
agent-netx forward udp 127.0.0.1:1053 1.1.1.1:53 --proxy prod-socks5
agent-netx forward tls 0.0.0.0:443 127.0.0.1:80
agent-netx forward reverse :8080 https://internal.example.com:9090
```

### 6.4 socat(TCP/UDP 双向中继)

🌐 全平台。纯 socket,零依赖。**不需要配置文件**,纯命令行。端点用 socat 风格地址:

| 端点形式 | 语义 |
|---------|------|
| `TCP-LISTEN:8080` | 监听全部接口 8080 |
| `TCP-LISTEN:127.0.0.1:8080` | 绑定指定地址 |
| `TCP:127.0.0.1:9000` | 拨号 TCP 服务端 |
| `UDP-LISTEN:53` | 监听 UDP 53 |
| `UDP:8.8.8.8:53` | 拨号 UDP 服务端 |
| `host:port` | 裸地址按 TCP 处理 |

```powershell
agent-netx socat TCP-LISTEN:8080 TCP:127.0.0.1:9000          # 端口转发
agent-netx socat UDP-LISTEN:5353 UDP:8.8.8.8:53              # UDP 转发(如 DNS)
agent-netx socat TCP-LISTEN:2222 TCP:127.0.0.1:22 -v         # 逐连接日志
agent-netx socat TCP-LISTEN:8080 TCP:10.0.0.1:80 -W 5s       # 拨号超时 5s
```

**原理图(TCP)**:
```
[Client A]──TCP──► [TCP-LISTEN]──► bidirectional pump ◄──► [TCP:dst]──► [Client B]
                    双向读写字节流                                    字节流
                    StatsTracker 双向计数
```

**原理图(UDP 按客户端会话)**:
```
[Client A]──UDP──► [UDP-LISTEN]──► [session A: 已连接至 dst]──► [Client B]
[Client B']──UDP──► [UDP-LISTEN]──► [session B: 已连接至 dst]──► [Client B]
                    每个客户端独立会话,各持一个已连接的远端 UDP Socket
                    非阻塞入队,队列满则丢弃
```

**机制**:
- **TCP**:listener 接受连接 → dial 目标 → 双向 pump 直到任一侧 EOF;有连接数 / 收发字节统计
- **UDP**:**按客户端会话架构** —— `udpSessions` 以 peer 地址为键,每个 session 持一个**已连接**的远端 UDP Socket(DialContext 返回 `net.Conn`,天然过滤回包),listener 保持**未连接**以接受多个客户端;每 session 独立 inbox channel,非阻塞入队,队列满则丢包

**使用步骤**:
1. 想转发 TCP:
   ```powershell
   agent-netx socat TCP-LISTEN:<本机端口> TCP:<目标地址>:<目标端口>
   ```
2. 想转发 UDP(如 DNS):
   ```powershell
   agent-netx socat UDP-LISTEN:5353 UDP:8.8.8.8:53
   ```
3. Ctrl-C 退出时关闭监听与所有在途连接,打印统计

### 6.5 FRP(fast reverse proxy)

🌐 全平台。纯 TCP,server 在公网,client 在内网。轻量级 FRP 实现,server / client 两角色:

**原理图**:
```
[Client 本地服务 :8080]──► [frp client]──UDP/TCP────[frp server :7000]──► [访问者连 frp server :9090]
```

**命令**:

```powershell
# 服务器端
agent-netx frp server [7000] --secret xxx --target 127.0.0.1

# 客户端(把本地 8080 暴露成服务器端 remote-port)
agent-netx frp client 8080 9090 --server 1.2.3.4:7000 --secret xxx
```

- `server`:监听端口(默认 7000),`--secret` 共享密钥,`--target` 回连地址(默认 127.0.0.1)
- `client`:本地端口 / 远端端口 / `--server <addr>:<port>` / `--secret`

**使用步骤**:
1. 在公网机器起 `frp server`
2. 在本地机器起 `frp client 8080 9090 --server <公网>:7000`
3. 访问者连 `<公网>:9090` 即连到本地 8080

### 6.6 CORS 代理

🌐 全平台。纯 HTTP server。**场景**:浏览器跨域请求被 CSRF/预检阻断,临时绕行。

```powershell
agent-netx corsproxy --port 8080
# 然后浏览器访问 http://127.0.0.1:8080/proxy?dest=https://target.example.com/...
```

**机制**:HTTP server,把所有响应加 CORS 头(`Access-Control-Allow-Origin: *` 等),转发请求到 `dest` URL。

### 6.7 系统代理一键开关 (sysproxy)

🌐 全平台。Windows 写注册表 + netsh winhttp;Linux 走 `gsettings`(纯服务器环境 / 无桌面可能失败),同时写 `~/.proxy.env` 供无桌面环境回读。**原理图**:
```
[浏览器 / App]──系统代理设置──► [agent-netx HTTP 监听 :7890]──► 上游代理 / 直连
         ▲                                   │
         │                                   ▼
    注册表 / gsettings             sysproxy on/off 写入
```

**命令**:
```
agent-netx sysproxy on          [http://127.0.0.1:7890] [--no-proxy host,host]
agent-netx sysproxy off
agent-netx sysproxy status
```

| 平台 | 实际写入 |
|------|---------|
| Windows | 注册表 `HKCU\...\Internet Settings` + `netsh winhttp` |
| Linux | `gsettings org.gnome.system.proxy` + `~/.proxy.env` |

**机制**:
- `on`:把指定代理地址写进系统级代理设置(不带地址时默认取 config.yml 的 HTTP 监听端口);`--no-proxy` 写进排除列表
- `off`:清除系统代理设置
- `status`:打印当前系统代理

**使用步骤**:先 `start -c config.yml` 起代理,再 `sysproxy on`,所有走系统代理设置的 App(浏览器等)即走 agent-netx。

### 6.8 ping(hping3 风格)

🌐 全平台。⚠️ `-1`(ICMP) / `--flood` / `--traceroute` 需 Administrator 或 root(raw socket);`-S` TCP / `-2` UDP 模式无权限要求。

**不需要配置文件**。三种模式 + traceroute,与 hping3 对齐:

```
agent-netx ping <host> [--mode icmp|tcp|udp] [--count n] [--port p]
                    [--interval <num>u|ms|s] [--data-size n]
                    [--interface eth0] [--verbose] [--flood]
                    [--traceroute [--hops n]] [--timeout 1s] [--spoof <ip>]
```

模式(hping3 简写):
- `-1, --icmp`  ICMP echo(需要管理员/raw socket)
- `-S, --tcp`  TCP connect(无权限要求)
- `-2, --udp`  UDP probe(无权限要求)
- 默认 ICMP

**注意**:根命令的 `-c` 与 `--config` 冲突,所以 count 只能用 `--count`,不能用 `-c`。

**机制**:ICMP 用 raw socket(`ip4:icmp`),TCP/UDP 用普通 TCP/UDP 拨号。traceroute 按 `--hops` 数量递增 TTL。

**使用步骤**:
```powershell
agent-netx ping 8.8.8.8                              # ICMP,无限(直到 Ctrl-C)
agent-netx ping -1 8.8.8.8 --count 4                 # 4 次 ICMP
agent-netx ping -S -p 80 example.com                 # TCP 80 端口探测
agent-netx ping -2 -p 53 8.8.8.8 --count 3           # UDP 53
agent-netx ping -1 8.8.8.8 --traceroute --hops 20    # traceroute
agent-netx ping -1 8.8.8.8 -i u100000                # 100ms 间隔(微秒)
agent-netx ping -1 8.8.8.8 -I eth0                   # 指定网卡
agent-netx ping -1 8.8.8.8 --flood                   # flood(管理员)
```

### 6.9 网络诊断 (netdiag) — 等价 netstat / ss / tcpdump

```
agent-netx netdiag <conns|listeners|packets|stats|interfaces|routes|proto|fd>
```

🌐 全平台。⚠️ `packets` 子命令需 Administrator 或 root(`CAP_NET_RAW`);其余子命令无权限要求。

**原理图**:
```
[App / 内核]──net_connections 列表──► [gopsutil v3/net]──► [分组 + 过滤]──► 输出
              raw 抓包                 raw socket ip4:tcp/udp   ──► [tcpdump 格式]
              DNS / 路由 / FD         lsof / os / ip cmd        ──► [stats/ifaces/routes/fd]
```

| 子命令 | 等价 | 说明 |
|--------|------|------|
| `conns` | `netstat -an` / `ss -tuan` | 所有连接(按状态分组,附进程名/PID) |
| `listeners` | `ss -tlnp` | 监听端口 |
| `packets` | `tcpdump` | 抓包(**需要管理员权限**) |
| `stats` | `ss -s` | 聚合统计 |
| `interfaces` | `ip -s link` | 接口 + IO 地址 |
| `routes` | `netstat -r` | 路由表 |
| `proto` | `netstat -s` | 协议统计 |
| `fd` | `lsof -p` | 进程 FD |

**机制**:
- `conns/listeners/stats/interfaces/routes/proto` 走 `github.com/shirou/gopsutil/v3/net` 读取内核态
- `packets` 用 raw socket(`net.ListenPacket("ip4:tcp")` 等),需要管理员/root(`CAP_NET_RAW`)
- 全部**零 cgo,可交叉编译**

**过滤参数**:`--proto tcp\|udp\|raw\|unix\|all`、`--port n`、`--pid n`、`--state established\|listen\|time-wait...`、`--src`、`--dst`、`--count`、`--timeout`。

**使用步骤**:
```powershell
agent-netx netdiag conns --proto tcp --port 8080
agent-netx netdiag conns --src 10.0.0.5 --dst 1.2.3.4
agent-netx netdiag listeners
agent-netx netdiag packets --count 30 --timeout 15
agent-netx netdiag packets --proto tcp --port 80
agent-netx netdiag stats
agent-netx netdiag interfaces
agent-netx netdiag routes
agent-netx netdiag fd --pid 1234
```

### 6.10 文件拷贝 (scp)

🌐 全平台。依赖 SSH 可达,零系统依赖。

复用 agent 的 SSH 凭据记忆,HIL 交互询问缺失信息:

```powershell
agent-netx scp --action upload --alias prod --src ./app.log --dst /var/log/app.log
agent-netx scp --action download --alias prod --src /var/log/app.log --dst ./
agent-netx scp --action upload --host 10.0.0.5 --user root --src f.bin --dst /tmp/f.bin
```

**机制**:通过 SSH session 用 SFTP / `cat` pipe 拷贝,复用 scp 底层(与 TUI 的 `file_copy` 工具同代码)。首次用 `--host` 直连,缺字段会终端询问;`--alias prod` 会写入 `~/.agent-netx/memory.json`,下次免输。

### 6.11 执行命令 (run)

🌐 全平台。`local` 走 `cmd.exe /c`(Windows)或 `/bin/sh -c`(Linux/macOS);`remote` 依赖 SSH 可达。

本地 / 远端执行一条 shell:

```powershell
agent-netx run local --cmd "whoami"
agent-netx run remote --alias prod --cmd "cd /opt && ./agent-netx start"
agent-netx run remote --host 10.0.0.5 --user root --password xxx --cmd "whoami"
```

**机制**:
- `local`:`cmd.exe /c`(Windows)或 `/bin/sh -c`(Linux/macOS)
- `remote`:通过 SSH session 执行,复用 agent `ResolveHost`(alias → memory → HIL 交互);首次缺失字段会终端询问并记忆

**使用步骤**:
1. 本地:直接 `run local --cmd "..."`
2. 远端:
   - 已记住的别名:`run remote --alias prod --cmd "..."`
   - 首次:`run remote --host <addr> --user <u> --password <p> --cmd "..."`,后续用 `--alias` 即可

### 6.12 日志 / 启停

🌐 全平台。基于 PID 文件,跨进程停/起子服务。

```powershell
agent-netx logs [--tail 100] [--follow]    # 读共享日志文件,--follow 类似 tail -f
agent-netx stop <name|all>                  # 通过 PID 文件跨进程停子服务
agent-netx restart <name|all>               # 停 + 起
```

**机制**:每个子服务启动时在固定位置写 PID 文件;`stop/restart` 按名读 PID、发信号终止,然后 `restart` 再起。

### 6.13 LLM Agent + TUI

🌐 全平台。Windows 用 `mwindows` + `syscall`(伪控制台);Linux/macOS 用 `termios`。底层终端适配由 build tag 区分,命令集完全一致。

```powershell
agent-netx tui                            # 新会话
agent-netx tui --continue <id\|name>      # 续写某会话
agent-netx tui --agent-config agent.yml   # 指定 agent 配置
```

**TUI 可用 Agent 工具**(全部用自然语言触发):

| 工具 | 作用 |
|------|------|
| `get_config` | 读取当前完整配置 |
| `update_config` | 用完整新 YAML 覆写 |
| `gen_config` | 从结构化 spec 生成完整可用配置 |
| `ping_proxies` | 测试所有代理延迟 |
| `switch_group` | 切 `selector` 分组 |
| `add_rule` | 开头插入一条规则(运行时动态生效,写入 `~/.agent-netx/dynamic.yml`) |
| `add_proxy` | 运行时新增代理(写入 `~/.agent-netx/dynamic.yml`) |
| `service` | 起/停/看单个子服务 |
| `list_commands` | 列所有 CLI 子命令 |
| `sysproxy` | 系统代理 on/off |
| `init` | 生成示例配置 |
| `run_local` / `run_remote` | 本地/远端执行 shell |
| `file_copy` | 上传/下载单个文件(复用 scp 底层) |
| `net_connections` / `net_listeners` | 网络诊断(连接/监听) |
| `net_ping` | ping 探测 |
| `net_packets` | 抓包(需要管理员) |
| `session_list` / `session_load` / `session_save` | 会话管理 |

**TUI 内置 `/xxx` 快捷命令**(TAB 自动补全):

```
/init · /status · /ping · /use · /sysproxy · /start · /proxy · /dns · /web
/tun · /n2n · /stunvpv · /wireguard · /frp · /tinc · /socat · /corsproxy
/forward · /scp · /netdiag · /run
```

不带参数的 `/xxx` 显示该命令的简短用法;默认自动附加 `-c <当前 config 路径>`。

`/add-proxy` / `/add-rule` 写入 `~/.agent-netx/dynamic.yml` 覆盖层,运行时生效无需重启。

### 6.14 运行时覆盖层(dynamic.yml)

🌐 全平台。运行时生效无需重启。

`add_proxy` / `add_rule` 工具写到的覆盖层文件是 `~/.agent-netx/dynamic.yml`,结构:

```yaml
proxies:
  - name: dyn-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: xxx
rules:
  - DOMAIN,extra.example.com,dyn-ss
```

`MergeDynamic` 会在加载主 config 后把动态代理和规则 append 到主列表(同名代理以主 config 为准)。这避免了改主 `config.yml` 就要重启的限制。

---

## 7. 场景实战(带原理图 + 使用步骤)

### 7.1 全局代理

🌐 全平台。

**应用场景**:想让整个机器都走一个 SS/Trojan/VLESS 出去。

**原理图**:
```
[App]──HTTP/SOCKS5──► [agent-netx 监听 7890/7891]──proxy──► [上游 SS/Trojan]──► [外网]
```

**使用步骤**:
1. `config.yml` 里配 `proxies`(至少一个 SS/Trojan/VMess/VLESS)
2. `mode: global`
3. `agent-netx start -c config.yml`
4. `agent-netx sysproxy on`(让浏览器也走代理)

配置示例:
```yaml
mode: global
proxies:
  - name: ss-1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: my-secret
```

### 7.2 劫持某 App 的流量(MITM)

🌐 全平台。WinDivert / Linux TProxy 方案(方案 B)分别见 §7.6 / §7.7 的平台约束。

**应用场景**:某 App 写死域名、不读系统代理,又想透明加密转发或做内容检查。

**原理图**:
```
[App]──HTTPS──► [MITM 监听 8081]──TLS终止──► [明文 HTTP 读首包]──重加密──► [真实上游]
                (按 allowlist 签发 per-host 证书)       (SNI=host)
```

**使用步骤**:
1. 确认 App 走不走系统代理;不走的话:
   - 方案 A:用 hosts 把 `example.com` 指向 `127.0.0.1`,`forward tls 0.0.0.0:443 127.0.0.1:8081`
   - 方案 B:WinDivert/Linux TProxy + MITM(见 §7.6 / §7.7)
2. `config.yml`:
   ```yaml
   mitm:
     enable: true
     allowlist:
       - DOMAIN,example.com
   ```
3. `agent-netx start -c config.yml` 自动生成 `ca.crt`
4. 把 `ca.crt` 装进系统/浏览器信任根
5. 用 `--no-proxy localhost,127.0.0.1` 防止 CA 安装本身走代理

### 7.3 多代理自动选最快 + 故障切换

🌐 全平台。

**应用场景**:有两条代理线路,想自动选最快,挂了自动切换。

**原理图**:
```
[App]──► [agent-netx]──► Router 按 rules 匹配 → 命中 Auto 分组
                                      │
                              ┌───────┴───────┐
                              ▼               ▼
                          Auto(url-test)    Fallback(failover)
                            │                  │
                      每 5 分钟测速        按序尝试,首个失败切下条
                      选最快 ss-1
                              │
                              ▼
                          [上游]──► [外网]
```

**使用步骤**:
1. 配多个同用途代理
2. 建一个 `url-test` 分组
3. `rules` 让流量走 Auto

```yaml
proxies:
  - name: ss-1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pass1
  - name: ss-2
    type: ss
    server: 5.6.7.8
    port: 8388
    cipher: aes-256-gcm
    password: pass2
proxy-groups:
  - name: Auto
    type: url-test
    proxies: [ss-1, ss-2]
    url: https://www.gstatic.com/generate_204
    interval: 300
    default: ss-1
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Auto
```

### 7.4 VLESS + Reality 翻墙(防封锁)

🌐 全平台。

**应用场景**:被网络方以 JA3 指纹 + SNI 联合封锁,需要伪装成真实浏览器。

**原理图**:
```
[App]──► [agent-netx]──► VLESS+Reality 拨号
                              │
                          TLS 握手(uTLS 指纹伪装 Chrome)
                              │
                          X25519(带 public-key / short-id 认证)
                              │
                              ▼
                         [上游 Reality 服务端]
                              │
                              ▼
                           [外网]
```

**使用步骤**:
1. 拿到上游提供的 `uuid` / `public-key` / `short-id` / `server:port` / `sni`
2. 按 §3.2 表填 `type: vless`,`fingerprint: chrome`
3. 走一个分组或直接走规则

### 7.5 跨 NAT 组网:n2n 虚拟局域网

🌐 全平台。

**应用场景**:家里/办公室几台机器想互通内网、团队临时内网。

**原理图**:
```
     Supernode(公网)
        ┌──────────┐
        │IP 分配   │
        │节点发现   │
        │NAT 打洞  │
        └────┬─────┘
          ┌──┴──┐
          ▼     ▼
       ┌────┐ ┌────┐
       │A   │ │B   │   ← 打洞成功后 P2P 直连,失败则经 Supernode 中继
       └────┘ └────┘
        10.200.0.2 10.200.0.3
```

**使用步骤**:
1. 公网服务器:
   ```yaml
   n2n:
     enable: true
     mode: "supernode"
     listen: ":7654"
     community: "my-team"
     password: "team-secret"
   ```
   `agent-netx start -c config.yml`
2. 各客户端(替换 supernode 地址):
   ```yaml
   n2n:
     enable: true
     mode: "edge"
     supernode: "1.2.3.4:7654"
     community: "my-team"
     password: "team-secret"
   ```
3. 各自启动,`ping 10.200.0.x`
4. 想"任意 App 无感互通":加 `tun.enable: true`

### 7.6 Windows 透明代理 (WinDivert TProxy)

🪟 ⚠️ Windows 专属。需 Administrator + WinDivert64.sys 驱动(首次 open 时 godivert 自动安装)。`mark/table` 为 no-op。

**应用场景**:局域网出口部署 HTTPS 内容检查;让客户端不感知地走代理。

**原理图**:
```
[LAN 客户端]──► 本机(网关)──► WinDivert(forward 层)
                                   │
                          改写:源端→127.0.0.1:<fakeP>
                                目的端→127.0.0.1:<tproxy port>
                                   │
                                   ▼
                          [tproxy 监听 :7892 (loopback)]
                                   │
                                   ▼
                          [handleTProxy]──► ShouldInterceptIP / SkipHost 决策
                                   │
                              ┌────┴────┐
                              ▼         ▼
                          命中 allowlist  未命中
                              │         │
                              ▼         ▼
                          MITM 解密   直连目标(透明放行)
```

**机制**:
- WinDivert 挂在 `LayerNetworkForward`,只看到"经过本机转发的流量"(LAN 客户端当网关时)
- `filter: "forward and outbound and ip and !impostor and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)"`
- **双向全 NAT 到 loopback**:源端改为 `127.0.0.1:<fakeP>`(40000..59999 端口池),目的端改为 `127.0.0.1:<tproxy port>`。回复走原生 loopback 路径,零翻译
- `Accept` 严格按 fake 端口池 + conntrack 查找判定;未知/陈旧/越界 → close(与 Linux fail-closed 对齐)
- `mark/table`(Linux fwmark)在 Windows 是 no-op
- **安全红线**:平台文件不做拦截决策,只呈现原始目的给 `handleTProxy`,由 `ShouldInterceptIP/SkipHost` 判定(与 Linux 路径一致)

**使用步骤**:
1. `config.yml`:
   ```yaml
   listen:
     tproxy: 7892
   mitm:
     enable: true
     allowlist:
       - DOMAIN,example.com
   ```
2. 本机设置为 LAN 客户端的**默认网关**
3. **以 Administrator 身份** 运行 `agent-netx start -c config.yml`
4. 首次 open 时 godivert 自动安装 WinDivert64.sys 驱动
5. LAN 客户端访问 example.com 即触发转发 + MITM 解密

**验证限制**:此宿主机 Windows 10 单用户桌面无法做网关,运行期需在目标机器验证。编译 / vet / 三平台交叉构建已通过。

### 7.7 Linux TProxy(防火墙级透明代理)

🐧 Linux 专属。需 root + iptables TPROXY 规则(需用户自建,与监听端口/协议相关)。

**应用场景**:在 Linux 网关上对局域网做透明代理 + MITM。

**原理图**:
```
[LAN 客户端]──► iptables PREROUTING -j TPROXY --tproxy-mark 0x1 ──►
    │                                                        │
    ▼                                                        ▼
ip rule fwmark 1 lookup 100                  [tproxy listener :7892]
    │                                                        │
    ▼                                                        ▼
ip route local table 100                       接受 IP_ORIGDSTADDR=原始目的
                                                  │
                                                 走 Proxy/MITM
```

**使用步骤**:
1. `config.yml`:`listen.tproxy: 7892` + `tproxy-mark: 1` + `tproxy-table: 100`(默认就是 1/100)
2. 本机设为 LAN 网关
3. `iptables -t mangle -A PREROUTING -p tcp -m tcp --dport 80,443 -j TPROXY --tproxy-mark 0x1 --on-port 7892`
4. `ip rule add fwmark 1 lookup 100`
5. `ip route add local default dev lo table 100`
6. `agent-netx start -c config.yml`

代码自动安装 `ip rule` + `ip route` 路由环(若 `tproxy-mark != 0`),但 `iptables` 那条用户自己配(因为 iptables 规则要区分目的端口、协议等细节)。

### 7.8 TUN 透明代理 + 组网

🌐 全平台。TUN 设备:Windows 用 `wintun`(`wintun.dll` 放程序目录),Linux/macOS 用 `/dev/net/tun`。

**应用场景**:让"任意 App 无感走代理"或"任意 App 无感访问内网对端",无需改 App 代理设置。

**原理图**:
```
┌──────┐       ┌─────────────────────────────┐       ┌──────────────┐       ┌──────┐
│App A │──────►│  TUN(wintun / tun)          │─────►│ tunnel.Peer   │─────►│ App B│
└──────┘       │  Read: 解析 IP 包 dstIP      │       │ OnData /     │       └──────┘
               │  Write: 从对端回来的 IP 包    │       │ SendTo       │
               └─────────────────────────────┘       └──────┬───────┘
                    bridgeTUN 自动桥接                        │
                    ┌──────┬──────┬──────┬──────┐           ▼
                    ▼      ▼      ▼      ▼      ▼      n2n Edge / stunvpv Client / WireGuard Peer
                  HTTP  HTTP  HTTP  HTTP  HTTP
                  代理  代理  代理  代理  代理   (任意 tunnel.Peer 实现)
```

**使用步骤**:把 `tun.enable` 和任意隧道(`n2n.enable` / `stunvpv.enable` / `wireguard.enable`)一起打开,启动即自动:
1. 创建 TUN 设备 + 设 MTU + 加路由(把 overlay CIDR 指向虚拟网关)
2. `TunDevice.SetPeer(edge|client|peer)`,把隧道接上接缝
3. `peer.OnData(func(data){ tun.WritePacket(data) })`:对端包 → 写回 TUN
4. TUN 读循环:收到真实 IP 包 → 解析 dstIP → `peer.SendTo(dstIP, data)` 发往对端

### 7.9 一键部署(在远端服务器上起 n2n/frp/wireguard)

🌐 全平台。依赖 SSH 可达。

**应用场景**:有一台公网服务器,想在上面起 n2n 中心节点或 frp 服务端,用自然语言搞定。

**原理图**:
```
                    SSH
本地 ──────────────────────────► 远端
    │                              │
    │  1. scp 传二进制 + config     │
    │  2. run_remote 起服务         │
    │  3. run_remote / logs 看状态  │
    ▼                              ▼
本地 TUI              远端 agent-netx start -c config.yml
```

**使用步骤**(在 TUI 里,用自然语言):
1. 告诉 agent 远端 SSH 主机地址/用户/密码 → `remember` 工具存到 `~/.agent-netx/memory.json`,下次 `--alias prod` 即可免输
2. `gen_config` 生成含目标模块的 `config.yml`
3. `file_copy`(复用 `scp` 底层)把 `agent-netx` 二进制 + `config.yml` 传到 `/opt/agent-netx/`
4. `run_remote --alias prod "cd /opt/agent-netx && ./agent-netx start -c config.yml"`
5. `run_remote --alias prod "agent-netx status"` 或 `logs_tail(n=20)` 看状态

CLI 等价:
```powershell
agent-netx run remote --alias prod --cmd "cd /opt/agent-netx && ./agent-netx start -c config.yml"
```

### 7.10 场景速查

🌐 各场景平台约束见对应小节开头标注。

| 想干嘛 | 用哪个 |
|-------|------|
| 全局翻墙 | §7.1 `mode: global` + `proxies` |
| 劫持某 App 做内容检查 | §7.2 `mitm` + `allowlist` |
| 自动选最快 + 故障切换 | §7.3 `url-test` + `failover` 分组 |
| 伪装真实浏览器(绕封锁) | §7.4 VLESS + Reality |
| 家里/团队内网互通 | §7.5 n2n / §7.8 TUN + n2n |
| LAN 出口透明代理 + MITM(Windows) | §7.6 WinDivert |
| LAN 出口透明代理 + MITM(Linux) | §7.7 iptables TPROXY |
| App 无感走代理 / 无感访问内网 | §7.8 TUN + 任意隧道 |
| 公网服务器起中心节点 | §7.9 `scp` + `run_remote` |
| 临时端口转发 | §6.3 `forward` |
| 临时 TCP/UDP 中继 | §6.4 `socat` |
| 内网服务暴露到公网 | §6.3 `forward reverse` 或 §6.5 `frp` |
| 系统级代理一键开关 | §6.7 `sysproxy on/off` |
| 本机连接/监听/抓包 | §6.9 `netdiag` |

---

## 8. 流量统计

`listener` 的 relay 路径自动生效:`Listener.Options.Stats` 接一个 `web.StatsTracker`,每个连接在 relay 时通过 `statsConn` 双向计数(读=下载,写=上传),同时跟踪活跃连接数。业务代码无需改动。

```
┌──────────────┐       ┌──────────────┐
│   client     │◄─────►│   remote     │
│    (statsConn)       (statsConn)    │
└──────┬───────┘       └──────┬───────┘
       │                       │
       └───────── StatsTracker ─┘
                  │
               web /api/stats
```

通过 Web 面板 `/api/stats` 或 `agent-netx netdiag stats` 查看。

---

## 9. 会话管理(TUI)

TUI 每次对话自动持久化到带 UUID 的 session 文件,退出即保存,启动可续写。

**存储位置**:`~/.agent-netx/sessions/session_<uuid>.json`。每个 session 保留最近 200 条消息。

**TUI 命令**:

| 命令 | 作用 |
|------|------|
| `/sessions` | 列出所有会话 |
| `/session <name\|id>` | 切换到某会话续写 |
| `/new [name]` | 新建会话 |
| `/rename <name>` | 重命名 |
| `/delete <name\|id>` | 删除(不能删当前) |
| `/clear` | 清空当前会话消息(保留 system) |
| `/session-export [<id>] <dst>` | 导出会话到 JSON |
| `/session-import <src>` | 从 JSON 导入 |
| `/help` | 查看命令帮助 |

`--continue` 启动参数续写:
```powershell
agent-netx tui --continue          # 续写最近一个
agent-netx tui --continue my-session
agent-netx tui --continue session_abc12345-dead-beef...
```

---

## 10. FAQ

- **端口占用**:`taskkill //F //FI "PID eq <pid>"`
- **规则不生效**:从上到下顺序匹配,第一条命中生效;`MATCH` 放最尾
- **App 不走代理**:开 `tun.enable: true` + 起隧道;或 `sysproxy on`
- **App 不走系统代理(如部分 Electron App)**:走 TUN 或 hosts + `forward tls`
- **tui 报 no api-key**:在 `agent.yml` 填 `api-key`,或 `export AGENT_API_KEY`
- **Windows TUN 启动失败**:下载 `wintun.dll` 放到程序目录
- **Windows 透明代理不生效**:必须**以 Administrator 身份**运行,首次会安装 WinDivert 驱动
- **UDP 转发要经过代理**:用 `forward udp <listen> <dst> --proxy <socks5 代理名>`,SOCKS5 的 UDP ASSOCIATE 才会接管
- **netdiag packets 抓不到包**:需要**管理员/root**身份(Windows 提权,Linux `sudo` 或 `CAP_NET_RAW`)
- **MITM 报错"empty allowlist"**:先填至少一条 allowlist 规则
- **快速模式 `--proxy` 支持的协议**:ss/http/https/socks5/trojan
- **Windows 支持 TProxy 吗**:支持,走 WinDivert(Linux 走 iptables TPROXY);见 §7.6

---

## 附录 A.全景图 & 分层速记

`docs/panorama.html` 是一个交互版的工具全景图(archify 生成,暗色/亮色主题可切换),纵轴是 TCP/IP 层,横轴是功能分组,同类命令聚在一起,LLM+Agent 用独立的 tall 列横贯所有层。配套静态分层文档在 `docs/FEATURES.md`。

> **L7 改应用,L4 转端口,L3 接网卡,协议可换,路由决定走谁,运维看面板。**

新增功能时先问"它属于哪一层":
- 改 / 拦截 App 流量 → L7
- 转发 / 监听 / 串联连接 → L4
- 虚拟网卡 / 跨 NAT 组网 → L3
- 新增一种远程代理 → 协议层(实现 `Proxy` 接口,注册一个 case)
- 决定流量去向 → 控制面
- 给人看 / 给程序调 → 运维面