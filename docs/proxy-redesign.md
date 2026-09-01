# 代理层改造方案 — mitmproxy / TPROXY / 透明代理 / eBPF(Windows)

> 参考 mitmproxy v12 的实际代码结构（`proxy/layer.py`、`commands.py`/`events.py`、
> `addons/next_layer.py`、`master.py`、`addonmanager.py`、8 种 mode spec），
> 以及本仓库已实现的 `listener/tproxy_linux.go`（Linux TPROXY 透明代理）。
>
> **联网无法核实的事实已标 `⚠️待核实`。** 本次会话 WebFetch 到 learn.microsoft.com 被网络策略拦截。

---

## 0. 修正：第一版草案搞错了中心抽象

第一版把 mitmproxy 的中心抽象当成 **Flow + hooks**。看了实际代码后，这是错的：

| | 第一版（错） | mitmproxy 实际 |
|---|---|---|
| 中心对象 | `Flow` 结构体 | **`Layer`** —— 活的连接两端 |
| 流量记录 | 用 `Flow` 承载 | `Flow` 是**记录**，由 Layer 产出，供 addon/dump/UI 消费 |
| 协议处理 | 一次性判定 `FlowKind` | **协议栈可升级**：TCP→TLS→HTTP 逐层 push，由 `next_layer` 判定 |
| 扩展点 | hook 列表 | **40+ addon** + Layer 本身可被替换 |
| 服务端 | 无 | `Master`（事件循环）+ `AddonManager`（钩子分发）+ `ConnectionHandler` |

**关键区别**：mitmproxy 里 Flow 是"看得见的东西"，Layer 是"跑起来的东西"。
把两者合成一个 Flow 结构体，会把"可观测"和"机制"焊死，后面想加协议就得改核心。

下面按真实结构重写。

---

## 1. 三个真正的中心抽象

### 1.1 Layer —— 活连接

对应 `proxy/layer.py`。每个 Layer 有两个方向：**client 端**（对端是发起方）和 **server 端**
（对端是目标）。它向外发 **Command**，向内收 **Event**。

```go
// proxy/layer.go
package proxy

// Layer 是一条活连接的一端。一个连接上的所有 Layer 组成栈，外层包住内层。
// 对应 mitmproxy 的 proxy/layer.py。
type Layer interface {
    // Kind 标注协议层。栈底永远是 TCP/UDP。
    Kind() LayerKind
    // Open 建立本层连接。TLS Layer 在这里完成握手；HTTP Layer 不需要。
    Open(ctx context.Context) error
    // Command 向上（向 Server/Master）报告事件，单向。
    Commands() <-chan Command
    // Handle 向下（从 Server/Master）接收指令，单向。
    Handle(Event)
    // Close 关闭本层及所有内层。
    Close() error
}

type LayerKind int
const (
    LKindTCP  LayerKind = iota
    LKindUDP
    LKindTLS
    LKindHTTP        // HTTP/1.x
    LKindHTTP2       // 后续作为可插拔 Layer 加入
    LKindDNS
    LKindWebSocket
    LKindQUIC        // HTTP/3，同上
)
```

### 1.2 Command / Event —— 双向总线

对应 `proxy/commands.py`（层→服务器）与 `proxy/events.py`（服务器→层）。
这是 mitmproxy 最精妙的一点：**协议层之间不直接通信**，全部经 Master 中转。
所以"给 HTTP 层注入一个 TLS 层"不需要 HTTP 层知道 TLS 的存在。

```go
// 层 → 服务器
type Command interface{ isCommand() }

type SendData     Command  // {LayerID, Data}
type DataReceived Command  // 服务器 → 层，见 Event
type OpenConnection Command // {DialSpec string}  —— 发起上游连接
type UpgradeLayer Command  // {LayerID, Kind}     —— 协议升级（关键！）
type CloseLayer   Command  // {LayerID, Reason}

// 服务器 → 层
type Event interface{ isEvent() }
type ConnectionClosed Event
type DataAvailable    Event  // {Data []byte}
type ReadDeadline     Event
type WriteDeadline    Event
type ErrorReceived    Event
```

**`UpgradeLayer` 是整个设计的枢纽。** 它让"这条连接其实是 TLS，不是裸 TCP"
成为一个运行时事件，而不是启动时的静态声明。这正是透明代理需要的能力：
你接管的是一个 IP:port，**事先不知道里面跑什么协议**。

### 1.3 Flow —— 记录，不是机制

对应 `flow.py` + `http.py`。Flow 由 Layer 栈在事务边界产出，是**只读观测对象**，
供 addon、dump、UI 消费。

```go
// proxy/flow.go —— 记录，由 Layer 栈产出
type Flow struct {
    ID        uint64
    Stack     []LayerKind       // 最终协议栈，如 [TCP, TLS, HTTP]
    Kind      FlowKind          // 栈顶协议
    State     FlowState         // Started/Received/Sending/Sent/Killed/Error
    SrcAddr   net.Addr          // 客户端真实地址 —— 透明代理下 ≠ 127.0.0.1
    DstAddr   net.Addr
    Host      string            // 由 DNS/FakeIP 回填
    Request   *Request          // 协议无关；HTTP 层填完才有值
    Response  *Response
    Matched   Rule
    BytesIn   int64
    BytesOut  int64
    CreatedAt time.Time
    Err       error
}
```

**`SrcAddr` 是透明代理的灵魂**：现在的 `proxy.Proxy.Connect(ctx, addr)` 只有目标地址，
上游代理根本看不到真实客户端。有了 `SrcAddr`，按客户端分流 / per-client 限速 /
`--allow-hosts` 才有落点。

### 1.4 Master + AddonManager

对应 `master.py` + `addonmanager.py`。职责必须拆开：

| | mitmproxy | 本方案 |
|---|---|---|
| 事件循环 / 调度 | `master.py` | `cmd/runtime.go` 的 standaloneRun（已有 ctx 生命周期） |
| 连接分派 | `server.py` ConnectionHandler | 新增 `proxy/handler.go` |
| addon 生命周期 + 钩子分发 | `addonmanager.py` | 新增 `proxy/addons.go` |
| 全局配置 | `options.py` | 现有 `config.Config` |

**不要**把 addon 分发塞进 Layer 里。mitmproxy 把两者分开的原因是：addon 可以被
热加载/禁用（`addonmanager.py` 管理生命周期），而 Layer 是连接级别的。混在一起
就丧失了"运行时插拔规则"的能力——而这个能力我们现在已经有（`Router.AddRule`）。

---

## 2. `next_layer`：协议自动识别 —— 透明代理真正的钥匙

第一版完全漏掉了 `addons/next_layer.py`。它是 mitmproxy 在透明模式下能工作的**唯一原因**。

透明代理接管的是 `(srcIP, dstIP, dstPort)`，你**不知道**里面是 HTTP、TLS、DNS、
还是任意 TCP。mitmproxy 的解法是：

```
收到 client 端第一个字节
   ▼
peek 而不 consume（零拷贝窥探，不破坏流）
   ▼
判定器逐个尝试：
   ├── 0x16 0x03 ...  → TLS ClientHello  → 读出 SNI → push TLS Layer
   ├── "GET "/"POST"/"HTTP"/"HEAD" 前缀 → HTTP/1 → push HTTP Layer
   ├── DNS 头（2 字节 id + 2 字节 flags，flags 低位=0x8180 且 QR=1）→ DNS
   ├── 任意字节 + 后续符合 SOCKS5 0x05 → SOCKS5
   └── 都不匹配 → 保持 TCP，纯透传
   ▼
发出 UpgradeLayer command → Master 决定新 Layer → 新 Layer 接管后续字节
```

```go
// proxy/nextlayer.go —— 对应 addons/next_layer.py
type Detector func(first []byte, peek io.Reader) (LayerKind, bool)

// 顺序敏感：TLS 必须在 HTTP 之前（TLS 握手的字节也可能被误判为其他）。
// 默认表，可在 config 里重排。
func DefaultDetectors() []Detector {
    return []Detector{
        DetectTLS,      // 0x16 0x03
        DetectHTTP1,    // 方法前缀
        DetectDNS,      // id+flags 特征
        DetectSOCKS5,   // 0x05
    }
}
```

**这个判定器是整个方案最容易被低估、也最该先做的部分。** 没有它，"透明代理"就
只能要求用户预先声明端口是 HTTP 还是 TLS，那就退化成了普通监听，不是透明代理。

### 2.1 与 FakeIP 的配合

```
App ──DNS──► dns.Server (FakeIP)
              │  example.com → 198.18.0.42
              │  写 FakeIPTable: 198.18.0.42 → "example.com"
              ▼
App ──TCP──► 透明代理入口 ──► ConnectionHandler
              │  Linux: TPROXY  ┐
              │  Win:   TUN     ├─► 三个入口产出同一个 DialContext
              │  Win10: WFP     ┘
              │  dst = 198.18.0.42:443
              │  查 FakeIPTable → Host = "example.com"
              │  Router.Pick(DialContext{Host, Addr, SrcAddr, IsUDP})
              ▼
              Layer 栈建立，next_layer 判定协议，按规则改写/透传
```

`Router.Pick` 必须换签名（破坏性变更，见 §6）：

```go
// 旧：router/router.go:58  Pick(addr string) (proxy.Proxy, error)
// 新：
type DialContext struct {
    Host    string     // 解析后的主机名；无 FakeIP 时为 ""
    Addr    string     // 原始 IP:port，永远有值
    SrcAddr net.Addr   // 客户端真实地址
    IsUDP   bool
}
func (r *Router) Pick(ctx DialContext) (proxy.Proxy, error)
```

`Host == ""` 时按纯 IP 规则匹配（IP-CIDR / PORT-RANGE / GEOIP / MATCH），域名类规则
跳过，并 **log warning**——不能静默丢弃，否则用户改规则永远不知道没生效。

---

## 3. Mode spec：8 种模式统一成一个语法

mitmproxy 的 `mode_specs.py` 把 8 种运行模式压成一个字符串：
`"regular"` / `"reverse:https://target"` / `"transparent"` / `"socks5@1234"` /
`"upstream:http://proxy"` / `"dns"` / `"wireguard"` / `"local"`。

**我们现在有 6 个重叠的子命令**（`socat`、`forward`、`proxy`、`dns`、`corsproxy`、
`corsproxy` 的反向代理角色），本质是同一个东西的不同 mode。建议统一：

```
agent-netx proxy "regular@:8080"                # 现有 proxy 子命令
agent-netx proxy "reverse:https://10.0.0.5:9000"  # 现有 corsproxy 的前身
agent-netx proxy "socks5@:1080"                 # 现有 socks5 监听
agent-netx proxy "upstream:socks5:127.0.0.1:1080" # 链路第二跳
agent-netx proxy "transparent"                   # 平台自适应：Linux→TPROXY、Win→TUN、macOS→TUN
agent-netx proxy "tproxy:8080"                   # 显式 TPROXY（Linux，对应现有 listen.tproxy）
agent-netx proxy "dns@:5353"                     # 现有 dns
agent-netx socat "TCP-LISTEN:8080" "TCP:10.0.0.1:80"  # 保持 socat 语义（无需路由器）
```

解析规则（对应 `mode_specs.py`）：

```
<mode>[:<spec>][@<listen-addr>]
  regular            默认，HTTP(S) 正向代理
  reverse:<url>      反向代理，固定上游
  transparent        平台自适应（见 §6.8）：Linux→TPROXY、Windows→TUN、macOS→TUN
  tproxy:<port>      显式 TPROXY，Linux only（其它平台 fail closed 报错）
  socks5             SOCKS5 监听（可选 :user:pass）
  upstream:<url>     连接到另一个代理作为上游
  dns                DNS 服务器
  local              OS 级重定向器（Linux pf/iptables）
```

`transparent` 平台自适应是**多平台支持的核心**：用户写一种模式，平台决定走哪条路径。
`mitmproxy transparent` 也是这个思路（Linux TPROXY / macOS networkextension /
其它平台 TUN）。

**收益**：`forward` 的 5 种模式（-L/-R/-D/-U/tls）和 `socat` 和 `corsproxy` 的
地址语法可以逐步收敛到同一套解析器。这是纯重构，不改行为，可单独发版。

**注意 WireGuard 模式**：mitmproxy 用 WireGuard 隧道做移动端拦截，因为手机上装
透明代理需要 root。这提示我们：**TUN 在 Windows/macOS/Linux 桌面是可行的，
但移动端不可行**。如果要做移动端，WireGuard 层是必经之路——而我们已经有
`wireguard` 文档和 `tun.Peer` 接缝，可以对接。列为 P2，不阻塞主线。

---

## 4. TLS 拦截作为 Layer

TLS 不是特殊分支，是普通 Layer：

```
TCP Layer 建立
   ▼ next_layer 检测到 0x16 0x03
push TLS Layer
   ▼
读 ClientHello 的 SNI（明文，不需要解密）
   ▼
addons（YAML hooks）on: tls 逐个执行
   ├── FlowKill     → 丢弃连接
   ├── FlowContinue → TLS pass-through：只建 TCP tunnel，不解密
   └── FlowModify + meta["mitm"]=true
                    → 用自签 CA 终止 TLS，解密后 push HTTP Layer
```

**安全红线（不可妥协）**：`mitm=true` 必须由显式规则触发，**默认绝不解密**。
`tls.inspect: false` 是二次确认开关。否则工具会退化成"被动偷看所有 HTTPS"，
既不可接受也过不了任何审查。
同时：解密后的流量**强制走同一 proxy 出口**，禁止"解密后再直连"。

---

## 5. Addon：脚本化决策（与第一版一致，理由更硬了）

mitmproxy 的 `addons/script.py` 加载用户 Python 脚本。第一版说不做 Python scripting，
理由是 Go plugin（`buildmode=plugin`）在 Windows 不可用。**这个结论不变，而且现在
更有必要**：mitmproxy 的 40+ 内置 addon 里 `script.py` 只是其中之一，
`modifyheaders.py` / `blocklist.py` / `next_layer.py` 都是**核心内置**而非用户脚本——
说明 mitmproxy 自己也没把"用户脚本"当主路径。

| 方案 | 能力 | 成本 | 建议 |
|---|---|---|---|
| **A. 内置 YAML hooks** | 静态改写：改头/改体/丢弃/按条件直连 | 低 | **先做** |
| **B. 沙盒 Lua (gopher-lua)** | 动态逻辑：计数器、状态机、条件改写 | 中 | 第二阶段 |
| C. WASM (wazero) | 最安全、可移植 | 高 | 有明确需求再说 |
| D. Go plugin | 强类型 | **Windows 不支持** | 放弃 |

内置 YAML 应优先覆盖 mitmproxy 已有内置 addon 的能力（因为它们已被验证为高频需求）：

```yaml
flows:
  max_body_size: 1048576        # 防 OOM，对应 --set max_body_size
  next_layer:                   # 对应 addons/next_layer.py，可重排/禁用
    - tls
    - http1
    - dns
    - socks5
  tls:
    inspect: false              # 二次确认开关
  addons:
    - name: modifyheaders       # 对应 addons/modifyheaders.py
      on: response
      if: { scheme: https }
      headers:
        set:
          - Strict-Transport-Security: max-age=31536000
          - X-Content-Type-Options: nosniff
    - name: blocklist           # 对应 addons/blocklist.py
      action: drop
      domains: ["*.doubleclick.net"]
    - name: replace             # 对应 mitmproxy --replace
      on: response
      body:
        - { from: "old", to: "new", regex: false }
    - name: allow-hosts
      action: drop              # 不在白名单的一律 drop
      allow: ["example.com"]
```

**mitmproxy 能力对齐**：

| mitmproxy | 本方案 | 优先级 |
|---|---|---|
| Layer 模型 + command/event 总线 | §1.1 / §1.2 | **P0** |
| **next_layer 协议自动识别** | §2 | **P0**（透明代理的前提） |
| Flow 记录 + 状态机 | §1.3 | P0 |
| `--modify-response` | `addons: modifyheaders` | P0 |
| `--replace` | `addons: replace` | P1 |
| TLS 按 SNI inspect/ignore | §4 | P0 |
| `--allow-hosts` / `--block-hosts` | `addons: blocklist` / `allow-hosts` | P0 |
| mitmdump（无头输出） | Flow 记录进现有 `web.LogRing`，`logs` 命令接入 | P1（基础设施已有） |
| 按客户端地址分流 | `DialContext.SrcAddr` | P1 |
| HTTP/2、HTTP/3、WebSocket、QUIC | **作为独立 Layer 增量加入，核心不动** | P2 |
| mitmweb 完整 Web UI | 已有 Web Dashboard，只加 flows 面板 | P2 |
| Python `--script` | 不做，用 YAML → Lua | — |
| 本地重定向器 (Linux/macOS pf) | `mode: local`，P2 | P2 |

**HTTP/2 与 HTTP/3 值得单独说一句**：第一版说"HTTP/2 改写生态不稳，只做透传+SNI"。
在 Layer 模型下这个顾虑消失了——HTTP/2 和 QUIC 是**独立 Layer**，可以加、可以禁、
可以回退到透传，而 HTTP/1 路径不受影响。所以列为 P2 而不是"不做"。

---

## 6. 透明代理：三条路径，TPROXY 是默认

### 6.1 路径对比

| 路径 | 平台 | 需分发驱动？ | 建议 |
|---|---|---|---|
| **TPROXY (Linux)** | Linux | **否**（内核 netfilter + 原生 syscall） | **Linux 首选，仓库已有** |
| **TUN (wintun)** | Win/Linux/macOS | 是（wintun.sys，业界通行） | **Windows 首选** |
| **WFP IP Redirect Provider** | 仅 Windows | **否**（用户态 FWPM API 下发） | **Win10 首选补充** |
| **eBPF XDP** | Win11 22H2+ `⚠️待核实` | 否（eBpf.sys 随系统） | 仅作加速器 |
| netsh ip nat | 仅 Windows | 否 | 仅固定端口重定向 |

第一版把 TUN 和 WFP 并列，**漏掉了 TPROXY——而它是仓库已经实现的那条**。
TPROXY 在 Linux 上是比 TUN 更好的默认：不装驱动、不改路由表、不碰 DHCP、
不影响本机其它 App，且 `mitmproxy transparent` 用的就是它。

### 6.2 仓库已实现的 TPROXY（`listener/tproxy_linux.go`）

已能工作，值得说清楚它做对了什么：

```go
// 监听侧：raw socket + IP_TRANSPARENT，让内核 TPROXY 重定向落到这里
unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)

// accept 后：零长度 recvmsg + MSG_PEEK，从 cmsg 里取出原始目标
_, oobn, _, _, err := unix.Recvmsg(fd, nil, oob, unix.MSG_PEEK)
// 解析 IP_ORIGDSTADDR → 原始 dst IP:port
```

`origDst()` 用 `MSG_PEEK` 而不 consume，不破坏流——这正是 §2 `next_layer` 需要的
"peek 而不 consume"。`tproxyConn.RemoteAddr()` 返回原始目标，所以 `handleTProxy`
能把它喂给 router。**这一段是正确的，不需要改。**

### 6.3 缺的另一半：fwmark 路由规则

TPROXY 需要**两半**，仓库只有后半：

```
前半（重定向）：iptables TPROXY + ip rule —— 仓库未实现
   iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY \
        --tproxy-mark 0x1/0xffffffff --on-port 8080
   ip rule add fwmark 0x1 lookup 100
   ip route add local 0.0.0.0/0 dev lo table 100
        │  缺 fwmark 路由 → 被重定向的包回流本机，形成转发环
        ▼
后半（接收）：IP_TRANSPARENT listener + IP_ORIGDSTADDR —— 仓库已实现
```

没有前半，用户看到的现象是"配了 `listen.tproxy: 8080` 但没有任何流量进来"。
应补：`config.tproxy.mark`（默认 `0x1`）+ 启动时幂等下发 `ip rule`/`iptables` +
关闭时回滚。这属于 **Phase 1**，因为它是既有功能的缺失而非新抽象。

### 6.4 TPROXY 丢失了客户端地址 —— 这是 §1.3 `SrcAddr` 的硬理由

`handleTProxy`（`http.go:543`）调 `Router.Pick(target)`，只有目标地址，没有客户端地址。
但客户端地址就在手上，被扔掉了：

```go
// 第一处丢失：Recvmsg 的第三个返回值（peer sockaddr）被 `_` 丢弃
_, oobn, _, _, err := unix.Recvmsg(fd, nil, oob, unix.MSG_PEEK)
        //     ^^^ 这里是真实的客户端地址

// 第二处：fallback 把客户端地址误当目标地址
orig := origDst(cfd)
if orig == nil {
    if orig, err = peerTCPAddr(cfd) { ... }   // peer = 客户端！却赋给名为 orig 的变量
}
```

`IP_ORIGDSTADDR` cmsg 是 **目标**地址；`Getpeername` 是 **客户端**地址。
fallback 分支把一个叫 `orig` 的变量填成客户端地址，然后 `RemoteAddr()` 返回它
当作"原始目标"——**目标会被替换成客户端自己的 IP**。虽然 Linux 上有 cmsg，
`origDst` 通常成功使 fallback 不触发，但这是一个潜伏错误，且让"客户端地址"
在这条路径上彻底消失。

修正后每个客户端都有真实地址，`SrcAddr` 才成立：

```go
// tproxyConn 同时携带两端
type tproxyConn struct {
    net.Conn
    orig    *net.TCPAddr // 原始目标 ← IP_ORIGDSTADDR
    client  *net.TCPAddr // 真实客户端 ← peer
}
func (c *tproxyConn) RemoteAddr() net.Addr { return c.orig }
func (c *tproxyConn) ClientAddr() net.Addr { return c.client }
```

`handleTProxy` 变为 `Router.Pick(DialContext{Addr: target, SrcAddr: conn.ClientAddr()})`。
这是 Phase 1 的内容——不需要 Layer，改两个文件即可拿到按客户端分流能力。

**对比 Windows**：TUN 路径天然带源地址（IP 包头里有），WFP IP Redirect 把
`(dstIP, dstPort)` 改写到 `127.0.0.1:<port>`，**原始 dst 和 src 都在监听 socket 上**。
TPROXY 是三条路径里唯一需要专门从 cmsg 恢复目标的——也是唯一在仓库里已实现的。

### 6.5 eBPF 只能是加速器，不能是地基

1. **版本门槛**：eBPF 支持自 Windows 11 22H2 (Build 22621) 起提供 `⚠️待核实`。
   Win10（含本机 19045）**没有** eBPF 内核支持——本机跑不起来是硬事实。
2. **能力是子集**：Windows eBPF 的程序类型少于 Linux `⚠️待核实`具体清单，
   已知包含 XDP 类、SCHED_CLS、KPROBE 系列、TRACING；没有完整 SOCKMAP、没有 LSM。
3. **用户态库**：`ebpf.dll` 可用性随 SDK 变化 `⚠️待核实`，老版本需反射 `ntdll` 的
   `eBpfSysCallTablePtr`。

### 6.6 WFP 做法（Win10 真正该做的）

```
用户态：wfp.dll / FWPM 子层 API（系统自带）
   │  创建 sublayer + 注册 IP Redirect Provider 规则
   │  (dstIP, dstPort) → 127.0.0.1:<本地监听端口>
   ▼
内核态：WFP 内建 IP Redirect Provider 执行重定向
   │  —— 零自定义内核代码，配置全由用户态下发
   ▼
ConnectionHandler 接管（Layer 栈 + next_layer 判定协议）
```

**为什么不写 WFP callout 驱动**：callout 必须编译成内核 `.sys` 分发，意味着签名、
WHQL、攻击面扩大、管理员批准。对一个代理工具是严重不成比例的成本。
IP Redirect Provider 是 WFP **内建** provider，用户态配置即可。

`⚠️待验证`：IP Redirect Provider 有已知限制（某些 loopback 目标、地址族覆盖）。
Phase 4 前做最小验证：建 sublayer → 加 `10.0.0.1:80 → 127.0.0.1:8080` →
`curl` 看是否被劫持。

### 6.7 TPROXY ↔ Layer 模型

TPROXY 不改变 Layer 设计，只是 Layer 栈的一个**入口**：

```
iptables TPROXY → tproxyListener.Accept()
   │  conn.RemoteAddr() = 原始目标，ClientAddr() = 真实客户端
   ▼
ConnectionHandler（同一套，三个入口汇合）
   ├── TPROXY 入口（Linux，已有）
   ├── TUN 入口（Win/mac/Linux）
   └── WFP 入口（Win10，待做）
   ▼
Layer 栈建立，next_layer 判定协议
```

三个入口的差异只到 `DialContext` 为止，之后完全一致。这验证了
`DialContext{Addr, SrcAddr, Host, IsUDP}` 作为统一入口签名的正确性。

### 6.8 多平台抽象：一个后端接口 + build tag

仓库已经在用 Go 的 build-tag 约定做这件事（`tproxy_linux.go` / `tproxy_other.go`），
应把它提升成正式接口而不是散落的文件：

```go
// transparent.go
package transparent

// Backend 是一个平台的透明代理实现。
// 由 build tag 选择具体文件，用户不需要知道差异。
type Backend interface {
    Name() string           // "tproxy" / "tun" / "wfp"
    // Platform 标注本实现适用于哪个 GOOS。
    Platform() string
    // Start 建立重定向 + 监听，返回统一的入口。
    Start(ctx context.Context, cfg Config) (Entry, error)
    Close() error
}

// Entry 是透明代理统一出口。三个平台都产出同一个类型，
// 之后完全共用 ConnectionHandler + Layer 栈。
type Entry interface {
    Accept() (net.Conn, error) // 连接已携带 SrcAddr（见 §6.4）
    Close() error
}
```

文件布局（沿用现有 build-tag 约定）：

| 文件 | 内容 |
|---|---|
| `transparent/transparent.go` | `Backend` / `Entry` 接口 + 注册表 |
| `transparent/tproxy_linux.go` | TPROXY 后端（从 `listener/tproxy_linux.go` 迁入） |
| `transparent/tun_darwin.go` | TUN 后端 |
| `transparent/tun_windows.go` | TUN 后端（wintun） |
| `transparent/tun_linux.go` | TUN 后端（`/dev/net/tun`） |
| `transparent/wfp_windows.go` | WFP 后端（Phase 4） |
| `transparent/unsupported_others.go` | `//go:build !linux && !windows && !darwin` → fail closed |

**`unsupported_others.go` 的关键价值**：现有 `tproxy_other.go` 已经在这么做——
非 Linux 平台直接返回错误而不是静默 no-op。这很重要：**多平台支持不等于
"所有平台都能跑"**，而是"不支持的平台明确报错"。一个静默失败的透明代理
比直接失败危险得多——用户以为在代理，实际流量直连。

**`transparent` 必须 fail closed**：

```go
// 平台不支持时，报错而不是退化
if b, ok := lookupBackend(runtime.GOOS); !ok {
    return nil, fmt.Errorf("no transparent backend for %s/%s",
        runtime.GOOS, runtime.GOARCH)
}
```

对比现有 `tproxy_other.go`（`tproxy.go:14`）的做法是对的——保持这个纪律。

**macOS 特别说明**：macOS 除了 TUN，还有 Apple Network Extension 的
`NETransparentProxyProvider` `⚠️待核实`（mitmproxy 在 macOS 上用的就是它）。
它不需要额外驱动，但需要代码签名 + 用户显式批准。列为 P2：TUN 在 macOS 已经能用，
NE 只是"更干净"而非"必须"。

**平台矩阵**（目标状态）：

| 能力 | Linux | Windows | macOS |
|---|---|---|---|
| TPROXY | ✅ 已有 | ❌ fail closed | ❌ fail closed |
| TUN | ✅ 已有 | ✅ 已有（wintun） | ✅ |
| WFP IP Redirect | — | Phase 4 | — |
| networkextension | — | — | P2 |
| eBPF XDP | 已有内核支持 | Win11 22H2+ `⚠️待核实` | ❌ |
| `transparent` 模式 | → TPROXY | → TUN | → TUN |

**结论**：`transparent` 模式在三个平台都能用，但**底层机制不同且互不共享代码**。
这正是 `Backend` 接口存在的理由——平台差异被封在 build-tag 文件里，
`ConnectionHandler` / Layer / Router 全部共用。

---

## 7. 与现有代码的对接

| 现有 | 位置 | 处理方式 |
|---|---|---|
| `proxy.Proxy.Connect` | `proxy/interface.go:12` | **保留不动**，作为最底层拨号能力；新增 `Layer` 在其上 |
| `proxy.PacketProxy` | `proxy/interface.go:26` | 保留；UDP Layer 走它 |
| `Router.Pick(addr)` | `router/router.go:58` | 换 `Pick(DialContext)`，保留 wrapper |
| `Router.AddRule` / `AddProxy` | `router/router.go:98,123` | 直接复用为 addon 热加载路径 |
| **TPROXY 监听** | `listener/tproxy_linux.go` | **迁入 `transparent/tproxy_linux.go`**，实现 `Backend`；修 §6.4 的客户端地址丢失 |
| `forward tls` + CA | `cmd/forward.go` | 复用为 TLS Layer 的 MITM 实现 |
| `web.LogRing` | `web/` | 作为 mitmdump 的 Flow 日志载体 |
| TUN + `tun.Peer` 接缝 | `tun/` | 包成 `Backend`（`transparent/tun_*.go`），不重写 |
| `dns` + FakeIP | `dns/` | 需打通 FakeIPTable → Router |

**关键约束**：`proxy.Proxy.Connect` 被 7 个实现 + N 个调用点依赖。
**不替换它，在其上加 Layer**。这是能分阶段交付的前提。

**TPROXY 迁移注意**：`listener/http.go` 的 `serveTProxy`/`handleTProxy` 也要跟随
迁到 `transparent` 包，或保持 `Listener` 作为薄封装（推荐后者——`Listener` 已经
同时管 HTTP/SOCKS5/TPROXY 三个 listener，拆开会引入锁竞争）。

---

## 8. 分阶段路线（每阶段可独立发布）

```
Phase 1 (v0.3.0)  Flow 记录 + Router.Pick(DialContext) + FakeIP 打通
                  · 不动 proxy.Proxy，不动 Layer
                  · 修 TPROXY 客户端地址丢失（§6.4）——改 2 个文件，不改抽象 [已实现]
                  · 补 TPROXY fwmark 路由规则（§6.3）——已有功能的缺失 [已实现]
                  · Flow 只记录不改写
                  · 收益：mitmdump 等价、按客户端分流、域名规则在 TUN 下生效
Phase 2 (v0.4.0)  Layer + Command/Event 总线 + next_layer 协议识别
                  · 引入 proxy.Layer，TCP/TLS/HTTP1 三个实现
                  · 收益：透明代理真正可用（不预声明协议）
Phase 3 (v0.5.0)  YAML addons（modifyheaders/blocklist/replace）+ on:tls
                  · 复用现有 forward tls + CA
                  · 收益：mitmproxy 的改写能力
Phase 4 (v0.6.0)  transparent 包 + Backend 抽象（多平台）
                  · 把 tproxy/tun 统一成 Backend，transparent 模式平台自适应
                  · 收益：一种模式跨三平台，平台差异封在 build-tag 文件里
Phase 5 (v0.7.0)  WFP IP Redirect 透明路径（Windows 可选）
                  · TUN 保持 Windows 默认，WFP 作为零驱动备选
                  · 收益：Win10 零 .sys 透明代理
Phase 6 (v0.8.0)  eBPF XDP 加速器（仅 Win11 22H2+，可选）
                  · 收益：低延迟；跳过则功能零损失
Phase 7 (v0.9.0)  HTTP/2 + WebSocket + QUIC Layer（可插拔）
                  · 收益：协议覆盖；核心不动
```

**Phase 5 / 6 明确可选**：跳过它们对功能零影响。WFP 是 Windows 的"零驱动"备选，
eBPF 只是加速器。所以 Windows 内核技术一直不被支持，整个改造也不阻塞。

**Phase 4 是"多平台"的落地**：之前 TPROXY 散在 `listener` 包里，没有平台抽象。
这个 phase 不增加新能力，只是把已有能力组织成跨平台可声明的形式。

### 向后兼容

- `Pick(addr string)` 保留 wrapper：`return r.Pick(DialContext{Addr: addr})`，
  标 `// Deprecated`，留一个完整大版本。
- YAML `flows` 段不写时行为与 v0.2.8 完全一致——**默认零风险**。
- `socat` 保持独立子命令语义（它不需要路由器，就是纯两端中继）。

---

## 9. 风险

| 风险 | 等级 | 缓解 |
|---|---|---|
| 解密后的 HTTPS 被当正常流量转发 | **高** | `tls.inspect` 默认 false；解密流量强制走同一出口，禁止解密后直连 |
| FakeIP 段与用户内网冲突 | 高 | 用 `198.18.0.0/16`（RFC 2544 保留段），允许配置覆盖 |
| next_layer 误判（TLS 字节被当 HTTP） | 高 | 判定器顺序固定且可配置，TLS 必须最先；误判时可回退纯透传 |
| **TPROXY 缺 fwmark 路由 → 转发环 / 无流量** | **高** | Phase 1 补 §6.3；启动时幂等下发、关闭时回滚 |
| **TPROXY fallback 把客户端当目标（§6.4）** | 高 | 已有潜伏 bug；修 `tproxyConn` 分离 orig/client |
| **不支持的平台静默 no-op** | **高** | fail closed：`unsupported_others.go` 直接报错，绝不退化 |
| WFP IP Redirect Provider 已知限制 | 中 | Phase 5 前做最小验证 |
| 分发内核驱动（callout） | — | **已规避**：只用内建 Provider，零 .sys |
| eBPF 门槛与 SDK 不确定 | 中 | 封装 loader，失败静默回退 TUN；整体标可选 |
| 大 body OOM | 中 | `max_body_size` 截断 + 标记 |
| `Pick` 签名变更破坏调用点 | 中 | wrapper + Deprecated，一个大版本宽限期 |
| Layer 栈并发（多 Layer 同写一个 Conn） | 中 | 每 Layer 独占其 Conn，栈内层与外层不共享写入端 |
| macOS networkextension 需签名 + 用户批准 | 低 | 列为 P2，TUN 已可用；不阻塞 |

---

## 10. 验收

### Phase 1（TPROXY 修复 + Flow 记录）

```bash
# 1. 规则命中可观测
agent-netx start -c config.yml
curl https://example.com
agent-netx logs --tail 50
# 应看到 Flow 记录：Stack / Host / SrcAddr / Matched / 字节数 / State

# 2. 按客户端地址分流
agent-netx proxy "regular@:8080"
# 192.168.1.50 走 ss-1，192.168.1.51 走 DIRECT

# 3. TPROXY 端到端（Linux，Phase 1 的核心验收）
iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY \
    --tproxy-mark 0x1/0xffffffff --on-port 8080
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
# 然后 curl 任意 HTTPS 站点应被劫持，日志里 SrcAddr 是真实客户端 IP
# 关键：如果看不到流量 → fwmark 路由缺失（§6.3），不是 TPROXY 本身的问题

# 4. 向后兼容
# 旧配置（无 flows 段、无 listen.tproxy）行为必须与 v0.2.8 完全一致
```

**第 3 项是最容易被误判的验收点**：TPROXY 失败和 fwmark 缺失的表现一模一样
（都看不到流量）。区分方法是 `iptables -L -n -t mangle` 确认规则在、
`ip rule list` 确认 fwmark 规则在——两个都在还没流量，才是 TPROXY 代码问题。

### Phase 4（多平台）

| 测试 | 期望 |
|---|---|
| Linux 上 `proxy "transparent"` | 走 TPROXY 后端，日志显示 `backend=tproxy` |
| Windows 上 `proxy "transparent"` | 走 TUN 后端，日志显示 `backend=tun` |
| macOS 上 `proxy "transparent"` | 走 TUN 后端 |
| Windows 上 `proxy "tproxy:8080"` | **fail closed**：明确报错，不静默 |
| Windows 上 `proxy "wfp"` | Phase 5 前报错；Phase 5 后走 WFP |

**fail closed 是必须验证的项**：一个在 Windows 上"没报错但也没代理"的 TPROXY
比直接报错危险得多——用户以为流量在走代理。这条对应风险表第三行。

---

## 11. 结论

第一版把 mitmproxy 的中心抽象搞错了，也把仓库已经实现的透明代理（TPROXY）漏掉了。
补齐了这两点后，四条结论清晰：

1. **真正的中心是 `Layer + Command/Event 总线`**，Flow 只是它的记录。这是第一版搞反的。
2. **`next_layer` 协议自动识别是透明代理的前提**——没有它，透明代理退化成普通监听。
   这是第一版完全漏掉、也最该先做的部分。
3. **仓库已经有三条透明代理路径**：Linux 上的 TPROXY（`listener/tproxy_linux.go`，
   但 §6.3 缺 fwmark 路由、§6.4 丢客户端地址）、跨平台 TUN（`tun/`，已 build-tag）、
   待做的 WFP（Windows）。三者只需**一个 `transparent.Backend` 接口 + build tag**
   就能组织起来，之后 `transparent` 模式平台自适应（Linux→TPROXY / Win→TUN /
   macOS→TUN），平台差异被封死在文件后缀里。
4. **eBPF 只是 Win11+ 的加速器**，WFP 是 Windows 的零驱动备选——跳过它们功能零损失，
   整个改造不被任何内核技术阻塞。

**TPROXY 不是可选特性，是仓库已经实现、但缺最后一块拼图的功能**。Phase 1 补上
fwmark 路由 + 修客户端地址丢失，就能拿到按客户端分流和"规则在 TUN 下生效"。
这不是新抽象，是把已有能力修到能用。
