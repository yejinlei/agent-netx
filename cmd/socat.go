package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"agent-netx/agent"
)

// socatCmd 是一个轻量 TCP/UDP 中继，不需要配置文件——与 ping 一样只走命令行。
//
// 端点用 socat 风格地址：TCP-LISTEN:8080 / TCP:127.0.0.1:9000 /
// UDP-LISTEN:53 / UDP:8.8.8.8:53。裸地址（host:port）按 TCP 处理，保持兼容。
func socatCmd() *cobra.Command {
	var (
		timeout time.Duration
		verbose bool
		quiet   bool
	)
	cmd := &cobra.Command{
		Use:   "socat <addr1> <addr2>",
		Short: "TCP/UDP relay between two endpoints (socat-style addresses, no config)",
		Long: `Relay between two endpoints — socat-style addresses, no config file (CLI only).

Address forms (a listener has -LISTEN:):
  TCP-LISTEN:8080            监听全部接口 8080（裸端口默认绑 :）
  TCP-LISTEN:127.0.0.1:8080  绑定指定地址
  TCP:127.0.0.1:9000         拨号到 TCP 服务端
  UDP-LISTEN:53              监听 UDP 53
  UDP:8.8.8.8:53             拨号到 UDP 服务端
  host:port                  裸地址按 TCP 处理

Examples:
  agent-netx socat TCP-LISTEN:8080 TCP:127.0.0.1:9000   # 端口转发
  agent-netx socat UDP-LISTEN:5353 UDP:8.8.8.8:53       # UDP 转发（如 DNS）
  agent-netx socat TCP-LISTEN:2222 TCP:127.0.0.1:22 -v  # 逐连接日志
  agent-netx socat TCP-LISTEN:8080 TCP:10.0.0.1:80 -W 5s

UDP 按客户端地址维持独立会话：每个客户端一个远端连接，回包发回原客户端。
Ctrl-C 会关闭监听与所有在途连接并打印统计。`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if timeout <= 0 {
				timeout = 10 * time.Second
			}
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			go func() {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, os.Interrupt)
				<-sigCh
				fmt.Fprintln(os.Stderr, "\n^C — 正在停止…")
				cancel()
			}()
			return runSocat(ctx, args[0], args[1], timeout, verbose, quiet)
		},
	}
	cmd.Flags().DurationVarP(&timeout, "timeout", "W", 10*time.Second, "拨号超时（远端连接建立）")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "逐连接日志（建立/结束/字节数）")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "只报错误，抑制常规输出")
	return cmd
}

// socatSpec 是解析后的端点：协议 + 地址 + 是否为监听端。
type socatSpec struct {
	proto  string // "tcp" 或 "udp"
	addr   string // host:port
	listen bool
}

// parseSocatSpec 解析 socat 风格地址。无前缀时按 TCP 处理（兼容旧用法）；
// 裸端口无冒号时，监听端绑 :端口（全部接口），拨号端按 socat 语义视为本机。
func parseSocatSpec(s string) (socatSpec, error) {
	low := strings.ToUpper(s)
	forms := []struct {
		prefix string
		proto  string
		listen bool
	}{
		{"TCP4-LISTEN:", "tcp", true},
		{"TCP-LISTEN:", "tcp", true},
		{"TCP4:", "tcp", false},
		{"TCP:", "tcp", false},
		{"UDP4-LISTEN:", "udp", true},
		{"UDP-LISTEN:", "udp", true},
		{"UDP4:", "udp", false},
		{"UDP:", "udp", false},
	}
	for _, f := range forms {
		if strings.HasPrefix(low, f.prefix) {
			rest := strings.TrimSpace(s[len(f.prefix):])
			if rest == "" {
				return socatSpec{}, fmt.Errorf("socat: 地址 %q 缺少端口或主机", s)
			}
			if !strings.Contains(rest, ":") {
				if f.listen {
					rest = ":" + rest
				} else {
					rest = "127.0.0.1:" + rest
				}
			}
			return socatSpec{proto: f.proto, addr: rest, listen: f.listen}, nil
		}
	}
	return socatSpec{proto: "tcp", addr: strings.TrimSpace(s), listen: false}, nil
}

// socatStats 汇总本次会话的连接与字节数。
type socatStats struct {
	conns    atomic.Int64
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

func (s *socatStats) addBytes(in, out int64) {
	if in > 0 {
		s.bytesIn.Add(in)
	}
	if out > 0 {
		s.bytesOut.Add(out)
	}
}

// conns 是一个受保护的连接集合，供退出时统一关闭在途连接。
type conns struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

func (c *conns) add(nn net.Conn) {
	c.mu.Lock()
	c.m[nn] = struct{}{}
	c.mu.Unlock()
}

func (c *conns) remove(nn net.Conn) {
	c.mu.Lock()
	delete(c.m, nn)
	c.mu.Unlock()
}

func (c *conns) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for nn := range c.m {
		nn.Close()
	}
}

func runSocat(ctx context.Context, spec1, spec2 string, timeout time.Duration, verbose, quiet bool) error {
	local, err := parseSocatSpec(spec1)
	if err != nil {
		return err
	}
	remote, err := parseSocatSpec(spec2)
	if err != nil {
		return err
	}
	if local.proto != remote.proto {
		return fmt.Errorf("socat: 两端协议不一致: %s <-> %s", local.proto, remote.proto)
	}
	if !local.listen && !remote.listen {
		return fmt.Errorf("socat: 至少一端需要是监听端（TCP-LISTEN: / UDP-LISTEN:）")
	}

	stats := &socatStats{}
	active := &conns{m: map[net.Conn]struct{}{}}
	var listener, target socatSpec
	if local.listen {
		listener, target = local, remote
	} else {
		listener, target = remote, local
	}
	return relay(ctx, listener, target, timeout, verbose, quiet, stats, active)
}

// relay 在 listener 端接受连接/数据报并转发到 target 端，直到 ctx 取消。
func relay(ctx context.Context, listener, target socatSpec, timeout time.Duration, verbose, quiet bool, stats *socatStats, active *conns) error {
	if !quiet {
		fmt.Printf("socat: %s %s -> %s %s\n", listener.proto, listener.addr, target.proto, target.addr)
	}
	if verbose {
		fmt.Printf("socat: 拨号超时 %s\n", timeout)
	}

	var err error
	if listener.proto == "udp" {
		err = socatUDP(ctx, listener, target, timeout, verbose, quiet, stats)
	} else {
		err = socatTCP(ctx, listener, target, timeout, verbose, quiet, stats, active)
	}
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("socat: %s", err)
	}
	active.closeAll()
	if !quiet {
		fmt.Printf("socat: 已处理 %d 条连接, 入 %s / 出 %s\n",
			stats.conns.Load(), agent.HumanSize(stats.bytesIn.Load()), agent.HumanSize(stats.bytesOut.Load()))
	}
	return nil
}

// ---------------------------------------------------------------------------
// TCP

func socatTCP(ctx context.Context, listener, target socatSpec, timeout time.Duration, verbose, quiet bool, stats *socatStats, active *conns) error {
	ln, err := net.Listen(listener.proto, listener.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listener.addr, err)
	}
	if !quiet {
		fmt.Printf("socat: 监听 %s\n", ln.Addr())
	}
	go func() { <-ctx.Done(); ln.Close() }() // 让阻塞中的 Accept 返回，避免 Ctrl-C 后空转
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !quiet {
				fmt.Printf("socat: accept: %v\n", err)
			}
			continue
		}
		stats.conns.Add(1)
		active.add(c)
		go socatRelay(ctx, c, target, timeout, verbose, quiet, stats, active)
	}
}

func socatRelay(ctx context.Context, local net.Conn, target socatSpec, timeout time.Duration, verbose, quiet bool, stats *socatStats, active *conns) {
	start := time.Now()
	defer func() {
		active.remove(local)
		local.Close()
		if verbose {
			fmt.Printf("socat: %s <-> %s 结束, 持续 %s\n", local.LocalAddr(), target.addr, time.Since(start).Round(time.Millisecond))
		}
	}()
	d := &net.Dialer{Timeout: timeout}
	rc, err := d.DialContext(ctx, target.proto, target.addr)
	if err != nil {
		if ctx.Err() == nil && !quiet {
			fmt.Printf("socat: dial %s: %v\n", target.addr, err)
		}
		return
	}
	defer rc.Close()
	if verbose {
		fmt.Printf("socat: 建立 %s <-> %s\n", local.LocalAddr(), rc.RemoteAddr())
	}

	// 两个方向各自汇报。等两个方向都结束才退出——只等第一个方向的错误会把
	// 第二个方向的错误整个丢掉。
	done := make(chan pumpResult, 2)
	go func() {
		err, in, out := socatPump(ctx, local, rc)
		done <- pumpResult{err: err, in: in, out: out}
	}()
	go func() {
		err, in, out := socatPump(ctx, rc, local)
		done <- pumpResult{err: err, in: in, out: out}
	}()
	var totalIn, totalOut int64
	var firstErr error
	for range 2 {
		r := <-done
		totalIn += r.in
		totalOut += r.out
		if firstErr == nil && r.err != nil {
			firstErr = r.err
		}
	}
	stats.addBytes(totalIn, totalOut)
	if verbose && firstErr != nil && ctx.Err() == nil {
		fmt.Printf("socat: %s <-> %s: %v\n", local.LocalAddr(), target.addr, firstErr)
	}
}

// pumpResult 是单个方向的转发结果：首个错误 + 读入/写出字节数。
type pumpResult struct {
	err error
	in  int64
	out int64
}

// socatPump 把 src 读到 dst，返回读入/写出字节数与首个错误。
// 写错误必须回报：只看 src.Read 的错误，会让对端断开后的写失败静默到底。
func socatPump(ctx context.Context, dst io.Writer, src io.Reader) (error, int64, int64) {
	var in, out int64
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return nil, in, out
		default:
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			in += int64(n)
			werr := fullWrite(ctx, dst, buf[:n])
			out += int64(n)
			if rerr == nil {
				rerr = werr
			}
		}
		if rerr != nil {
			return rerr, in, out
		}
	}
}

// fullWrite 写满 buf，遇 ctx 取消立即返回。
func fullWrite(ctx context.Context, w io.Writer, b []byte) error {
	for len(b) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := w.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// UDP

// udpSink 是维持一个客户端会话所需的环境：回包出口（监听端）与远端地址。
type udpSink struct {
	listener net.PacketConn
	target   socatSpec
	timeout  time.Duration
	verbose  bool
	quiet    bool
	stats    *socatStats
}

// udpMsg 是一条待转发的数据报：已复制，可安全跨 goroutine 传递。
type udpMsg struct {
	peer net.Addr
	data []byte
}

// udpSessions 按客户端地址维护独立的远端 UDP 会话。每个客户端拥有自己的
// **已连接**远端套接字和单个转发 goroutine：
//
//   - 按地址建表是因为 UDP 无连接，无法靠套接字本身区分客户端；
//   - 远端套接字用已连接形式（DialContext 返回 net.Conn）是因为它只接收
//     对端的数据报，天然过滤掉其它客户端的应答——回包归属无需自己判断；
//   - 一个会话只由一个 goroutine 读写，所以不会有两个 goroutine 竞争同一
//     个套接字的 Read 而把 A 的应答错送给 B。
//
// 注意回包必须走 listener（未连接）并按 peer 定向发送；listener 不连接才能
// 同时接纳多个客户端。
type udpSessions struct {
	mu   sync.Mutex
	m    map[string]*udpSession
	cons []net.Conn
	sink udpSink
}

type udpSession struct {
	key   string
	inbox chan udpMsg
}

func newUDPSessions(sink udpSink) *udpSessions {
	return &udpSessions{m: map[string]*udpSession{}, sink: sink}
}

// enqueue 把数据报投给该客户端的会话（不存在则新建并启动转发 goroutine）。
// 不阻塞：会话积压时丢弃，而不是卡住整个接收循环。
func (s *udpSessions) enqueue(ctx context.Context, peer net.Addr, data []byte) {
	if ctx.Err() != nil {
		return
	}
	key := peer.String()
	s.mu.Lock()
	sess, ok := s.m[key]
	if !ok {
		sess = &udpSession{key: key, inbox: make(chan udpMsg, 128)}
		s.m[key] = sess
		s.sink.stats.conns.Add(1)
		go s.run(ctx, sess)
		if s.sink.verbose {
			fmt.Printf("socat: udp 会话 %s -> %s\n", key, s.sink.target.addr)
		}
	}
	s.mu.Unlock()
	select {
	case sess.inbox <- udpMsg{peer: peer, data: data}:
	default:
		if s.sink.verbose {
			fmt.Printf("socat: udp 会话 %s 已满，丢弃 %d 字节\n", key, len(data))
		}
	}
}

// run 拥有单个客户端会话的远端套接字：收数据报→转发→把回包送回原客户端。
// 拨号在 goroutine 内做，避免持锁阻塞其它客户端的建会话。
func (s *udpSessions) run(ctx context.Context, sess *udpSession) {
	sink := s.sink
	d := &net.Dialer{Timeout: sink.timeout}
	c, err := d.DialContext(ctx, "udp", sink.target.addr)
	if err != nil {
		// 拨号失败就把会话从表里摘掉，让后续数据报重新建会话重试。
		s.drop(sess.key)
		if ctx.Err() == nil && !sink.quiet {
			fmt.Printf("socat: udp dial %s: %v\n", sink.target.addr, err)
		}
		return
	}
	s.mu.Lock()
	s.cons = append(s.cons, c)
	s.mu.Unlock()
	defer c.Close()

	rb := make([]byte, 65535) // 完整 UDP 数据报上限，小缓冲会截断大报文
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-sess.inbox:
			if !ok {
				return
			}
			if _, werr := c.Write(msg.data); werr != nil {
				if sink.verbose {
					fmt.Printf("socat: udp write %s: %v\n", sink.target.addr, werr)
				}
				continue
			}
			n, rerr := c.Read(rb)
			if n > 0 {
				sink.stats.bytesOut.Add(int64(n))
				if _, werr := sink.listener.WriteTo(rb[:n], msg.peer); werr != nil {
					if sink.verbose {
						fmt.Printf("socat: udp reply to %s: %v\n", msg.peer, werr)
					}
				}
			}
			if rerr != nil {
				if ctx.Err() == nil && sink.verbose {
					fmt.Printf("socat: udp read %s: %v\n", sink.target.addr, rerr)
				}
				return
			}
		}
	}
}

func (s *udpSessions) drop(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

func (s *udpSessions) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cons {
		c.Close() // 解除阻塞中的 c.Read，run 才能退出
	}
	s.cons = nil
	for k, sess := range s.m {
		close(sess.inbox)
		delete(s.m, k)
	}
}

func socatUDP(ctx context.Context, listener, target socatSpec, timeout time.Duration, verbose, quiet bool, stats *socatStats) error {
	ln, err := net.ListenPacket(listener.proto, listener.addr)
	if err != nil {
		return fmt.Errorf("udp listen %s: %w", listener.addr, err)
	}
	if !quiet {
		fmt.Printf("socat: 监听 %s\n", ln.LocalAddr())
	}
	sink := udpSink{listener: ln, target: target, timeout: timeout, verbose: verbose, quiet: quiet, stats: stats}
	sess := newUDPSessions(sink)
	go func() { <-ctx.Done(); ln.Close(); sess.closeAll() }()
	buf := make([]byte, 65535)
	for {
		n, peer, err := ln.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !quiet {
				fmt.Printf("socat: read %s: %v\n", listener.addr, err)
			}
			continue
		}
		if n == 0 {
			continue
		}
		stats.bytesIn.Add(int64(n))
		// 在派发前复制：buf 是复用缓冲，下一轮 ReadFrom 会覆盖它。
		data := make([]byte, n)
		copy(data, buf[:n])
		sess.enqueue(ctx, peer, data)
	}
}
