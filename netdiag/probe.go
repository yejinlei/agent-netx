package netdiag

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ProbeMode selects the probe protocol. Mirrors hping3 modes:
//
//	-1 / ICMP  原始 ICMP echo（需管理员/root）
//	-S / TCP   TCP 连接探测（SYN 语义，无需特权，全平台可用）
//	-2 / UDP   UDP 探测（无需特权，全平台可用）
type ProbeMode int

const (
	ProbeICMP ProbeMode = iota
	ProbeTCP
	ProbeUDP
)

func (m ProbeMode) String() string {
	switch m {
	case ProbeTCP:
		return "tcp"
	case ProbeUDP:
		return "udp"
	default:
		return "icmp"
	}
}

// ParseProbeMode maps hping3-style selectors to a ProbeMode.
// "1"/"icmp" → ICMP; "S"/"tcp"/"syn" → TCP; "2"/"udp" → UDP.
func ParseProbeMode(s string) (ProbeMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "icmp":
		return ProbeICMP, true
	case "s", "tcp", "syn":
		return ProbeTCP, true
	case "2", "udp":
		return ProbeUDP, true
	}
	return 0, false
}

// ProbeOpts configures one probe session.
type ProbeOpts struct {
	Target      string // 主机或 IP（不含端口）
	Mode        ProbeMode
	Count       int           // 0 = 持续直到被取消（Ctrl-C）
	Interval    time.Duration // 探测间隔；Flood 时为 0
	Timeout     time.Duration // 单次读取/拨号超时
	DataSize    int           // ICMP/UDP 负载字节数
	Port        int           // TCP/UDP 端口
	Interface   string        // 绑定到接口名 → 源 IPv4（ICMP 原始套接字）
	Flood       bool          // hping3 --flood：尽可能快地发送
	SpoofSource string        // hping3 -a：源地址伪装（需原始套接字）
	Verbose     bool          // -V：详细输出
}

// ProbeSample is the result of a single probe.
type ProbeSample struct {
	Seq    int
	RTT    time.Duration
	TTL    int    // 0 = 未知/不可取（原始套接字路径成熟后再填充）
	RecvIP string // 应答来源 IP
	RecvN  int    // 收到的字节数（UDP）
	State  string // "open"/"closed"/"filtered"/"reply"/"timeout"/"error"
	Err    error
}

// ProbeStats aggregates a session.
type ProbeStats struct {
	Sent    int
	Mode    ProbeMode
	Target  string
	Samples []ProbeSample
}

// Recv counts successful samples (a reply / open port).
func (s ProbeStats) Recv() int {
	n := 0
	for _, x := range s.Samples {
		if x.Err == nil && (x.State == "reply" || x.State == "open") {
			n++
		}
	}
	return n
}

// LossPct is the packet-loss percentage.
func (s ProbeStats) LossPct() float64 {
	if s.Sent == 0 {
		return 0
	}
	return float64(s.Sent-s.Recv()) / float64(s.Sent) * 100
}

// rtts returns the RTTs of successful samples in milliseconds.
func (s ProbeStats) rtts() []float64 {
	var out []float64
	for _, x := range s.Samples {
		if x.Err == nil && (x.State == "reply" || x.State == "open") && x.RTT > 0 {
			out = append(out, float64(x.RTT.Microseconds())/1000.0)
		}
	}
	return out
}

func (s ProbeStats) rttMin() float64 { return reduce(s.rtts(), math.Min, math.MaxFloat32) }
func (s ProbeStats) rttMax() float64 { return reduce(s.rtts(), math.Max, 0) }

func (s ProbeStats) rttAvg() float64 {
	v := s.rtts()
	if len(v) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func (s ProbeStats) rttStdDev() float64 {
	v := s.rtts()
	if len(v) < 2 {
		return 0
	}
	mean := s.rttAvg()
	sum := 0.0
	for _, x := range v {
		d := x - mean
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(v)))
}

func reduce(vals []float64, fn func(a, b float64) float64, init float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	r := init
	for _, v := range vals {
		r = fn(r, v)
	}
	return r
}

// Probe runs a probe session. emit (may be nil) is called after each sample
// for live output. ctx cancels infinite (Count==0) sessions and interrupts
// the inter-probe sleep; a blocked ReadFrom honors its deadline (≤Timeout),
// so cancellation may lag up to Timeout after Ctrl-C.
func Probe(ctx context.Context, opts ProbeOpts, emit func(ProbeSample)) (*ProbeStats, error) {
	// 源地址伪装需要构造完整 IP 头，仅原始套接字可做；Windows 的
	// ipv4.RawConn 读写在所有平台上都未实现（x/net packet.go 的 BUG 行），
	// 非 Linux/macOS 管理员直接拒绝。
	if opts.SpoofSource != "" {
		return nil, fmt.Errorf("源地址伪装 (-a) 需要原始套接字（管理员/root）；" +
			"Windows 不支持 RawConn 读写，请在 Linux/macOS 以管理员运行")
	}
	if opts.Target == "" {
		return nil, fmt.Errorf("缺少目标主机")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second
	}
	if opts.DataSize < 0 {
		opts.DataSize = 0
	}

	stats := &ProbeStats{Mode: opts.Mode, Target: opts.Target}
	switch opts.Mode {
	case ProbeTCP:
		return tcpProbe(ctx, opts, stats, emit)
	case ProbeUDP:
		return udpProbe(ctx, opts, stats, emit)
	default:
		return icmpProbe(ctx, opts, stats, emit)
	}
}

// ---------------------------------------------------------------------------
// ICMP

func icmpProbe(ctx context.Context, opts ProbeOpts, stats *ProbeStats, emit func(ProbeSample)) (*ProbeStats, error) {
	dst, err := resolveIPv4(opts.Target)
	if err != nil {
		return stats, err
	}
	bind, err := bindAddrFor(opts.Interface)
	if err != nil {
		return stats, err
	}
	// ip4:icmp 为特权原始套接字：Linux/macOS 需 cap_net_raw 或 root；
	// Windows 需管理员。udp4（非特权数据报 ICMP）仅 Darwin/Linux 可用。
	conn, err := icmp.ListenPacket("ip4:icmp", bind)
	if err != nil {
		return stats, fmt.Errorf("无法打开原始套接字 (ip4:icmp), 请以管理员/root 身份运行: %w\n"+
			"提示: 非特权环境请改用 TCP 探测: agent-netx ping -S -p 80 %s", err, opts.Target)
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	for seq := 1; opts.Count == 0 || seq <= opts.Count; seq++ {
		if ctx.Err() != nil {
			break
		}
		payload := makePayload(opts.DataSize, seq)
		msg := &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: payload},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			return stats, fmt.Errorf("marshal icmp: %w", err)
		}
		t0 := time.Now()
		if _, err := conn.WriteTo(b, &net.IPAddr{IP: dst}); err != nil {
			s := ProbeSample{Seq: seq, State: "error", Err: err}
			stats.Sent++
			stats.Samples = append(stats.Samples, s)
			if emit != nil {
				emit(s)
			}
			if !opts.Flood {
				sleepCtx(ctx, opts.Interval)
			}
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(opts.Timeout))
		s := waitICMPReply(conn, id, seq, t0)
		stats.Sent++
		stats.Samples = append(stats.Samples, s)
		if emit != nil {
			emit(s)
		}
		if !opts.Flood {
			sleepCtx(ctx, opts.Interval)
		}
	}
	return stats, nil
}

// waitICMPReply reads until a matching EchoReply (same ID+Seq) arrives or the
// read deadline passes. Stray packets (other hosts' replies, unrelated ICMP)
// are skipped so they don't steal a probe's reply.
func waitICMPReply(conn *icmp.PacketConn, id, wantSeq int, t0 time.Time) ProbeSample {
	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return ProbeSample{Seq: wantSeq, State: "timeout", Err: err}
		}
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok || echo.ID != id || echo.Seq != wantSeq {
			continue
		}
		peerIP := ""
		if a, ok := peer.(*net.IPAddr); ok {
			peerIP = a.IP.String()
		}
		return ProbeSample{
			Seq:    wantSeq,
			RTT:    time.Since(t0),
			RecvIP: peerIP,
			State:  "reply",
		}
	}
}

// ---------------------------------------------------------------------------
// TCP (连接探测 / "SYN")

func tcpProbe(ctx context.Context, opts ProbeOpts, stats *ProbeStats, emit func(ProbeSample)) (*ProbeStats, error) {
	if opts.Port == 0 {
		opts.Port = 80
	}
	addr := net.JoinHostPort(opts.Target, strconv.Itoa(opts.Port))
	for seq := 1; opts.Count == 0 || seq <= opts.Count; seq++ {
		if ctx.Err() != nil {
			break
		}
		t0 := time.Now()
		d := net.Dialer{Timeout: opts.Timeout}
		c, err := d.DialContext(ctx, "tcp", addr)
		rt := time.Since(t0)
		if err != nil {
			state := "timeout"
			// 端口关闭（RST / ECONNREFUSED）必须与超时区分开：前者表示"端口确实
			// 不存在"，后者表示"SYN 被丢弃或被过滤"。与 udpProbe 的分类保持一致。
			if isRefused(err) {
				state = "closed"
			}
			s := ProbeSample{Seq: seq, RTT: rt, State: state, Err: err}
			stats.Sent++
			stats.Samples = append(stats.Samples, s)
			if emit != nil {
				emit(s)
			}
		} else {
			ip := ""
			if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
				ip = a.IP.String()
			}
			_ = c.Close()
			s := ProbeSample{Seq: seq, RTT: rt, RecvIP: ip, State: "open"}
			stats.Sent++
			stats.Samples = append(stats.Samples, s)
			if emit != nil {
				emit(s)
			}
		}
		if !opts.Flood {
			sleepCtx(ctx, opts.Interval)
		}
	}
	return stats, nil
}

// ---------------------------------------------------------------------------
// UDP

func udpProbe(ctx context.Context, opts ProbeOpts, stats *ProbeStats, emit func(ProbeSample)) (*ProbeStats, error) {
	if opts.Port == 0 {
		opts.Port = 33434 // 默认 traceroute 端口，便于探测
	}
	addr := net.JoinHostPort(opts.Target, strconv.Itoa(opts.Port))
	for seq := 1; opts.Count == 0 || seq <= opts.Count; seq++ {
		if ctx.Err() != nil {
			break
		}
		c, err := net.DialTimeout("udp", addr, opts.Timeout)
		if err != nil {
			s := ProbeSample{Seq: seq, State: "error", Err: err}
			stats.Sent++
			stats.Samples = append(stats.Samples, s)
			if emit != nil {
				emit(s)
			}
			if !opts.Flood {
				sleepCtx(ctx, opts.Interval)
			}
			continue
		}
		// RemoteAddr 在 Close 后可能返回 nil，先取。
		peerIP := ""
		if a, ok := c.RemoteAddr().(*net.UDPAddr); ok {
			peerIP = a.IP.String()
		}
		_ = c.SetDeadline(time.Now().Add(opts.Timeout))
		payload := makePayload(opts.DataSize, seq)
		t0 := time.Now()
		_, _ = c.Write(payload)
		rb := make([]byte, 1500)
		n, err := c.Read(rb)
		rt := time.Since(t0)
		_ = c.Close()

		s := ProbeSample{Seq: seq, RTT: rt, RecvIP: peerIP, RecvN: n}
		switch {
		case err == nil:
			s.State = "open"
		case isRefused(err):
			s.State = "closed"
			s.Err = err
		default:
			// 超时：UDP 语义本身有歧义——端口开放但无应答，或被过滤。
			s.State = "filtered"
			s.Err = err
		}
		stats.Sent++
		stats.Samples = append(stats.Samples, s)
		if emit != nil {
			emit(s)
		}
		if !opts.Flood {
			sleepCtx(ctx, opts.Interval)
		}
	}
	return stats, nil
}

// isRefused 判定 ICMP port-unreachable（端口确实关闭）。各平台错误码不同：
// Linux/macOS 把该不可达映射为 ECONNREFUSED；Windows 映射为 WSAECONNRESET
// (10054)，只认前者会让 Windows 上"端口关闭"被误报成 filtered。错误码缺失
// 的平台回落到错误文本匹配。
func isRefused(err error) bool {
	if err == nil {
		return false
	}
	for _, want := range []syscall.Errno{syscall.ECONNREFUSED, syscall.ECONNRESET} {
		if errors.Is(err, want) {
			return true
		}
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "refused") || strings.Contains(s, "connection reset")
}

// ---------------------------------------------------------------------------
// Traceroute — 委托给系统工具（Windows tracert / 其他 traceroute）。
// 这些工具在非管理员下可用（Windows tracert 使用 ICMP，普通权限即可），
// 比 x/net 在 Windows 上未实现的 RawConn 路径更可靠、更诚实。

// Traceroute runs the OS traceroute and streams its output to w.
func Traceroute(target string, maxHops int, w io.Writer) error {
	if maxHops <= 0 {
		maxHops = 30
	}
	name := "traceroute"
	args := []string{"-m", strconv.Itoa(maxHops), target}
	if runtime.GOOS == "windows" {
		name = "tracert"
		args = []string{"-d", "-h", strconv.Itoa(maxHops), target}
	}
	cmd := exec.Command(name, args...)
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, target, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// helpers

// resolveIPv4 resolves a host to its first IPv4 address.
func resolveIPv4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("%s 不是 IPv4 地址", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("解析 %s: %w", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("未找到 %s 的 IPv4 地址", host)
}

// bindAddrFor maps an interface name to a source IPv4 (for ICMP bind).
// Empty name → "0.0.0.0" (all interfaces).
func bindAddrFor(ifaceName string) (string, error) {
	if ifaceName == "" {
		return "0.0.0.0", nil
	}
	stats, err := GetInterfaces()
	if err != nil {
		return "", fmt.Errorf("枚举接口: %w", err)
	}
	for _, s := range stats {
		if !strings.EqualFold(s.Name, ifaceName) {
			continue
		}
		for _, a := range s.Addrs {
			ipStr := a
			if i := strings.IndexByte(ipStr, '/'); i >= 0 {
				ipStr = ipStr[:i]
			}
			if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
				return ipStr, nil
			}
		}
	}
	return "", fmt.Errorf("接口 %q 未找到或无 IPv4 地址", ifaceName)
}

func makePayload(size, seq int) []byte {
	if size > 65507 {
		size = 65507
	}
	b := make([]byte, size)
	for i := range b {
		b[i] = byte('a' + (i+seq)%26) // 可识别的填充，便于抓包辨认
	}
	return b
}

func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
