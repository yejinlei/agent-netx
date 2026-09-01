package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"agent-netx/agent"
	"agent-netx/config"
	"agent-netx/forward"
	"agent-netx/proxy"

	"github.com/spf13/cobra"
)

// forwardCmd implements SSH-style multi-mode port forwarding. Each mode is a
// clean sub-function in the `forward` package; this command is the thin CLI
// dispatcher. Adding a new mode = one case here + one function in forward.
//
//	forward local    <listen> <dst>             (-L)   local listener → fixed dst
//	forward remote   <sshAlias> <rListen> <dst> (-R)  listener on a remote SSH host → local dst
//	forward dynamic  <listen>                   (-D)   local SOCKS5 listener → any dst
//	forward udp      <listen> <dst>             (-U)   local UDP listener → fixed UDP dst (DNS, etc.)
//	forward tls      <listen> <dst> [sni]              HTTPS listener → plain-HTTP backend
//	forward reverse  <listen> <target>            HTTP reverse proxy: 本地端口 → 固定上游 (mitmproxy reverse 模式)
//
// --proxy <name> routes the *destination dial* through a configured proxy
// (resolved from config.yml), so forwarding can egress via SS/Trojan/etc.
// Without --proxy, the destination is reached directly (forward.Direct).
func forwardCmd() *cobra.Command {
	var proxyName string
	cmd := &cobra.Command{
		Use:   "forward <mode> ...",
		Short: "SSH 风格端口转发: local(-L)/remote(-R)/dynamic(-D)/udp(-U)/tls",
		Long: `SSH 风格的多模式端口转发。每个模式对应 forward 包里的一个函数，新增模式只需加一个 case。

  forward local   <listen> <dst>              # 本地监听 → 固定目标 (-L)
  forward remote  <sshAlias> <rListen> <dst>   # 远程主机上的监听 → 本地目标 (-R)
  forward dynamic <listen>                     # 本地 SOCKS5 监听 → 任意目标 (-D)
  forward udp     <listen> <dst>               # 本地 UDP 监听 → 固定 UDP 目标 (-U，DNS/QUIC 等)
  forward tls     <listen> <dst> [sni]         # HTTPS 监听 → 明文 HTTP 后端
  forward reverse <listen> <target>          # HTTP 反向代理：本地端口 → 固定上游 (mitmproxy reverse)

--proxy <name>  让目标拨号走配置文件里的指定代理（SS/Trojan 等）；不指定则直连。
  forward local :8080 example.com:80 --proxy prod-ss
  forward udp :1053 1.1.1.1:53 --proxy prod-socks5   # 通过 SOCKS5 的 UDP ASSOCIATE 代理 DNS

示例:
  agent-netx forward local 127.0.0.1:3306 db.internal:3306
  agent-netx forward dynamic 1080
  agent-netx forward remote prod :9090 127.0.0.1:8080
  agent-netx forward udp 127.0.0.1:1053 1.1.1.1:53 --proxy prod-socks5
  agent-netx forward tls 0.0.0.0:443 127.0.0.1:80
  agent-netx forward reverse :8080 https://internal.example.com:9090`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("usage: forward <local|remote|dynamic|tls> ...")
			}
			mode := strings.ToLower(args[0])
			rest := args[1:]

			// Build the destination dialer. --proxy wires a configured proxy's
			// Connect into the forward.Dialer signature; nil → direct.
			dialer, cleanup, err := buildDialer(cmd, proxyName)
			if err != nil {
				return err
			}
			defer cleanup()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, os.Interrupt)
				<-sigCh
				fmt.Println("\n收到中断信号，停止转发…")
				cancel()
			}()

			switch mode {
			case "local", "-l", "-L":
				return forwardLocal(ctx, rest, dialer)
			case "remote", "-r", "-R":
				return forwardRemote(ctx, rest, dialer)
			case "dynamic", "-d", "-D":
				return forwardDynamic(ctx, rest, dialer)
			case "udp", "-u", "-U":
				return forwardUDP(ctx, rest, cmd, proxyName)
			case "tls":
				return forwardTLS(ctx, rest)
			case "reverse":
				return forwardReverse(ctx, rest)
			default:
				return fmt.Errorf("unknown mode %q (want local|remote|dynamic|udp|tls|reverse)", mode)
			}
		},
	}
	cmd.Flags().StringVar(&proxyName, "proxy", "", "目标拨号经由配置文件里的某个代理（名称）；不填则直连")
	return cmd
}

// buildDialer returns a forward.Dialer. If proxyName is set, it loads config,
// registers proxies, picks the named one, and returns a Dialer that calls
// proxy.Connect(ctx, addr). Otherwise it returns forward.Direct (nil). The
// cleanup func closes any proxy the dialer owns.
//
// This is the seam where forwarding composes with the proxy layer (and with
// Chain, since chains are themselves proxies in the registry): to add
// rule-based "auto" picking later, swap this function — the modes don't change.
func buildDialer(cmd *cobra.Command, proxyName string) (forward.Dialer, func(), error) {
	if proxyName == "" {
		return forward.Direct, func() {}, nil
	}
	cfg, err := loadCfg(cmd)
	if err != nil {
		return nil, nil, err
	}
	reg, err := proxy.Register(cfg.Proxies)
	if err != nil {
		return nil, nil, fmt.Errorf("register proxies: %w", err)
	}
	p, err := reg.Get(proxyName)
	if err != nil {
		return nil, nil, err
	}
	d := func(ctx context.Context, addr string) (net.Conn, error) {
		return p.Connect(ctx, addr)
	}
	return d, func() { p.Close() }, nil
}

// loadCfg loads config.yml (or --config path), shared with other subcommands.
func loadCfg(cmd *cobra.Command) (*config.Config, error) {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		cwd, _ := os.Getwd()
		cfgPath = filepath.Join(cwd, "config.yml")
	}
	return config.Load(cfgPath)
}

func forwardLocal(ctx context.Context, args []string, dialer forward.Dialer) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: forward local <listen> <dst>")
	}
	return forward.Local(ctx, args[0], args[1], dialer)
}

func forwardDynamic(ctx context.Context, args []string, dialer forward.Dialer) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: forward dynamic <listen>")
	}
	return forward.Dynamic(ctx, args[0], dialer)
}

func forwardUDP(ctx context.Context, args []string, cmd *cobra.Command, proxyName string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: forward udp <listen> <dst>")
	}
	pd, cleanup, err := buildPacketDialer(cmd, proxyName)
	if err != nil {
		return err
	}
	defer cleanup()
	return forward.UDP(ctx, args[0], args[1], pd)
}

// buildPacketDialer returns a forward.PacketDialer for the udp mode. If
// proxyName is set, it resolves the proxy from config and type-asserts it to
// proxy.PacketProxy (the UDP-capable interface); only SOCKS5 qualifies today.
// If the named proxy doesn't support UDP, it's a user-facing error rather than
// a silent fallback to direct — the user asked to proxy UDP, so failing loud
// is correct. With no --proxy, returns nil (= direct UDP) and a no-op cleanup.
func buildPacketDialer(cmd *cobra.Command, proxyName string) (forward.PacketDialer, func(), error) {
	if proxyName == "" {
		return nil, func() {}, nil
	}
	cfg, err := loadCfg(cmd)
	if err != nil {
		return nil, nil, err
	}
	reg, err := proxy.Register(cfg.Proxies)
	if err != nil {
		return nil, nil, fmt.Errorf("register proxies: %w", err)
	}
	p, err := reg.Get(proxyName)
	if err != nil {
		return nil, nil, err
	}
	pp, ok := proxy.AsPacketProxy(p)
	if !ok {
		return nil, nil, fmt.Errorf("proxy %q (%s) does not support UDP — only SOCKS5 does", proxyName, p.Name())
	}
	d := func(ctx context.Context) (net.PacketConn, error) {
		return pp.ConnectUDP(ctx)
	}
	return d, func() { p.Close() }, nil
}

func forwardTLS(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: forward tls <listen> <dst> [sni]")
	}
	sni := ""
	if len(args) >= 3 {
		sni = args[2]
	}
	return forward.TLS(ctx, args[0], args[1], sni)
}

func forwardReverse(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: forward reverse <listen> <target>")
	}
	return forward.Reverse(ctx, args[0], args[1])
}

// forwardRemote implements -R: open a listener ON a remote SSH host (resolved
// via --alias/memory/HIL like scp), tunnel connections back, and dial the
// local dst from here. The SSH client lives for the lifetime of the forwarder.
func forwardRemote(ctx context.Context, args []string, dialer forward.Dialer) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: forward remote <sshAlias> <remoteListen> <localDst>")
	}
	alias := args[0]
	remoteListen := args[1]
	localDst := args[2]

	h, err := resolveForwardSSHHost(ctx, alias)
	if err != nil {
		return err
	}
	sshClient, err := agent.DialSSH(ctx, h)
	if err != nil {
		return fmt.Errorf("ssh dial %s@%s:%d: %w", h.User, h.Host, agent.PortOf(h), err)
	}
	defer sshClient.Close()

	// Open a TCP listener on the remote host. ssh.Client.Listen does
	// "tcpip-forward" channel-based listening — exactly SSH -R semantics.
	openRemote := func(ctx context.Context, addr string) (net.Listener, error) {
		return sshClient.Listen("tcp", addr)
	}
	return forward.Remote(ctx, remoteListen, localDst, dialer, openRemote)
}

// resolveForwardSSHHost mirrors scp's host resolution: alias → memory → HIL,
// so a host remembered via `scp --alias prod` is reused by `forward remote prod`.
func resolveForwardSSHHost(ctx context.Context, alias string) (agent.HostInfo, error) {
	mem := agent.NewMemory(agent.DefaultMemoryPath())
	ask := agent.PromptOrSilentForCmd()
	if ask == nil {
		fmt.Fprintln(os.Stderr, "⚠️ stdin 非 TTY：缺少的 SSH 连接信息将无法交互询问，请先用 scp --alias 记住主机。")
	}
	return agent.ResolveHost(ctx, alias, "", "", "", "", 0, mem, ask)
}
