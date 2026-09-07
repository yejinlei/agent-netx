package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"agent-netx/agent"
	"agent-netx/config"
	"agent-netx/dns"
	"agent-netx/listener"
	"agent-netx/mitm"
	"agent-netx/n2n"
	"agent-netx/proxy"
	"agent-netx/router"
	"agent-netx/stunvpv"
	"agent-netx/tun"
	"agent-netx/web"
)

// This file holds the per-subsystem runners shared by `start` (full mode) and
// the standalone subcommands (proxy/dns/web/tun/n2n/stunvpv). Each runner
// builds one component from the loaded config and runs it in the foreground
// (blocking until ctx is cancelled or a fatal error occurs). Running them
// standalone is the "non-TUI, tools run independently" mode; the agent's
// `service` tool spawns/stops these same commands from inside the TUI.

func buildRouter(cfg *config.Config) (*router.Router, *proxy.Registry, error) {
	if err := config.MergeDynamic(cfg, agent.DynamicPath()); err != nil {
		return nil, nil, fmt.Errorf("merge dynamic config: %w", err)
	}
	reg, err := proxy.Register(cfg.Proxies)
	if err != nil {
		return nil, nil, fmt.Errorf("register proxies: %w", err)
	}
	rtr, err := router.New(cfg.Mode, cfg.Rules, reg)
	if err != nil {
		return nil, nil, fmt.Errorf("init router: %w", err)
	}
	reg.Each(func(name string, p proxy.Proxy) {
		if ut, ok := p.(*proxy.URLTest); ok {
			ut.Probe()
		}
	})
	return rtr, reg, nil
}

// bridgeTUN attaches a kernel TUN device to an overlay transport (n2n edge or
// stunvpv client), forming the all-layer VPN data path:
//
//	outgoing: TUN.Read → parsePacket(dst) → peer.SendTo(dst, pkt)
//	incoming: peer.OnData(src, pkt) → tunDev.WritePacket(pkt) → TUN.Write
//
// It is a no-op when TUN is disabled or useTun is false (--no-tun). The TUN
// runs in its own goroutine so the caller's transport Start can block in the
// foreground; both share the same ctx and stop together.
//
// Supernode/server modes never bridge (a relay is not a traffic endpoint).
// OnData is a setter, so this replaces any prior (log-only) callback — no leak.
func bridgeTUN(ctx context.Context, cfg *config.Config, useTun bool, peer tun.Peer, logRing *web.LogRing) {
	if !useTun || !cfg.TUN.Enable {
		return
	}
	tunDev := tun.NewTunDevice(tun.TunConfig{
		Enable:  true,
		Device:  cfg.TUN.Device,
		MTU:     cfg.TUN.MTU,
		Gateway: cfg.TUN.Gateway,
		CIDR:    cfg.TUN.CIDR,
		DNS:     cfg.TUN.DNS,
	})
	tunDev.SetPeer(peer)
	peer.OnData(func(srcIP net.IP, data []byte) {
		tunDev.WritePacket(data)
		if logRing != nil {
			logRing.Write(web.DEBUG, "tun: <-%s (%d bytes)", srcIP, len(data))
		}
	})
	if logRing != nil {
		logRing.Write(web.INFO, "tun: bridged to overlay (device=%s cidr=%s)", cfg.TUN.Device, cfg.TUN.CIDR)
	}
	go func() {
		if err := tunDev.Start(ctx); err != nil {
			if logRing != nil {
				logRing.Write(web.ERROR, "tun: %v", err)
			}
		}
	}()
}

// runProxy starts the HTTP/SOCKS5 listener with the configured proxies and
// router. Blocks until ctx is cancelled or a listener fails. stats, when
// non-nil, receives per-proxy traffic + connection accounting; it is the same
// tracker the web dashboard reads, so fullStart passes one shared instance.
func runProxy(ctx context.Context, cfg *config.Config, logRing *web.LogRing, stats *web.StatsTracker) error {
	rtr, _, err := buildRouter(cfg)
	if err != nil {
		return err
	}

	lst, err := listener.New(listener.Options{
		HTTPPort:    cfg.Listen.HTTP,
		SOCKS5Port:  cfg.Listen.SOCKS5,
		TProxyPort:  cfg.Listen.TProxy,
		TProxyMark:  cfg.Listen.TProxyMark,
		TProxyTable: cfg.Listen.TProxyTable,
		Router:      rtr,
		MITM:        buildMITMHandler(cfg, logRing),
		URLActions:  cfg.MITM.URLActions,
		Stats:       stats,
		Hooks:       buildFlowHooks(cfg),
		Sinks:       buildFlowSinks(cfg),
		Upstream:    buildUpstreamProxy(cfg),
	})
	if err != nil {
		return fmt.Errorf("init listener: %w", err)
	}
	if logRing != nil {
		logRing.Write(web.INFO, "proxy: http=:%d socks5=:%d tproxy=:%d mode=%s", cfg.Listen.HTTP, cfg.Listen.SOCKS5, cfg.Listen.TProxy, cfg.Mode)
	}
	go func() {
		<-ctx.Done()
		lst.Stop()
	}()
	return lst.Start()
}

// runDNS starts the local DNS server. Blocks until ctx is cancelled.
func runDNS(ctx context.Context, cfg *config.Config, logRing *web.LogRing) error {
	dnsCfg := dns.DnsConfig{
		Enable:    true,
		Listen:    cfg.DNS.Listen,
		Mode:      cfg.DNS.Mode,
		DoHServer: cfg.DNS.DoHServer,
		DoTServer: cfg.DNS.DoTServer,
		FakeCIDR:  cfg.DNS.FakeCIDR,
	}
	srv, err := dns.NewServer(dnsCfg)
	if err != nil {
		return fmt.Errorf("init dns: %w", err)
	}
	if logRing != nil {
		logRing.Write(web.INFO, "dns: server starting on %s (mode=%s)", cfg.DNS.Listen, cfg.DNS.Mode)
	}
	return srv.Start(ctx)
}

// runWeb starts the dashboard. Blocks until ctx is cancelled.
func runWeb(ctx context.Context, cfg *config.Config) error {
	logRing := web.NewLogRing(1000)
	statsTracker := web.NewStatsTracker()
	webCfg := web.WebConfig{
		Enable:   true,
		Port:     cfg.Web.Port,
		Username: cfg.Web.Username,
		Password: cfg.Web.Password,
	}
	srv := web.NewWebServer(webCfg, logRing, statsTracker)
	return srv.Start(ctx)
}

// runTUN starts the TUN device (route config only for now; packet I/O is a
// pending task). Blocks until ctx is cancelled.
func runTUN(ctx context.Context, cfg *config.Config, logRing *web.LogRing) error {
	tunCfg := tun.TunConfig{
		Enable:  true,
		Device:  cfg.TUN.Device,
		MTU:     cfg.TUN.MTU,
		Gateway: cfg.TUN.Gateway,
		CIDR:    cfg.TUN.CIDR,
		DNS:     cfg.TUN.DNS,
	}
	dev := tun.NewTunDevice(tunCfg)
	if logRing != nil {
		logRing.Write(web.INFO, "tun: device %s starting (cidr=%s)", cfg.TUN.Device, cfg.TUN.CIDR)
	}
	return dev.Start(ctx)
}

// runN2N starts an n2n supernode or edge. Blocks until ctx is cancelled.
// When running as an edge with TUN enabled (and not --no-tun), the edge is
// auto-bridged to a kernel TUN for the real VPN data path. Supernodes are pure
// relays and never get a TUN — they forward between peers, not to apps.
func runN2N(ctx context.Context, cfg *config.Config, logRing *web.LogRing, useTun bool) error {
	n2nCfg := n2n.Config{
		Enable:      true,
		Mode:        cfg.N2N.Mode,
		Listen:      cfg.N2N.Listen,
		Supernode:   cfg.N2N.Supernode,
		Community:   cfg.N2N.Community,
		Password:    cfg.N2N.Password,
		VirtualIP:   cfg.N2N.VirtualIP,
		VirtualCIDR: cfg.N2N.VirtualCIDR,
		MTU:         cfg.N2N.MTU,
		Interval:    cfg.N2N.Interval,
	}
	switch cfg.N2N.Mode {
	case "supernode":
		sn, err := n2n.NewSupernode(n2nCfg)
		if err != nil {
			return fmt.Errorf("n2n supernode: %w", err)
		}
		if logRing != nil {
			logRing.Write(web.INFO, "n2n: supernode starting on %s (community=%s)", cfg.N2N.Listen, cfg.N2N.Community)
		}
		return sn.Start(ctx)
	case "edge":
		edge, err := n2n.NewEdge(n2nCfg)
		if err != nil {
			return fmt.Errorf("n2n edge: %w", err)
		}
		bridgeTUN(ctx, cfg, useTun, edge, logRing) // registers OnData → TUN when enabled
		if logRing != nil {
			logRing.Write(web.INFO, "n2n: edge starting, supernode=%s", cfg.N2N.Supernode)
		}
		return edge.Start(ctx)
	default:
		return fmt.Errorf("n2n: unknown mode %q", cfg.N2N.Mode)
	}
}

// runSTUNVPV starts a STUN/TURN supernode (server) or client. Blocks until
// ctx is cancelled. When running as a client with TUN enabled (and not
// --no-tun), the client is auto-bridged to a kernel TUN for the real VPN data
// path. Servers are pure relays and never get a TUN.
func runSTUNVPV(ctx context.Context, cfg *config.Config, logRing *web.LogRing, useTun bool) error {
	stunCfg := stunvpv.Config{
		Enable:      true,
		Mode:        cfg.STUNVPN.Mode,
		Listen:      cfg.STUNVPN.Listen,
		TURNServer:  cfg.STUNVPN.TURNServer,
		Realm:       cfg.STUNVPN.Realm,
		Username:    cfg.STUNVPN.Username,
		Password:    cfg.STUNVPN.Password,
		VirtualCIDR: cfg.STUNVPN.VirtualCIDR,
		MTU:         cfg.STUNVPN.MTU,
	}
	switch cfg.STUNVPN.Mode {
	case "supernode":
		sn, err := stunvpv.NewServer(stunCfg)
		if err != nil {
			return fmt.Errorf("stunvpv server: %w", err)
		}
		if logRing != nil {
			logRing.Write(web.INFO, "stunvpv: server starting on %s (cidr=%s)", cfg.STUNVPN.Listen, cfg.STUNVPN.VirtualCIDR)
		}
		return sn.Start(ctx)
	case "client":
		cl, err := stunvpv.NewClient(stunCfg)
		if err != nil {
			return fmt.Errorf("stunvpv client: %w", err)
		}
		bridgeTUN(ctx, cfg, useTun, cl, logRing) // registers OnData → TUN when enabled
		if logRing != nil {
			logRing.Write(web.INFO, "stunvpv: client starting, server=%s", cfg.STUNVPN.TURNServer)
		}
		return cl.Start(ctx)
	default:
		return fmt.Errorf("stunvpv: unknown mode %q", cfg.STUNVPN.Mode)
	}
}

// buildMITMHandler builds a listener.MITMHandler when MITM is enabled with
// a non-empty allowlist. Empty allowlist disables interception even with
// enable=true (安全红线: default-deny). Returns nil when MITM is off or
// the CA cannot be loaded/generated (logs a warning in that case).
func buildMITMHandler(cfg *config.Config, logRing *web.LogRing) *listener.MITMHandler {
	if !cfg.MITM.Enable {
		return nil
	}
	if len(cfg.MITM.Allowlist) == 0 {
		if logRing != nil {
			logRing.Write(web.WARN, "mitm: enabled but allowlist is empty — interception disabled (安全红线)")
		}
		return nil
	}
	caCert, err := mitm.LoadCA(cfg.MITM.CAPath+".crt", cfg.MITM.CAPath+".key")
	if err != nil {
		if logRing != nil {
			logRing.Write(web.WARN, "mitm: cannot load CA, generating new one: %v", err)
		}
		caCert, err = mitm.GenerateCA("net-redirect")
		if err != nil {
			if logRing != nil {
				logRing.Write(web.ERROR, "mitm: generate CA: %v", err)
			}
			return nil
		}
		if err := caCert.SaveTo(cfg.MITM.CAPath); err != nil {
			if logRing != nil {
				logRing.Write(web.ERROR, "mitm: save CA: %v", err)
			}
			return nil
		}
	}
	if logRing != nil {
		logRing.Write(web.INFO, "mitm: HTTPS interception ready (allowlist=%d rules)", len(cfg.MITM.Allowlist))
	}
	var mitmLogFile *os.File
	if cfg.MITM.LogPath != "" {
		f, err := os.OpenFile(cfg.MITM.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("mitm: open log %s: %v", cfg.MITM.LogPath, err)
		} else {
			mitmLogFile = f
		}
	}
	mh := &listener.MITMHandler{
		Interceptor:    mitm.NewInterceptor(caCert, cfg.MITM.CertDir),
		Allowlist:      cfg.MITM.Allowlist,
		SkipHosts:      cfg.MITM.SkipHosts,
		VerifyUpstream: cfg.MITM.VerifyUpstream,
		EgressProxy:    nil,
		RewriteRules:   cfg.MITM.Rewrite,
		LogFile:        mitmLogFile,
		URLActions:     cfg.MITM.URLActions,
	}
	if cfg.MITM.ClientCrt != "" || cfg.MITM.ClientKey != "" {
		cert, cerr := loadClientCertPair(cfg.MITM.ClientCrt, cfg.MITM.ClientKey)
		if cerr != nil {
			log.Printf("mitm: client cert: %v (continuing without origin mTLS)", cerr)
		} else {
			mh.ClientCert = cert
		}
	}
	return mh
}

// (MITM interception used to run as a standalone subsystem here; it now lives
// inside runProxy via buildMITMHandler, which is the canonical init path.)

// buildFlowSinks returns the FlowSink slice for the listener. Two sinks
// are wired: a JSON-line writer (config.Flow.LogPath) and an optional
// SQLite writer (config.Flow.DBPath). Both fire on every Flow when both
// are configured; enable=false returns nil.
func buildFlowSinks(cfg *config.Config) []listener.FlowSink {
	if !cfg.Flow.Enable {
		return nil
	}
	var sinks []listener.FlowSink
	if cfg.Flow.LogPath != "" {
		s, err := listener.NewJSONFlowSink(cfg.Flow.LogPath)
		if err != nil {
			log.Printf("flow: cannot open log %s: %v", cfg.Flow.LogPath, err)
		} else {
			sinks = append(sinks, s)
		}
	}
	if cfg.Flow.DBPath != "" {
		s, err := listener.NewSQLiteSink(cfg.Flow.DBPath)
		if err != nil {
			log.Printf("flow: cannot open sqlite db %s: %v", cfg.Flow.DBPath, err)
		} else {
			sinks = append(sinks, s)
		}
	}
	return sinks
}

// buildFlowHooks returns the FlowHooks slice. Reserved for future in-code
// policy hooks (e.g. a rate-limiter, a PII-redactor, a per-client denylist);
// config does not expose them yet, so this returns nil. Keeping the factory
// means future config-driven hooks are a one-file change, not a wiring
// change in runProxy.
func buildFlowHooks(cfg *config.Config) listener.FlowHooks {
	return nil
}

// buildUpstreamProxy parses cfg.Upstream.URL into an outbound UpstreamProxy.
// Nil URL or parse error → nil (no upstream chain; dials go direct). The
// listener's dialDirect falls back to a raw TCP dial when this returns nil,
// so a malformed upstream URL is a soft failure: traffic keeps flowing.
// When cfg.Upstream.ClientCrt/ClientKey are set, the pair is loaded and
// presented on the outbound TLS session (mTLS to the egress proxy). A
// malformed pair is a soft failure too — the upstream still works without
// the cert, matching mitmproxy's `-u` behavior.
func buildUpstreamProxy(cfg *config.Config) *proxy.UpstreamProxy {
	if cfg.Upstream.URL == "" {
		return nil
	}
	timeout := time.Duration(cfg.Upstream.Timeout) * time.Second
	u, err := proxy.NewUpstreamProxy(cfg.Upstream.URL, timeout)
	if err != nil {
		log.Printf("upstream: %v", err)
		return nil
	}
	if cfg.Upstream.ClientCrt != "" || cfg.Upstream.ClientKey != "" {
		cert, cerr := loadClientCertPair(cfg.Upstream.ClientCrt, cfg.Upstream.ClientKey)
		if cerr != nil {
			log.Printf("upstream: client cert: %v (continuing without mTLS)", cerr)
		} else {
			u.SetClientCert(cert)
		}
	}
	return u
}

// loadClientCertPair loads a PEM client cert + key pair into a
// tls.Certificate. Both paths must be non-empty; partial config is an
// error (a cert without a key can't complete a handshake). Only PEM is
// accepted — PKCS#12 is a common corporate format but parsing it would
// require either a password (not exposed in config) or an external tool.
func loadClientCertPair(crtPath, keyPath string) (*tls.Certificate, error) {
	if crtPath == "" || keyPath == "" {
		return nil, fmt.Errorf("both client-crt and client-key required")
	}
	crtPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, fmt.Errorf("read crt %q: %w", crtPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %q: %w", keyPath, err)
	}
	cert, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse pair: %w", err)
	}
	return &cert, nil
}
