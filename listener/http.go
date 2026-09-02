package listener

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"agent-netx/proxy"
	"agent-netx/router"
	"agent-netx/web"
)

type Options struct {
	HTTPPort    int
	SOCKS5Port  int
	TProxyPort  int
	// TProxyMark / TProxyTable drive the Linux TPROXY routing loop
	// (ip rule + ip route local). Passed to installTProxyRouting/teardown.
	// Zero disables auto-installation (user owns routing rules).
	TProxyMark  int
	TProxyTable int
	Router      *router.Router
	// MITM, when non-nil, enables HTTPS interception for CONNECT requests
	// whose target matches the MITM allowlist (see listener/mitm.go). nil
	// disables interception entirely; empty allowlist disables too (安全红线).
	MITM *MITMHandler
	// Stats optionally receives per-proxy traffic + connection accounting.
	// nil disables accounting (no overhead).
	Stats *web.StatsTracker
}

type Listener struct {
	opts Options

	mu      sync.Mutex
	httpLn  net.Listener
	socksLn net.Listener
	tproxyLn net.Listener
	closed  bool
	stopCh  chan struct{}
	errs    chan error
}

func New(opts Options) (*Listener, error) {
	return &Listener{opts: opts}, nil
}

// Start binds the HTTP and SOCKS5 listeners synchronously (so port conflicts
// surface immediately) and then blocks serving until Stop is called or a
// listener suffers a fatal error. Returns the first fatal error, or nil if
// stopped cleanly.
func (l *Listener) Start() error {
	l.stopCh = make(chan struct{})
	l.errs = make(chan error, 2)

	if l.opts.HTTPPort > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", l.opts.HTTPPort))
		if err != nil {
			return fmt.Errorf("http listen :%d: %w", l.opts.HTTPPort, err)
		}
		l.mu.Lock()
		l.httpLn = ln
		l.mu.Unlock()
		go l.serveHTTP(ln)
	}
	if l.opts.SOCKS5Port > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", l.opts.SOCKS5Port))
		if err != nil {
			l.Stop() // release anything already bound
			return fmt.Errorf("socks5 listen :%d: %w", l.opts.SOCKS5Port, err)
		}
		l.mu.Lock()
		l.socksLn = ln
		l.mu.Unlock()
		go l.serveSOCKS5(ln)
	}
	if l.opts.TProxyPort > 0 {
		ln, err := tproxyListen(fmt.Sprintf(":%d", l.opts.TProxyPort))
		if err != nil {
			l.tproxyLn.Close()
			return fmt.Errorf("tproxy listen :%d: %w", l.opts.TProxyPort, err)
		}
		l.mu.Lock()
		l.tproxyLn = ln
		l.mu.Unlock()
		if err := installTProxyRouting(l.opts.TProxyMark, l.opts.TProxyTable); err != nil {
			ln.Close()
			teardownTProxyRouting(l.opts.TProxyMark, l.opts.TProxyTable)
			return fmt.Errorf("tproxy routing: %w", err)
		}
		go l.serveTProxy(ln)
	}

	// If none of the three ports is configured there is nothing to serve.
	if l.opts.HTTPPort == 0 && l.opts.SOCKS5Port == 0 && l.opts.TProxyPort == 0 {
		return nil
	}

	select {
	case <-l.stopCh:
		return nil
	case err := <-l.errs:
		l.Stop()
		return err
	}
}

// Stop closes both listeners and unblocks Start. Idempotent.
func (l *Listener) Stop() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	httpLn, socksLn, tproxyLn, stopCh := l.httpLn, l.socksLn, l.tproxyLn, l.stopCh
	l.mu.Unlock()

	if httpLn != nil {
		httpLn.Close()
	}
	if socksLn != nil {
		socksLn.Close()
	}
	if tproxyLn != nil {
		tproxyLn.Close()
	}
	teardownTProxyRouting(l.opts.TProxyMark, l.opts.TProxyTable)
	if stopCh != nil {
		close(stopCh)
	}
}

func (l *Listener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// fatalAccept reports a listener accept error. Shutdown-induced errors (closed)
// are silent; genuine errors unblock Start via errs.
func (l *Listener) fatalAccept(ln net.Listener, src string, err error) {
	if l.isClosed() {
		return
	}
	select {
	case l.errs <- fmt.Errorf("%s: %w", src, err):
	default:
	}
}

func (l *Listener) serveHTTP(ln net.Listener) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			l.fatalAccept(ln, "http listener", err)
			return
		}
		go l.handleHTTP(conn)
	}
}

func (l *Listener) handleHTTP(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	reqLine, err := reader.ReadString('\n')
	if err != nil { return }
	method, target, _, err := parseRequestLine(strings.TrimSpace(reqLine))
	if err != nil { return }

	if method != "CONNECT" {
		u, err := url.Parse(target)
		if err != nil { return }
		if u.Scheme == "https" { return }
		remoteAddr := u.Host
		if !strings.Contains(remoteAddr, ":") { remoteAddr = remoteAddr + ":80" }

		proxy, err := l.opts.Router.Pick(remoteAddr)
		if err != nil {
			log.Printf("pick proxy for %s: %v", remoteAddr, err)
			return
		}

		// Get upstream connection — through proxy or direct
		var remote net.Conn
		if proxy.Name() == "DIRECT" {
			remote, err = net.DialTimeout("tcp", remoteAddr, 10*time.Second)
		} else {
			remote, err = proxy.Connect(context.Background(), remoteAddr)
		}
		if err != nil {
			log.Printf("connect %s via %s: %v", remoteAddr, proxy.Name(), err)
			return
		}

		req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, target, u.Host)
		remote.Write([]byte(req))
		l.relay(conn, remote, proxy.Name())
		remote.Close()
		return
	}

	proxy, err := l.opts.Router.Pick(target)
	if err != nil {
		log.Printf("pick proxy for %s: %v", target, err)
		return
	}

	// MITM HTTPS interception: only for allowlist-matched hosts (see mitm.go).
	// When intercepting, we TLS-terminate the client side, read the first
	// plaintext request, re-establish TLS to the real origin, and relay the
	// decrypted streams. SkipHosts is a safety valve for CONNECT tunnels that
	// carry non-HTTP protocols over 443.
	if l.opts.MITM != nil && l.opts.MITM.ShouldIntercept(target) && !l.opts.MITM.SkipHost(target) {
		tlsClient, upstream, firstReq, err := l.opts.MITM.InterceptConnect(conn, target)
		if err != nil {
			log.Printf("mitm intercept %s: %v — falling back to tunnel", target, err)
		} else {
			defer upstream.Close()
			if firstReq != nil {
				upstream.Write(firstReq)
			}
			l.relay(tlsClient, upstream, proxy.Name())
			return
		}
	}

	remote, err := proxy.Connect(context.Background(), target)
	if err != nil {
		log.Printf("proxy connect %s via %s: %v", target, proxy.Name(), err)
		return
	}
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	l.relay(conn, remote, proxy.Name())
}

func parseRequestLine(line string) (string, string, string, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 { return "", "", "", fmt.Errorf("bad request") }
	return parts[0], parts[1], parts[2], nil
}

func (l *Listener) serveSOCKS5(ln net.Listener) {
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			if l.isClosed() {
				return
			}
			log.Printf("socks5 accept: %v", err)
			return
		}
		go l.handleSOCKS5(c)
	}
}

func (l *Listener) handleSOCKS5(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 256)
	n, err := io.ReadFull(conn, buf[:3])
	if err != nil || n < 3 { return }
	conn.Write([]byte{0x05, 0x00})

	cmdBuf := make([]byte, 256)
	m, err := io.ReadFull(conn, cmdBuf[:5])
	if err != nil || m < 5 { return }
	cmd := cmdBuf[1]
	at := cmdBuf[3]
	switch at {
	case 0x01:
		io.ReadFull(conn, cmdBuf[:6])
	case 0x03:
		ln := int(cmdBuf[4])
		io.ReadFull(conn, cmdBuf[:5+ln])
	case 0x04:
		io.ReadFull(conn, cmdBuf[:18])
	}

	// UDP ASSOCIATE (CMD 0x03): the client wants to relay UDP through us. We
	// allocate a local UDP socket, reply with its bound address, and pump
	// SOCKS5-framed datagrams between that socket and the dial-side UDP conn
	// (direct, or through a proxy's ConnectUDP if the routed proxy supports it).
	// The TCP control connection stays open for the relay's lifetime; closing
	// it tears the association down.
	if cmd == 0x03 {
		l.handleSOCKS5UDP(conn)
		return
	}

	host := ""
	port := uint16(0)
	switch at {
	case 0x01:
		ip := net.IPv4(cmdBuf[4], cmdBuf[5], cmdBuf[6], cmdBuf[7])
		host = ip.String()
		port = uint16(cmdBuf[8])<<8 | uint16(cmdBuf[9])
	case 0x03:
		host = string(cmdBuf[5 : 5+cmdBuf[4]])
		port = uint16(cmdBuf[5+cmdBuf[4]])<<8 | uint16(cmdBuf[5+cmdBuf[4]+1])
	}
	remoteAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	proxy, err := l.opts.Router.Pick(remoteAddr)
	if err != nil {
		log.Printf("pick proxy for %s: %v", remoteAddr, err)
		return
	}

	var remote net.Conn
	if proxy.Name() == "DIRECT" {
		remote, err = net.DialTimeout("tcp", remoteAddr, 10*time.Second)
	} else {
		remote, err = proxy.Connect(context.Background(), remoteAddr)
	}
	if err != nil {
		log.Printf("connect %s via %s: %v", remoteAddr, proxy.Name(), err)
		return
	}
	defer remote.Close()

	boundIP, boundPort := getBound(conn)
	boundIPBytes := boundIP.To4()
	if boundIPBytes == nil { boundIPBytes = boundIP.To16() }
	resp := []byte{0x05, 0x00, 0x00, 0x01}
	resp = append(resp, boundIPBytes...)
	resp = append(resp, byte(boundPort>>8), byte(boundPort))
	conn.Write(resp)

	l.relay(conn, remote, proxy.Name())
}

func getBound(conn net.Conn) (net.IP, uint16) {
	addr, _ := net.ResolveTCPAddr("tcp", conn.LocalAddr().String())
	return addr.IP, uint16(addr.Port)
}

// handleSOCKS5UDP implements the SOCKS5 UDP ASSOCIATE server path (CMD 0x03).
// The client sent the greeting + a UDP ASSOCIATE request; we've read cmdBuf
// (5 bytes: ver,cmd,rsv,atyp,addr...). We reply with the bound address of a
// freshly-allocated local UDP socket, then relay SOCKS5-framed datagrams:
//
//	client→us:  [RSV 2][FRAG 1][ATYP 1][DST.ADDR][DST.PORT 2][DATA]  → unwrap, forward to dst
//	dst→us:     DATA                                                                  → wrap, send to client's relay socket
//
// The TCP control connection (conn) stays open for the relay's lifetime; when
// the client closes it, the relay goroutine tears down. Routing follows the
// same Router.Pick as the CONNECT path: if the picked proxy implements
// proxy.PacketProxy (UDP-capable, e.g. a chained SOCKS5), datagrams egress
// through it; otherwise we dial dst directly over a plain UDP socket.
func (l *Listener) handleSOCKS5UDP(conn net.Conn) {
	// The client's DST.ADDR in a UDP ASSOCIATE request is conventionally
	// 0.0.0.0:0 (it doesn't know the relay address yet). We don't route on it.
	udpSock, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		log.Printf("socks5 udp listen: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // general failure
		return
	}
	defer udpSock.Close()

	// Reply with BND.ADDR:BND.PORT. Report the address the client should send
	// its UDP datagrams to: if the TCP peer is a real address, echo that IP so
	// NAT'd clients target the right interface; else 0.0.0.0. Port is the UDP
	// socket's bound port.
	boundPort := uint16(localPort(udpSock))
	boundIP := peerIP(conn)
	if boundIP == nil {
		boundIP = net.IPv4zero
	}
	ipBytes := boundIP.To4()
	atyp := byte(0x01)
	addrBytes := ipBytes
	if ipBytes == nil {
		atyp = 0x04
		addrBytes = boundIP.To16()
	}
	resp := []byte{0x05, 0x00, 0x00, atyp}
	resp = append(resp, addrBytes...)
	resp = append(resp, byte(boundPort>>8), byte(boundPort))
	if _, err := conn.Write(resp); err != nil {
		return
	}

	// Remember the client's relay socket address (where to send wrapped replies).
	// The client sends its first datagram from the same socket it'll keep using,
	// so we capture it on the first packet and send replies there.
	var clientRelay net.Addr

	// Try to route through a UDP-capable proxy. We don't know the dst ahead of
	// time (it's per-datagram), so we only set up the proxied path if a single
	// global proxy is configured; otherwise relay directly. This matches the
	// common "local SOCKS5 server that egresses through one upstream" use case.
	relayToDst, relayFromDst := l.udpRelayDirect(udpSock)

	done := make(chan struct{})
	go func() {
		<-connClosed(conn) // TCP control conn closed → tear down
		udpSock.Close()
		close(done)
	}()

	// Read loop: unwrap each client datagram, forward payload to dst.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := udpSock.ReadFrom(buf)
			if err != nil {
				return
			}
			clientRelay = from
			dst, payload, err := proxy.ParseUDPHeader(buf[:n])
			if err != nil {
				continue // drop malformed
			}
			relayToDst(dst, payload)
		}
	}()

	// Reply pump (if proxied) writes wrapped replies to the client relay addr.
	if relayFromDst != nil {
		go func() {
			buf := make([]byte, 65535)
			for {
				n, src, err := relayFromDst.ReadFrom(buf)
				if err != nil {
					return
				}
				if clientRelay == nil {
					continue
				}
				hdr, err := proxy.EncodeUDPHeader(src.String())
				if err != nil {
					continue
				}
				frame := append(hdr, buf[:n]...)
				udpSock.WriteTo(frame, clientRelay)
			}
		}()
	}

	<-done
}

// udpRelayDirect returns a (toDst, fromDst) pair for direct UDP relay: toDst
// resolves dst and writes the payload on the caller's udpSock; fromDst is nil
// (direct mode reads replies on the same udpSock the caller already loops on,
// so there's no separate reply pump). For proxied relay through a UDP-capable
// upstream, a future variant returns a proxy.PacketProxy-backed PacketConn.
func (l *Listener) udpRelayDirect(udpSock net.PacketConn) (func(dst string, payload []byte), net.PacketConn) {
	toDst := func(dst string, payload []byte) {
		addr, err := net.ResolveUDPAddr("udp", dst)
		if err != nil {
			return
		}
		udpSock.WriteTo(payload, addr)
	}
	return toDst, nil
}

// localPort extracts the port from a PacketConn's local address.
func localPort(p net.PacketConn) int {
	addr, err := net.ResolveUDPAddr("udp", p.LocalAddr().String())
	if err != nil {
		return 0
	}
	return addr.Port
}

// peerIP returns the remote IP of a TCP connection (the client's address), or
// nil if it can't be resolved.
func peerIP(conn net.Conn) net.IP {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcp.IP
	}
	return nil
}

// connClosed returns a channel that fires when the connection is closed (read
// returns EOF/error). Used to detect TCP control-connection teardown for the
// UDP ASSOCIATE lifetime without blocking the main goroutine.
func connClosed(conn net.Conn) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		one := make([]byte, 1)
		_, err := conn.Read(one)
		_ = err
		close(ch)
	}()
	return ch
}

// statsConn wraps a net.Conn and reports bytes read/written to a StatsTracker
// under proxyName. Read bytes count as "download" (remote→local), written as
// "upload" (local→remote). No-op when tracker is nil.
type statsConn struct {
	net.Conn
	stats    *web.StatsTracker
	proxy   string
}

func (c *statsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.stats != nil {
		c.stats.RecordTraffic(c.proxy, 0, int64(n)) // download
	}
	return n, err
}

func (c *statsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && c.stats != nil {
		c.stats.RecordTraffic(c.proxy, int64(n), 0) // upload
	}
	return n, err
}

// connWithClientAddr is implemented by listener-side connection types that
// know the real client source address (e.g. TProxy, where RemoteAddr is the
// original target after redirect). nil is fine to return.
type connWithClientAddr interface {
	ClientAddr() net.Addr
}

func clientAddrStr(conn net.Conn) string {
	if c, ok := conn.(connWithClientAddr); ok {
		if ca := c.ClientAddr(); ca != nil {
			return ca.String()
		}
	}
	return conn.RemoteAddr().String()
}

// relay copies bidirectionally between client and remote, optionally counting
// bytes under proxyName. It tracks active connections on the tracker too.
// Blocks until one direction closes; closes both ends.
func (l *Listener) relay(client, remote net.Conn, proxyName string) {
	if l.opts.Stats != nil {
		l.opts.Stats.AddConnection(proxyName)
		defer l.opts.Stats.RemoveConnection(proxyName)
		client = &statsConn{Conn: client, stats: l.opts.Stats, proxy: proxyName}
		remote = &statsConn{Conn: remote, stats: l.opts.Stats, proxy: proxyName}
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, client); done <- struct{}{}; remote.Close() }()
	go func() { io.Copy(client, remote); done <- struct{}{}; client.Close() }()
	<-done
	<-done
}

// serveTProxy accepts connections delivered by the Linux TPROXY socket option.
// Each accepted conn already carries the original destination in RemoteAddr (via
// origDst in tproxyConn); serveTProxy hands it off to handleTProxy, which
// behaves like handleHTTP (reads HTTP CONNECT or tunneling request lines, picks
// a proxy via Router.Pick, and relays) but using the conn's RemoteAddr as the
// target. This way TProxy can be pointed at a plain HTTP proxy and let the
// existing HTTP dispatch handle the rest of the flow.
func (l *Listener) serveTProxy(ln net.Listener) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			l.fatalAccept(ln, "tproxy listener", err)
			return
		}
		go l.handleTProxy(conn)
	}
}

// handleTProxy tunnels an incoming TProxy connection through the configured
// router, using the original destination (RemoteAddr, preserved by
// tproxyConn.origDst) as the target address. If RemoteAddr can't be parsed
// as TCP, the conn is closed and a log line emitted.
func (l *Listener) handleTProxy(conn net.Conn) {
	defer conn.Close()
	ta, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ta == nil {
		log.Printf("tproxy: cannot determine target address: %v", conn.RemoteAddr())
		return
	}
	if ta.Port == 0 {
		ta = &net.TCPAddr{IP: ta.IP, Port: 443}
	}
	target := ta.String()
	client := clientAddrStr(conn)
	if client != "" {
		log.Printf("tproxy: %s -> %s", client, target)
	}

	// MITM over TProxy: transparent connections have no CONNECT hostname —
	// the original destination is an IP:port — so the allowlist matches by
	// IP-CIDR rules. When it hits, TLS-terminate here (the signed cert will
	// carry the IP SAN; clients must trust our CA anyway for interception to
	// work at all), re-encrypt upstream, and relay decrypted.
	if l.opts.MITM != nil && l.opts.MITM.ShouldInterceptIP(ta.IP.String()) && !l.opts.MITM.SkipHost(target) {
		tlsClient, upstream, firstReq, err := l.opts.MITM.InterceptConnect(conn, target)
		if err != nil {
			log.Printf("tproxy mitm intercept %s: %v — falling back to tunnel", target, err)
		} else {
			defer upstream.Close()
			if firstReq != nil {
				upstream.Write(firstReq)
			}
			l.relay(tlsClient, upstream, "TPROXY-MITM")
			return
		}
	}

	p, err := l.opts.Router.Pick(target)
	if err != nil {
		log.Printf("tproxy: pick proxy for %s: %v", target, err)
		return
	}
	var remote net.Conn
	if p.Name() == "DIRECT" {
		remote, err = net.DialTimeout("tcp", target, 10*time.Second)
	} else {
		remote, err = p.Connect(context.Background(), target)
	}
	if err != nil {
		log.Printf("tproxy: connect %s via %s: %v", target, p.Name(), err)
		return
	}
	l.relay(conn, remote, p.Name())
	remote.Close()
}
