package listener

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"agent-netx/config"
	"agent-netx/proxy"
	"agent-netx/router"
	"agent-netx/web"
)

// RewriteFn is a callback invoked on every byte write through the relay.
// It receives the raw bytes just written, the direction
// ("upstream"=upstream→client, "client"=client→upstream), the proxy name,
// and the remote address of the peer that received those bytes.
type RewriteFn func(bytes []byte, direction string, proxyName string, peer net.Addr)

// Options holds the Listener's configuration.
type Options struct {
	HTTPPort   int
	SOCKS5Port int
	TProxyPort int
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
	// URLActions are evaluated on both the plain-HTTP path (handleHTTP non-
	// CONNECT) and the MITM-intercepted path. Empty = no URL-based short-
	// circuit. Mirrored into MITMHandler.URLActions at build time.
	URLActions []config.URLAction
	// Stats optionally receives per-proxy traffic + connection accounting.
	// nil disables accounting (no overhead).
	Stats *web.StatsTracker
	// OnLog, when non-nil, is called for every byte written during relay,
	// with direction, proxyName, and the peer address that received the bytes.
	// nil = no logging. MITM rewriter and flow logger both use this.
	OnLog RewriteFn
	// Hooks, when non-empty, are invoked on each Flow at defined lifecycle
	// points ("request" and "done"). Return false from any hook to abort
	// the pipeline for that flow.
	Hooks FlowHooks
	// Sinks, when non-empty, receive each completed Flow via Write. Multiple
	// sinks can coexist; write order matches slice order. Never invoked for
	// flows aborted by a Hook.
	Sinks []FlowSink
	// Upstream, when non-nil and IsConfigured(), is the proxy the agent
	// itself dials through when connecting to the ultimate upstream (after
	// Router.Pick). Corresponds to mitmproxy's -u flag: chain the outbound
	// path so agent egress is routed through another hop.
	Upstream *proxy.UpstreamProxy
}

type Listener struct {
	opts Options

	mu       sync.Mutex
	httpLn   net.Listener
	socksLn  net.Listener
	tproxyLn net.Listener
	closed   bool
	stopCh   chan struct{}
	errs     chan error
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
	if err != nil {
		return
	}
	method, target, reqProto, err := parseRequestLine(strings.TrimSpace(reqLine))
	if err != nil {
		return
	}

	// Read the request headers while they're still on the wire. The
	// buffered Reader holds everything up to and including the blank
	// line that terminates the header block, so subsequent body reads
	// still see the full payload. Body capture is deferred: knowing
	// Content-Length and stream-limiting the first N bytes is a bigger
	// relay rewrite. Headers are cheap and needed for keep-alive anyway.
	reqHeaders := readRequestHeaders(reader)

	if method != "CONNECT" {
		u, err := url.Parse(target)
		if err != nil {
			return
		}
		if u.Scheme == "https" {
			return
		}
		remoteAddr := u.Host
		if !strings.Contains(remoteAddr, ":") {
			remoteAddr = remoteAddr + ":80"
		}

		proxy, err := l.opts.Router.Pick(remoteAddr)
		if err != nil {
			log.Printf("pick proxy for %s: %v", remoteAddr, err)
			return
		}

		// Build the Flow snapshot before the URLAction short-circuit so we
		// still record which rule fired (or didn't). ClientAddr for a plain
		// HTTP proxy is the TCP peer; FullURL is the absolute form the
		// client sent us.
		fl := NewFlow("http", remoteAddr, clientAddrStr(conn))
		fl.Host = u.Host
		fl.Method = method
		fl.Path = u.Path
		fl.FullURL = target
		fl.ProxyName = proxy.Name()
		fl.RequestProto = reqProto
		fl.RequestHeaders = reqHeaders

		// Ask hooks to make the call. A "false" here means an upstream
		// policy rejected the request — we tell the client and record
		// the flow before closing. This runs BEFORE the URLAction
		// short-circuit so hooks always observe a Flow with a
		// "request" phase before any "done" phase — otherwise a
		// URLAction rule would emit "done" without ever emitting
		// "request", breaking the contract every other Flow obeys.
		if !l.opts.Hooks.Emit("request", fl) {
			fl.Error = "hook rejected request"
			fl.ResponseStatus = 403
			l.emitDone(fl)
			return
		}

		// URLAction short-circuit on the plain-HTTP path: evaluate rules
		// against the full request line and the path BEFORE dialing upstream.
		// This is the HTTP analog of the same check inside InterceptConnect,
		// but here we have only the raw TCP conn (no TLS) so we write the
		// response straight through.
		if r := matchURLActions(l.opts.URLActions, strings.TrimSpace(reqLine), u.Path); r.Action != "" {
			WriteURLResponse(conn, r)
			fl.ResponseStatus = r.Status
			l.emitDone(fl)
			return
		}

		// Get upstream connection — through proxy or direct. When the
		// router picked DIRECT and cfg.Upstream is configured, dial
		// through that upstream instead of a raw TCP socket — the
		// mitmproxy -u analog.
		var remote net.Conn
		remote, err = l.connectVia(proxy, remoteAddr)
		if err != nil {
			log.Printf("connect %s via %s: %v", remoteAddr, proxy.Name(), err)
			fl.MarkError(fmt.Errorf("connect %s: %w", remoteAddr, err))
			l.emitDone(fl)
			return
		}

		req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, u.RequestURI(), u.Host)
		remote.Write([]byte(req))
		l.relay(&clientWithFlow{conn: conn, flow: fl}, remote, proxy.Name())
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
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		tlsClient, upstream, firstReq, err := l.opts.MITM.InterceptConnect(conn, target)
		if err != nil {
			log.Printf("mitm intercept %s: %v — falling back to tunnel", target, err)
		} else if firstReq == nil && upstream == nil {
			// URLAction short-circuit fired inside InterceptConnect: the
			// client already received a response and both conns are closed.
			return
		} else {
			defer upstream.Close()
			// Build a Flow for the decrypted request so JSON sinks see
			// the same shape as plain-HTTP flows. Parse headers from the
			// first-plaintext-request bytes returned by InterceptConnect —
			// they contain request line + all headers + trailing blank.
			if len(firstReq) > 0 {
				fl := NewFlow("https-mitm", target, clientAddrStr(conn))
				fl.Intercepted = true
				parseFirstRequestBytes(firstReq, fl)
				if !l.opts.Hooks.Emit("request", fl) {
					fl.Error = "hook rejected request"
					fl.ResponseStatus = 403
					l.emitDone(fl)
					upstream.Close()
					return
				}
				// Write the plaintext request upstream, then read the
				// upstream's plaintext response headers (status line +
				// response headers + trailing blank). Buffer that so
				// relay() can pump the first read off it, then drain.
				// Body bytes are captured via byte counters only — the
				// upstream response body itself is streamed straight
				// through, same as the client request body.
				if _, err := upstream.Write(firstReq); err != nil {
					fl.MarkError(err)
					l.emitDone(fl)
					return
				}
				rReader := bufio.NewReader(upstream)
				statusLine, err := rReader.ReadString('\n')
				if err == nil {
					rHeaders := readResponseHeaders(rReader)
					fl.ResponseHeaders = rHeaders
					if line := strings.TrimRight(statusLine, "\r\n"); len(line) > 0 {
						parts := strings.Fields(line)
						if len(parts) >= 2 {
							fl.ResponseProto = parts[0]
							if n, e := strconv.Atoi(parts[1]); e == nil {
								fl.ResponseStatus = n
							}
						}
					}
					// Re-wrap upstream so the buffered response headers
					// the reader peeked past are read first by relay().
					upstream = &tlsBufConn{br: rReader, Conn: upstream}
				}
				// Wrap tlsClient so relay() finds a FlowCarrier and
				// byte counters land on fl. clientWithFlow is a thin
				// pass-through that implements net.Conn + FlowCarrier.
				l.relay(&clientWithFlow{conn: tlsClient, flow: fl}, upstream, proxy.Name())
				return
			}
			if firstReq != nil {
				upstream.Write(firstReq)
			}
			l.relay(tlsClient, upstream, proxy.Name())
			return
		}
	}

	remote, err := l.connectVia(proxy, target)
	if err != nil {
		log.Printf("proxy connect %s via %s: %v", target, proxy.Name(), err)
		return
	}
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	l.relay(conn, remote, proxy.Name())
}

func parseRequestLine(line string) (string, string, string, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("bad request")
	}
	proto := ""
	if len(parts) >= 3 {
		proto = parts[2]
	}
	return parts[0], parts[1], proto, nil
}

// readResponseHeaders is the response-side twin of readRequestHeaders:
// it consumes all response header lines from a buffered reader up to the
// blank line (CRLF CRLF). The status line has already been read by the
// caller; this reads only the header lines.
func readResponseHeaders(r *bufio.Reader) []string {
	return readRequestHeaders(r)
}

// readRequestHeaders reads all header lines from a buffered reader up to
// and including the blank line (CRLF CRLF) that terminates the header
// block. Returns one entry per header line as "Name: value" (trimmed of
// trailing CRLF, no leading whitespace normalization). Does NOT read the
// body — subsequent reads from r resume after the blank line, which is
// exactly what a client's body starts with.
//
// Malformed input (EOF before blank line, oversized header line) returns
// whatever was read so far. Callers may proceed with what they have —
// headers are best-effort metadata.
func readRequestHeaders(r *bufio.Reader) []string {
	var out []string
	for {
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return out
		}
		// Strip trailing CR/LF.
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return out
		}
		out = append(out, line)
		// Guard against a maliciously huge header block. We don't need
		// every header — the first ~50 lines covers any real request.
		if len(out) >= 200 {
			return out
		}
		if len(line) > 8192 {
			return out
		}
	}
}

// parseFirstRequestBytes parses an MITM-decrypted plaintext HTTP request
// (request line + all headers + trailing blank line, as returned by
// InterceptConnect) and stamps Method, Path, FullURL, RequestProto,
// RequestHeaders, and a preliminary Host onto f. It does NOT populate
// bodies — those require Content-Length / chunked parsing, which is a
// relay rewrite (see MANUAL §3.17).
func parseFirstRequestBytes(b []byte, f *Flow) {
	if f == nil || len(b) == 0 {
		return
	}
	// Split into lines, preserving order. The last line is always blank.
	var lines []string
	cur := []byte{}
	for _, c := range b {
		if c == '\n' {
			line := strings.TrimRight(string(cur), "\r\n")
			if line == "" {
				break
			}
			lines = append(lines, line)
			cur = cur[:0]
		} else {
			cur = append(cur, c)
		}
	}
	if len(lines) == 0 {
		return
	}
	// Request line: "METHOD PATH PROTO".
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return
	}
	f.Method = parts[0]
	f.Path = parts[1]
	if len(parts) >= 3 {
		f.RequestProto = parts[2]
	}
	// Body starts after the blank line — we only have the pre-blank
	// portion, so there's no body to save here.
	f.RequestHeaders = lines[1:]
	// Extract Host if present.
	for _, h := range f.RequestHeaders {
		if col := strings.IndexByte(h, ':'); col > 0 {
			if strings.EqualFold(strings.TrimSpace(h[:col]), "host") {
				f.Host = strings.TrimSpace(h[col+1:])
				break
			}
		}
	}
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
	if err != nil || n < 3 {
		return
	}
	conn.Write([]byte{0x05, 0x00})

	cmdBuf := make([]byte, 256)
	m, err := io.ReadFull(conn, cmdBuf[:5])
	if err != nil || m < 5 {
		return
	}
	cmd := cmdBuf[1]
	at := cmdBuf[3]
	switch at {
	case 0x01:
		io.ReadFull(conn, cmdBuf[5:10])
	case 0x03:
		ln := int(cmdBuf[4])
		io.ReadFull(conn, cmdBuf[5:5+ln+2])
	case 0x04:
		io.ReadFull(conn, cmdBuf[5:22])
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
	if boundIPBytes == nil {
		boundIPBytes = boundIP.To16()
	}
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
	stats *web.StatsTracker
	proxy string
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
//
// When the client conn carries a Flow (via FlowCarrier), relay wraps both
// ends in a countingConn so byte counters can be stamped onto the Flow after
// the connection drains. That Flow is then handed to emitDone, which runs
// the "done" hooks and pushes to every Sink.
func (l *Listener) relay(client, remote net.Conn, proxyName string) {
	carrier := extractFlowCarrier(client, remote)
	var reqBytes, respBytes int64
	// The client-side write is proxy→client (ResponseBytes); the upstream
	// write is proxy→upstream (RequestBytes). The read side mirrors it.
	clientW, clientR := &respBytes, &reqBytes
	remoteW, remoteR := &reqBytes, &respBytes

	client = newCountingConn(client, clientW, clientR)
	remote = newCountingConn(remote, remoteW, remoteR)

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

	if carrier != nil {
		fl := carrier.Flow()
		if fl != nil {
			fl.RequestBytes = atomic.LoadInt64(&reqBytes)
			fl.ResponseBytes = atomic.LoadInt64(&respBytes)
			l.emitDone(fl)
		}
	}
}

// emitDone finalizes the Flow's duration, emits the "done" hook phase, and
// writes to every configured Sink. Never called with a nil flow — the
// nil check happens in emitDone defensively.
func (l *Listener) emitDone(fl *Flow) {
	if fl == nil {
		return
	}
	fl.Finalize()
	// The "done" hook can veto the sink write (e.g. an audit hook that
	// decides a flow is PII and shouldn't land on disk).
	if l.opts.Hooks.Emit("done", fl) {
		for _, s := range l.opts.Sinks {
			if s != nil {
				s.Write(fl)
			}
		}
	}
}

// dialDirect dials remoteAddr, respecting cfg.Upstream: if an upstream
// proxy is configured, the connection is tunneled through it instead of
// a raw TCP socket. This is where mitmproxy -u semantics plug in.
func (l *Listener) dialDirect(ctx context.Context, remoteAddr string) (net.Conn, error) {
	if l.opts.Upstream != nil && l.opts.Upstream.IsConfigured() {
		return l.opts.Upstream.Connect(ctx, remoteAddr)
	}
	return net.DialTimeout("tcp", remoteAddr, 10*time.Second)
}

// connectVia combines Router.Pick and Upstream semantics: if the picked
// proxy is DIRECT and Upstream is configured, tunnel through Upstream;
// otherwise use the picked proxy's Connect. This is the single chokepoint
// where the "mitmproxy -u" chain is applied to plain-HTTP and CONNECT
// paths in handleHTTP and handleTProxy.
func (l *Listener) connectVia(p proxy.Proxy, target string) (net.Conn, error) {
	if p.Name() == "DIRECT" {
		return l.dialDirect(context.Background(), target)
	}
	return p.Connect(context.Background(), target)
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

	// SNI sniff: transparent connections carry no CONNECT hostname, so before
	// falling back to the IP-CIDR allowlist we peek one TLS ClientHello off
	// the wire (10ms deadline; any non-TLS or non-TLS-first protocol is
	// passed through untouched) and match the SNI against the domain-based
	// allowlist. When it hits we re-wrap the conn with the hello prefilled
	// so tls.Server inside InterceptConnect sees the same bytes.
	if tlsClient, upstream, firstReq, sniffed := l.trySNIMITM(conn, target); sniffed {
		defer upstream.Close()
		if firstReq != nil {
			upstream.Write(firstReq)
		}
		l.relay(tlsClient, upstream, "TPROXY-MITM")
		return
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

// trySNIMITM attempts SNI-based HTTPS interception on a TProxy connection.
// Returns (nil, nil, nil, false) whenever the connection should NOT be
// intercepted — no MITM handler, non-TLS first bytes, no SNI, SNI skipped,
// SNI not in the allowlist, or InterceptConnect refused. The single true
// return path means: "hand us these two conn, that first-req, and we're
// handling the rest." Any sniff failure is a soft failure — we hand back to
// the IP-CIDR / router path unchanged.
func (l *Listener) trySNIMITM(conn net.Conn, target string) (net.Conn, net.Conn, []byte, bool) {
	if l.opts.MITM == nil {
		return nil, nil, nil, false
	}
	sniffedConn, hello, ok := peekClientHello(conn)
	if !ok || len(hello) == 0 {
		return nil, nil, nil, false
	}
	sni := parseSNI(hello)
	if sni == "" {
		return nil, nil, nil, false
	}
	if l.opts.MITM.SkipHost(sni) || !l.opts.MITM.ShouldIntercept(sni) {
		return nil, nil, nil, false
	}
	wrapped := wrapWithPrefill(sniffedConn, hello)
	tlsClient, upstream, firstReq, err := l.opts.MITM.InterceptConnect(wrapped, target)
	if err != nil {
		log.Printf("tproxy mitm sni=%q intercept: %v — falling back", sni, err)
		return nil, nil, nil, false
	}
	return tlsClient, upstream, firstReq, true
}

// peekClientHello reads a TLS ClientHello record off conn without destroying
// the stream. Returns (conn, helloBytes, true) on success; (conn, nil, false)
// on any non-TLS or read failure. Uses a 10ms read deadline — TLS handshakes
// start immediately, so a slow first byte means we're looking at something
// that isn't going to be TLS, and the caller should keep passing it through.
// The deadline is reset to zero (no deadline) before returning.
func peekClientHello(conn net.Conn) (net.Conn, []byte, bool) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return conn, nil, false
	}
	if err := tc.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		return conn, nil, false
	}
	defer tc.SetReadDeadline(time.Time{})

	hdr := make([]byte, 5)
	n, err := tc.Read(hdr)
	if err != nil || n < 5 {
		return conn, nil, false
	}
	if hdr[0] != 0x16 { // TLS handshake record type
		return conn, nil, false
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen > 4096 { // ClientHello is bounded well under this; refuse the rest
		return conn, nil, false
	}
	buf := make([]byte, n+recLen)
	copy(buf, hdr)
	if _, err := io.ReadFull(tc, buf[5:]); err != nil {
		return conn, nil, false
	}
	return conn, buf, true
}

// parseSNI extracts the server_name from a TLS ClientHello record. Walks:
// record header (5) → handshake header (4) → version (2) → random (32) →
// session_id (1+len) → cipher_suites (2+len) → compression (1+len) →
// extensions (2+len) → find extension type 0x0000 → host_name (1+len).
// Returns "" on any malformed or missing field. Never panics on short input.
func parseSNI(record []byte) string {
	if len(record) < 5 {
		return ""
	}
	p := 5
	if p+4 > len(record) || record[p] != 0x01 { // HandshakeType=ClientHello
		return ""
	}
	p += 4 // handshake_type, length (3) — we already sized buf to the record
	if p+2 > len(record) {
		return ""
	}
	p += 2 // client version
	if p+32 > len(record) {
		return ""
	}
	p += 32 // random
	if p+1 > len(record) {
		return ""
	}
	sidLen := int(record[p])
	p += 1 + sidLen
	if p+2 > len(record) {
		return ""
	}
	csLen := int(record[p])<<8 | int(record[p+1])
	p += 2 + csLen
	if p+1 > len(record) {
		return ""
	}
	ccLen := int(record[p])
	p += 1 + ccLen
	if p+2 > len(record) {
		return ""
	}
	extLen := int(record[p])<<8 | int(record[p+1])
	p += 2
	extEnd := p + extLen
	if extEnd > len(record) {
		extEnd = len(record)
	}
	for p+4 <= extEnd {
		etype := int(record[p])<<8 | int(record[p+1])
		elen := int(record[p+2])<<8 | int(record[p+3])
		p += 4
		if p+elen > extEnd {
			break
		}
		if etype == 0x0000 && elen >= 5 {
			// server_name list: SNL_len(2) + NameType(1) + hl(2) + host(hl).
			// RFC 6066 §3 — host_name is an opaque <1..2^16-1>, so its
			// length field is 2 bytes (not 1). Real ClientHellos always
			// send hl_hi=0 for short names, but reading just the low byte
			// makes the parser miss them entirely.
			snl := int(record[p])<<8 | int(record[p+1])
			q := p + 2
			if snl != elen-2 || q+3 > extEnd {
				p += elen
				continue
			}
			if record[q] == 0x00 {
				hn := int(record[q+1])<<8 | int(record[q+2])
				if hn > 0 && hn <= 255 && q+3+hn <= extEnd {
					return string(record[q+3 : q+3+hn])
				}
			}
		}
		p += elen
	}
	return ""
}

// peerBufConn is a net.Conn that serves an initial prefill of bytes from
// memory before falling through to its underlying Conn. Used when a sniff
// has already read bytes off the wire and the downstream TLS handshake
// expects to read them again — tls.Client/Server do NOT re-issue a Read on
// the same buffer, they consume fresh bytes, so we need this shim to hand
// them back the sniffed ClientHello.
type peerBufConn struct {
	rest []byte
	net.Conn
}

func (c *peerBufConn) Read(b []byte) (int, error) {
	if len(c.rest) == 0 {
		return c.Conn.Read(b)
	}
	n := copy(b, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

func wrapWithPrefill(conn net.Conn, prefill []byte) net.Conn {
	if len(prefill) == 0 {
		return conn
	}
	return &peerBufConn{rest: append([]byte(nil), prefill...), Conn: conn}
}
