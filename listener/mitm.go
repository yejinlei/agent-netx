package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"agent-netx/mitm"
	"agent-netx/proxy"
	"agent-netx/router"
)

// MITMHandler handles HTTPS interception for allowlist-matched hosts. It
// TLS-terminates the client connection with a per-host signed cert, reads the
// first plaintext HTTP request, re-establishes TLS to the real upstream, and
// lets the caller relay decrypted traffic between the two TLS sessions.
//
// Security: only allowlist-matched hosts are intercepted. An empty allowlist
// means "never intercept" even when the handler is configured (安全红线).
type MITMHandler struct {
	Interceptor *mitm.Interceptor
	Allowlist   []string
	// EgressProxy is the outbound proxy used to dial upstream after TLS
	// termination. nil means direct (the default).
	EgressProxy proxy.Proxy
	// VerifyUpstream enables certificate validation of the real server on
	// the re-encrypted upstream TLS session. Default false: like most
	// intercepting proxies we present the client's trust decision as ours to
	// relay, and rejecting here would break self-signed internal hosts. When
	// true, the system root pool is used.
	VerifyUpstream bool
	// SkipHosts lists host rules (same syntax as Allowlist) that are never
	// intercepted even when the allowlist matches. Use it for known non-HTTP
	// tunnels on 443 (long-lived WebSocket, gRPC streams, custom protocols)
	// where TLS termination would break the conversation.
	SkipHosts []string
}

// ShouldIntercept returns true when target (which may include a port, e.g.
// "example.com:443") matches at least one rule in the allowlist. Empty
// allowlist → always false.
func (h *MITMHandler) ShouldIntercept(target string) bool {
	if h == nil || len(h.Allowlist) == 0 {
		return false
	}
	host, _, _ := net.SplitHostPort(target)
	if host == "" {
		host = target
	}
	return router.MatchAllow(host, h.Allowlist) && !router.MatchAllow(host, h.SkipHosts)
}

// ShouldInterceptIP is the TProxy counterpart of ShouldIntercept: transparent
// connections deliver an IP original destination with no CONNECT hostname, so
// allowlist matching runs against the IP string (IP-CIDR rules apply; plain
// DOMAIN rules cannot). Empty allowlist → false (安全红线 holds on this path).
func (h *MITMHandler) ShouldInterceptIP(ip string) bool {
	if h == nil || len(h.Allowlist) == 0 {
		return false
	}
	return router.MatchAllow(ip, h.Allowlist) && !router.MatchAllow(ip, h.SkipHosts)
}

// SkipHost reports whether target (host or host:port) is in the never-intercept
// skip list. Callers that intercept without consulting Allowlist (e.g. the
// TProxy path, which matches by IP) use this as their safety valve.
func (h *MITMHandler) SkipHost(target string) bool {
	if h == nil || len(h.SkipHosts) == 0 {
		return false
	}
	host, _, _ := net.SplitHostPort(target)
	if host == "" {
		host = target
	}
	return router.MatchAllow(host, h.SkipHosts)
}

// InterceptConnect does the MITM handshake for a CONNECT request:
//
//	1. Sign a per-host cert via Interceptor.GetCertForHost.
//	2. TLS-terminate conn with that cert (client-facing).
//	3. Read the first plaintext HTTP request (line + headers) from the
//	   terminated stream.
//	4. Dial upstream for targetAddr (direct or via EgressProxy) and re-establish
//	   TLS to the real server (SNI = host), so the plaintext request can reach an
//	   actual HTTPS origin instead of being shot at port 443 in the clear.
//
// Returns (tlsClient, upstreamTLS, firstReq, nil) on success — both conns are
// TLS sessions speaking plaintext HTTP. Caller writes firstReq to upstream,
// then relays tlsClient ↔ upstream.
func (h *MITMHandler) InterceptConnect(conn net.Conn, targetAddr string) (tlsClient, upstream net.Conn, firstReq []byte, err error) {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
	}

	cert, err := h.Interceptor.GetCertForHost(host)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign cert for %s: %w", host, err)
	}

	// Dial upstream BEFORE TLS-terminating the client. If the origin is
	// unreachable or not speaking TLS we fail here, while conn is still raw
	// TCP, and the caller can fall back to a blind CONNECT tunnel instead of
	// having already committed to interception with a half-read client hello.
	var rawUp net.Conn
	if h.EgressProxy != nil && h.EgressProxy.Name() != "DIRECT" {
		rawUp, err = h.EgressProxy.Connect(context.Background(), targetAddr)
	} else {
		rawUp, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial upstream %s: %w", targetAddr, err)
	}

	// Re-encrypt toward the real origin. The bytes we forward are plaintext
	// HTTP, which a bare TCP socket to :443 cannot carry — wrap the upstream
	// in tls.Client with SNI so the full interception chain works against
	// actual HTTPS servers. Handshake() here also performs the server-first
	// TLS probe: non-HTTP tunnels (SOCKS-over-443, custom protocols) fail it
	// and trigger the caller's tunnel fallback.
	upstreamTLS := tls.Client(rawUp, h.upstreamTLSConfig(host))
	if err := upstreamTLS.Handshake(); err != nil {
		upstreamTLS.Close()
		return nil, nil, nil, fmt.Errorf("upstream tls handshake %s: %w", targetAddr, err)
	}

	tlsServer := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsServer.Handshake(); err != nil {
		upstreamTLS.Close()
		return nil, nil, nil, fmt.Errorf("tls handshake with client: %w", err)
	}

	br := bufio.NewReader(tlsServer)
	reqBytes, err := readFirstHTTPRequest(br)
	if err != nil {
		upstreamTLS.Close()
		return nil, nil, nil, fmt.Errorf("read plaintext request: %w", err)
	}

	tlsClient = &tlsBufConn{br: br, Conn: tlsServer}
	return tlsClient, upstreamTLS, reqBytes, nil
}

// upstreamTLSConfig builds the client config for the re-encrypted upstream
// session. ServerName is the intercepted host (SNI); verification follows
// VerifyUpstream (default off — see field doc on MITMHandler).
func (h *MITMHandler) upstreamTLSConfig(host string) *tls.Config {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if !h.VerifyUpstream {
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

// readFirstHTTPRequest reads an HTTP request line + all headers + the final
// empty line (CRLF) that terminates the header block. It does NOT read the
// body. Returns everything read so far as one byte slice.
func readFirstHTTPRequest(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		out = append(out, line...)
		if len(line) == 2 && line[0] == '\r' && line[1] == '\n' {
			break
		}
	}
	return out, nil
}

// tlsBufConn wraps a bufio.Reader around a net.Conn so reads pull from the
// buffered remainder first (data read ahead of the header delimiter), then
// fall through to the underlying Conn.
type tlsBufConn struct {
	br   *bufio.Reader
	net.Conn
}

func (c *tlsBufConn) Read(b []byte) (int, error) { return c.br.Read(b) }
func (c *tlsBufConn) Write(b []byte) (int, error) { return c.Conn.Write(b) }
func (c *tlsBufConn) Close() error                 { return c.Conn.Close() }
func (c *tlsBufConn) LocalAddr() net.Addr          { return c.Conn.LocalAddr() }
func (c *tlsBufConn) RemoteAddr() net.Addr         { return c.Conn.RemoteAddr() }
func (c *tlsBufConn) SetDeadline(t time.Time) error  { return c.Conn.SetDeadline(t) }
func (c *tlsBufConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}
func (c *tlsBufConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
// NOTE: deliberately NO ReadFrom/WriteTo methods here. A net.Conn wrapper
// that implements them lures io.Copy into optimizations that either re-enter
// the method forever (stack overflow — a real defect this code had) or skip
// the bufio.Reader entirely and lose the read-ahead remainder. The generic
// path in io.Copy goes through Read/Write below, which drain br first.