package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

// UpstreamProxy is an outbound proxy that the agent itself dials through
// when making its own upstream connections. It corresponds to mitmproxy's
// `-u http://...` / `-u socks5://...` flag: chain this proxy in front of
// every upstream dial so traffic from the agent goes through another
// network hop (a corporate proxy, a VPN gateway, a second region, etc.).
//
// Supported schemes:
//
//	http://[user:pass@]host:port    HTTP CONNECT tunnel
//	https://...                    TLS-wrapped HTTP CONNECT (rare; use http://)
//	socks5://[user:pass@]host:port  SOCKS5 v5 tunnel (RFC 1928/1929)
//
// Other schemes are rejected at New time with an informative error.

type UpstreamProxy struct {
	scheme     string
	host       string
	port       int
	username   string
	password   string
	timeout    time.Duration
	tlsWrap    bool
	nameLabel  string
	clientCert *tls.Certificate
}

// NewUpstreamProxy parses rawURL (http://, https://, or socks5://) and
// returns an UpstreamProxy configured to dial through that endpoint.
// timeout is the dial timeout to the upstream; 0 = 30s default.
func NewUpstreamProxy(rawURL string, timeout time.Duration) (*UpstreamProxy, error) {
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("upstream parse %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("upstream %q: missing host", rawURL)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return nil, fmt.Errorf("upstream %q: scheme %q unsupported (want http/https/socks5)", rawURL, u.Scheme)
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "socks5":
			port = "1080"
		case "http", "https":
			port = "3128"
		}
	}
	portN, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("upstream port %q: %w", port, err)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return &UpstreamProxy{
		scheme:    u.Scheme,
		host:      u.Hostname(),
		port:      portN,
		username:  user,
		password:  pass,
		timeout:   timeout,
		tlsWrap:   u.Scheme == "https",
		nameLabel: "UPSTREAM:" + u.Scheme,
	}, nil
}

// IsConfigured returns true when this UpstreamProxy should intercept dials.
func (u *UpstreamProxy) IsConfigured() bool {
	return u != nil && u.scheme != ""
}

// Name implements Proxy.
func (u *UpstreamProxy) Name() string { return u.nameLabel }

// SetClientCert attaches a TLS client certificate to the outbound session to
// the upstream proxy. Only takes effect when the URL scheme is https — a
// non-TLS upstream has nowhere to present a cert. Callers wire this from
// config.Upstream.ClientCrt/ClientKey so a corporate egress proxy that
// requires client auth (mTLS) is usable.
func (u *UpstreamProxy) SetClientCert(cert *tls.Certificate) {
	if u != nil {
		u.clientCert = cert
	}
}

// Connect dials through the upstream to the given target address (host:port).
// Semantically this is "make an outbound connection via the upstream proxy" —
// the returned conn is a tunnel whose bytes are already routed through the
// upstream.
func (u *UpstreamProxy) Connect(ctx context.Context, addr string) (net.Conn, error) {
	if u == nil {
		return nil, fmt.Errorf("upstream nil")
	}
	target := net.JoinHostPort(u.host, strconv.Itoa(u.port))
	conn, err := net.DialTimeout("tcp", target, u.timeout)
	if err != nil {
		return nil, fmt.Errorf("upstream dial %s: %w", target, err)
	}
	if u.tlsWrap {
		conn, err = u.wrapTLS(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream tls %s: %w", target, err)
		}
	}
	switch u.scheme {
	case "http", "https":
		if err := u.httpHandshake(conn, addr); err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream http %s: %w", target, err)
		}
	case "socks5":
		if err := u.socks5Handshake(conn, addr); err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream socks5 %s: %w", target, err)
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("upstream scheme %q unsupported", u.scheme)
	}
	return conn, nil
}

func (u *UpstreamProxy) httpHandshake(conn net.Conn, target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	req := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n", host, port, host, port)
	if u.username != "" {
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n",
			base64.StdEncoding.EncodeToString([]byte(u.username+":"+u.password)))
	}
	req += "\r\n"
	if err := conn.SetDeadline(time.Now().Add(u.timeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	var rest string
	for !doneHTTPResponse(rest) {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		rest += string(buf[:n])
		if len(rest) > 8192 {
			return fmt.Errorf("upstream http response too large")
		}
	}
	if !isHTTPOk(rest) {
		return fmt.Errorf("upstream http %s", statusLine(rest))
	}
	return nil
}

func (u *UpstreamProxy) socks5Handshake(conn net.Conn, target string) error {
	if err := conn.SetDeadline(time.Now().Add(u.timeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})

	// Version + offered methods.
	buf := []byte{0x05, 0x01, 0x00}
	if u.username != "" {
		buf = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("upstream socks5 version mismatch")
	}
	if resp[1] == 0x02 {
		if err := u.socks5Auth(conn); err != nil {
			return err
		}
	} else if resp[1] != 0x00 {
		return fmt.Errorf("upstream socks5 handshake rejected (method=0x%02x)", resp[1])
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	portN, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(portN>>8), byte(portN))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("upstream socks5 request failed (code=0x%02x)", reply[1])
	}
	// Skip the BND.ADDR section.
	switch reply[3] {
	case 0x01:
		skip(conn, 6)
	case 0x03:
		b := make([]byte, 1)
		io.ReadFull(conn, b)
		skip(conn, int(b[0])+2)
	case 0x04:
		skip(conn, 18)
	default:
		return fmt.Errorf("upstream socks5 unknown address type 0x%02x", reply[3])
	}
	return nil
}

func (u *UpstreamProxy) socks5Auth(conn net.Conn) error {
	buf := make([]byte, 0, 2+len(u.username)+1+len(u.password))
	buf = append(buf, 0x01, byte(len(u.username)))
	buf = append(buf, []byte(u.username)...)
	buf = append(buf, byte(len(u.password)))
	buf = append(buf, []byte(u.password)...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("upstream socks5 auth failed")
	}
	return nil
}

// wrapTLS upgrades a plain TCP conn to a TLS conn. No certificate
// verification is done because most corporate MITM proxies present a
// self-signed cert for their HTTP CONNECT tunnel — verifying would break
// the chain. Callers that want verification should dial the upstream
// themselves with http.Transport. When u.clientCert is set (via
// SetClientCert) it is presented during the handshake for mTLS.
func (u *UpstreamProxy) wrapTLS(conn net.Conn) (net.Conn, error) {
	cfg := &tls.Config{
		ServerName:         u.host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	if u.clientCert != nil {
		cfg.Certificates = []tls.Certificate{*u.clientCert}
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// skip discards n bytes from the conn.
func skip(conn net.Conn, n int) {
	if n <= 0 {
		return
	}
	buf := make([]byte, 4096)
	remaining := n
	for remaining > 0 {
		chunk := remaining
		if chunk > len(buf) {
			chunk = len(buf)
		}
		_, err := io.ReadFull(conn, buf[:chunk])
		if err != nil {
			return
		}
		remaining -= chunk
	}
}

// doneHTTPResponse reports whether we've seen the "\r\n\r\n" end of headers.
func doneHTTPResponse(s string) bool {
	return len(s) >= 4 && s[len(s)-4:] == "\r\n\r\n"
}

// isHTTPOk returns true if the status line indicates a 2xx response.
// CONNECT should return 200 Connection Established.
func isHTTPOk(s string) bool {
	if len(s) < 12 {
		return false
	}
	space := 0
	for space < len(s) && s[space] != ' ' {
		space++
	}
	if space >= len(s) {
		return false
	}
	if space+4 > len(s) {
		return false
	}
	code := s[space+1 : space+4]
	return code[0] == '2'
}

func statusLine(s string) string {
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

// Latency implements Proxy. Not used for UpstreamProxy in normal operation
// (the router won't pick it as a target), but provided so UpstreamProxy
// satisfies Proxy if that ever becomes useful.
func (u *UpstreamProxy) Latency(target string) (time.Duration, error) {
	if target == "" {
		target = "example.com:443"
	}
	start := time.Now()
	conn, err := u.Connect(context.Background(), target)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

// Close implements Proxy.
func (u *UpstreamProxy) Close() error { return nil }
