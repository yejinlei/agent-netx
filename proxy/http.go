package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type HTTPProxy struct {
	cfg Config
}

func NewHTTP(cfg Config) Proxy { return &HTTPProxy{cfg: cfg} }

func (h *HTTPProxy) Name() string { return h.cfg.Name }

func (h *HTTPProxy) Connect(ctx context.Context, addr string) (net.Conn, error) {
	target := net.JoinHostPort(h.cfg.Server, strconv.Itoa(h.cfg.Port))
	rawConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("http proxy dial %s: %w", target, err)
	}

	var conn net.Conn = rawConn
	if h.cfg.SNI != "" {
		tlsConn := tls.Client(rawConn, TLSConfig(h.cfg.SNI, h.cfg.ALPN))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("http proxy tls: %w", err)
		}
		conn = tlsConn
	}

	// Basic auth is per-request (Proxy-Authorization), not per-connection —
	// some proxies require it on every CONNECT. The token is recomputed each
	// Connect so credentials can rotate across calls.
	token := ""
	if h.cfg.Username != "" {
		token = base64.StdEncoding.EncodeToString([]byte(h.cfg.Username + ":" + h.cfg.Password))
	}

	if err := sendConnect(conn, addr, token); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// sendConnect sends a CONNECT request and reads the response. token is the
// base64-encoded "user:pass" Basic-auth payload, or "" for no auth. 200 is
// the only success status (407 = auth required, 403/404 = policy reject).
func sendConnect(conn net.Conn, addr string, token string) error {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if token != "" {
		req += "Proxy-Authorization: Basic " + token + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	resp, err := httpReadResponse(conn)
	if err != nil {
		return err
	}
	if resp.status != 200 {
		return fmt.Errorf("connect failed: %d %s", resp.status, resp.reason)
	}
	return nil
}

type httpResp struct {
	status int
	reason string
}

func httpReadResponse(conn net.Conn) (httpResp, error) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return httpResp{}, err
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return httpResp{}, fmt.Errorf("bad http response")
	}
	var status int
	fmt.Sscanf(parts[1], "%d", &status)
	reason := ""
	if len(parts) >= 3 {
		reason = parts[2]
	}
	for {
		h, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.TrimSpace(h) == "" {
			break
		}
	}
	return httpResp{status: status, reason: reason}, nil
}

func (h *HTTPProxy) Latency(url string) (time.Duration, error) {
	host := url
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	start := time.Now()
	conn, err := h.Connect(context.Background(), host)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

func (h *HTTPProxy) Close() error { return nil }