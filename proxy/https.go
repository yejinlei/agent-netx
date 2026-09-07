package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type HTTPSProxy struct {
	cfg Config
}

func NewHTTPS(cfg Config) Proxy { return &HTTPSProxy{cfg: cfg} }

func (h *HTTPSProxy) Name() string { return h.cfg.Name }

func (h *HTTPSProxy) Connect(ctx context.Context, addr string) (net.Conn, error) {
	target := net.JoinHostPort(h.cfg.Server, strconv.Itoa(h.cfg.Port))
	rawConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("https proxy dial %s: %w", target, err)
	}

	sni := h.cfg.SNI
	if sni == "" {
		sni, _, _ = net.SplitHostPort(target)
	}
	tlsConn := tls.Client(rawConn, TLSConfig(sni, h.cfg.ALPN))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("https proxy tls handshake: %w", err)
	}

	// Same per-request Basic auth pattern as HTTPProxy.Connect — HTTPS proxies
	// speak CONNECT over a TLS tunnel to the proxy, but auth is still a
	// CONNECT header.
	token := ""
	if h.cfg.Username != "" {
		token = base64.StdEncoding.EncodeToString([]byte(h.cfg.Username + ":" + h.cfg.Password))
	}
	if err := sendConnect(tlsConn, addr, token); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (h *HTTPSProxy) Latency(url string) (time.Duration, error) {
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

func (h *HTTPSProxy) Close() error { return nil }