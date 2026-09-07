package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUpstreamProxyNewParsing(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		scheme   string
		port     int
		user     string
		pass     string
		wantErr  bool
	}{
		{"empty", "", "", 0, "", "", false},
		{"http_with_port", "http://127.0.0.1:3128", "http", 3128, "", "", false},
		{"http_no_port", "http://proxy.example.com", "http", 3128, "", "", false},
		{"https_port", "https://proxy.example.com:8443", "https", 8443, "", "", false},
		{"socks5_default", "socks5://127.0.0.1:1080", "socks5", 1080, "", "", false},
		{"socks5_auth", "socks5://user:pass@127.0.0.1:1080", "socks5", 1080, "user", "pass", false},
		{"unsupported_scheme", "ftp://127.0.0.1:21", "", 0, "", "", true},
		{"no_host", "http://", "", 0, "", "", true},
		{"bad_port", "http://127.0.0.1:xx", "", 0, "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := NewUpstreamProxy(c.url, time.Second)
			if c.wantErr {
				if err == nil && p != nil {
					t.Fatalf("expected error, got %v", p)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if c.url == "" {
				return // empty input → nil proxy, no fields to check
			}
			if p == nil {
				t.Fatalf("expected non-nil proxy for %q", c.url)
			}
			if p.scheme != c.scheme {
				t.Errorf("scheme: got %q want %q", p.scheme, c.scheme)
			}
			if p.port != c.port {
				t.Errorf("port: got %d want %d", p.port, c.port)
			}
			if p.username != c.user {
				t.Errorf("user: got %q want %q", p.username, c.user)
			}
			if p.password != c.pass {
				t.Errorf("pass: got %q want %q", p.password, c.pass)
			}
			if !p.IsConfigured() {
				t.Errorf("IsConfigured should be true for %q", c.url)
			}
		})
	}
}

func TestUpstreamProxyIsConfiguredNil(t *testing.T) {
	var p *UpstreamProxy
	if p.IsConfigured() {
		t.Errorf("nil proxy must not report configured")
	}
}

// startRawHTTPProxy opens a TCP listener that accepts CONNECT requests and
// forwards them to the given backend address via a hijacked TCP pipe.
// httptest's server handler is used only for the initial request-line parse;
// the actual pipe is raw TCP. Returns the proxy address.
func startRawHTTPProxy(t *testing.T) (addr string, done func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	var wg sync.WaitGroup
	done = func() { ln.Close(); wg.Wait() }
		wg.Add(1)
	go func() {
		defer wg.Done()
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Parse "CONNECT host:port HTTP/1.1\r\n" manually — the
				// target is a bare host:port string that http.RequestURI
				// won't parse reliably (no scheme).
				reqLine := make([]byte, 0, 256)
				buf := make([]byte, 1)
				for {
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					reqLine = append(reqLine, buf[0])
					// Read until we've consumed the whole request (headers
					// included). Otherwise leftover header bytes get read
					// as tunnel data and corrupt the backend request.
					if len(reqLine) >= 4 && string(reqLine[len(reqLine)-4:]) == "\r\n\r\n" {
						break
					}
				}
				// The request line is the first line of the buffer.
				full := string(reqLine)
				line := full
				if idx := strings.Index(full, "\r\n"); idx >= 0 {
					line = full[:idx]
				}
				if !strings.HasPrefix(line, "CONNECT ") {
					_, _ = c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
					return
				}
				fields := strings.Fields(line)
				if len(fields) < 2 {
					return
				}
				target := fields[1]
				backend, err := net.Dial("tcp", target)
				if err != nil {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer backend.Close()
				if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
					return
				}
				done := make(chan struct{})
				go func() { _, _ = io.Copy(backend, c); close(done) }()
				_, _ = io.Copy(c, backend)
				<-done
			}(conn)
		}
	}()
	return ln.Addr().String(), done
}

func TestUpstreamProxyConnectHTTP(t *testing.T) {
	// Backend HTTP server — the "target" the client ultimately talks to.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("through-the-proxy"))
	}))
	defer target.Close()

	// Upstream CONNECT proxy.
	proxyAddr, doneProxy := startRawHTTPProxy(t)
	defer doneProxy()

	up, err := NewUpstreamProxy("http://"+proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}

	conn, err := up.Connect(context.Background(), target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(buf[:n]) < 5 || string(buf[:5]) != "HTTP/" {
		t.Fatalf("unexpected response: %q", string(buf[:n]))
	}
	if indexOf(buf[:n], "through-the-proxy") < 0 {
		t.Fatalf("missing target body in response: %q", string(buf[:n]))
	}
}

func TestUpstreamProxyRejectsUnsupportedScheme(t *testing.T) {
	_, err := NewUpstreamProxy("ftp://127.0.0.1:21", time.Second)
	if err == nil {
		t.Fatalf("expected New to reject ftp://")
	}
}

func indexOf(haystack []byte, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == needle {
			return i
		}
	}
	return -1
}
