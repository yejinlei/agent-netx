package proxy

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// startFakeProxy returns an address that accepts TCP, reads one CONNECT
// request (headers included), writes back a fixed response, and captures
// the request text for assertions. status==0 means "never respond" for the
// timeout path.
func startFakeProxy(t *testing.T, status int, captured *string) (addr string, done func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done = func() { ln.Close() }
	go func() {
		defer ln.Close()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				// Read until "\r\n\r\n" — same discipline as startRawHTTPProxy:
				// stop after the full headers, or leftover header bytes get
				// misread as tunnel data.
				var buf []byte
				chunk := make([]byte, 512)
				for {
					n, err := c.Read(chunk)
					if n > 0 {
						buf = append(buf, chunk[:n]...)
						if strings.Contains(string(buf), "\r\n\r\n") {
							break
						}
					}
					if err != nil {
						return
					}
				}
				*captured = string(buf)
				if status == 0 {
					// Silent server — never responds. Caller asserts timeout.
					time.Sleep(3 * time.Second)
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 " + itoa(status) + " OK\r\n\r\n"))
			}(c)
		}
	}()
	return ln.Addr().String(), done
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// startFakeProxyWithCapture is the append-per-connect variant — captures
// every CONNECT body in order via the callback so tests can assert per-
// call content instead of overwriting a single slot.
func startFakeProxyWithCapture(t *testing.T, status int, cb func(string)) (addr string, done func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done = func() { ln.Close() }
	go func() {
		defer ln.Close()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				var buf []byte
				chunk := make([]byte, 512)
				for {
					n, err := c.Read(chunk)
					if n > 0 {
						buf = append(buf, chunk[:n]...)
						if strings.Contains(string(buf), "\r\n\r\n") {
							break
						}
					}
					if err != nil {
						return
					}
				}
				cb(string(buf))
				if status == 0 {
					time.Sleep(3 * time.Second)
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 " + itoa(status) + " OK\r\n\r\n"))
			}(c)
		}
	}()
	return ln.Addr().String(), done
}

func TestSendConnectNoAuth(t *testing.T) {
	var captured string
	addr, done := startFakeProxy(t, 200, &captured)
	defer done()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := sendConnect(conn, "example.com:443", ""); err != nil {
		t.Fatalf("sendConnect: %v", err)
	}

	if !strings.HasPrefix(captured, "CONNECT example.com:443 HTTP/1.1\r\n") {
		t.Errorf("request line: %q", captured)
	}
	if !strings.Contains(captured, "Host: example.com:443\r\n") {
		t.Errorf("missing Host: %q", captured)
	}
	if strings.Contains(captured, "Proxy-Authorization") {
		t.Errorf("no auth expected, got %q", captured)
	}
}

func TestSendConnectBasicAuth(t *testing.T) {
	var captured string
	addr, done := startFakeProxy(t, 200, &captured)
	defer done()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	token := "dXNlcjpwYXNz" // base64("user:pass")
	if err := sendConnect(conn, "example.com:443", token); err != nil {
		t.Fatalf("sendConnect: %v", err)
	}

	want := "Proxy-Authorization: Basic " + token + "\r\n"
	if !strings.Contains(captured, want) {
		t.Errorf("missing %q in %q", want, captured)
	}
}

func TestSendConnectRejectsNon200(t *testing.T) {
	for _, status := range []int{401, 403, 407, 502} {
		t.Run("status"+itoa(status), func(t *testing.T) {
			var captured string
			addr, done := startFakeProxy(t, status, &captured)
			defer done()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			err = sendConnect(conn, "example.com:443", "")
			if err == nil {
				t.Fatalf("expected error for HTTP %d", status)
			}
			if !strings.Contains(err.Error(), "connect failed") {
				t.Errorf("err shape: %v", err)
			}
			// Status code should be surfaced so operators can tell 407 (auth)
			// from 403 (policy) without a proxy-side log.
			if !strings.Contains(err.Error(), itoa(status)) {
				t.Errorf("err missing status %d: %v", status, err)
			}
		})
	}
}

func TestSendConnectRejectsSilentServer(t *testing.T) {
	var captured string
	addr, done := startFakeProxy(t, 0, &captured)
	defer done()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := sendConnect(conn, "example.com:443", ""); err == nil {
		t.Fatalf("expected error when proxy never responds")
	}
}

func TestHTTPReadResponseParsesStatusAndReason(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go func() {
		_, _ = a.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}()

	resp, err := httpReadResponse(b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.status != 200 {
		t.Errorf("status: got %d want 200", resp.status)
	}
	if resp.reason != "Connection Established" {
		t.Errorf("reason: got %q", resp.reason)
	}
}

func TestHTTPReadResponseDrainsHeaders(t *testing.T) {
	// Multiple headers, then blank line. httpReadResponse must drain the
	// header block exactly to "\r\n\r\n" and return the correct status.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go func() {
		_, _ = a.Write([]byte("HTTP/1.1 200 OK\r\nX-One: 1\r\nX-Two: 2\r\n\r\n"))
	}()

	resp, err := httpReadResponse(b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.status != 200 {
		t.Errorf("status: got %d", resp.status)
	}
	if resp.reason != "OK" {
		t.Errorf("reason: got %q", resp.reason)
	}
}

func TestHTTPReadResponseRejectsGarbage(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// httpReadResponse uses bufio with no internal timeout — a pipe whose
	// writer never closes would block forever. A read deadline turns that
	// into an error we can assert on.
	_ = b.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	go func() { _, _ = a.Write([]byte("no http here")) }()
	if _, err := httpReadResponse(b); err == nil {
		t.Errorf("expected error on non-HTTP data")
	}
}

func TestHTTPProxyNoAuthSendsNoHeader(t *testing.T) {
	var captured string
	addr, done := startFakeProxy(t, 200, &captured)
	defer done()
	host, port, _ := net.SplitHostPort(addr)
	p := &HTTPProxy{cfg: Config{Server: host, Port: atoi(port), Username: "", Password: ""}}
	if _, err := p.Connect(t.Context(), "example.com:443"); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if strings.Contains(captured, "Proxy-Authorization") {
		t.Errorf("no auth configured, but header sent: %q", captured)
	}
}

func TestHTTPProxyAuthSendsBasicHeader(t *testing.T) {
	var captured string
	addr, done := startFakeProxy(t, 200, &captured)
	defer done()
	host, port, _ := net.SplitHostPort(addr)
	p := &HTTPProxy{cfg: Config{Server: host, Port: atoi(port), Username: "user", Password: "pass"}}
	if _, err := p.Connect(t.Context(), "example.com:443"); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !strings.Contains(captured, "Proxy-Authorization: Basic dXNlcjpwYXNz") {
		t.Errorf("missing Basic auth header: %q", captured)
	}
}

// TestHTTPProxyAuthTokenRecomputedPerConnect guards against a caller caching
// the base64 token outside Connect. A real deployment rotates creds mid-
// session; the next CONNECT must use the new creds, not the stale ones.
func TestHTTPProxyAuthTokenRecomputedPerConnect(t *testing.T) {
	var mu sync.Mutex
	var first, second string
	got := make(chan struct{}, 2)
	addr, done := startFakeProxyWithCapture(t, 200, func(s string) {
		mu.Lock()
		defer mu.Unlock()
		if first == "" {
			first = s
		} else {
			second = s
		}
		got <- struct{}{}
	})
	defer done()
	host, port, _ := net.SplitHostPort(addr)
	p := &HTTPProxy{cfg: Config{Server: host, Port: atoi(port), Username: "u1", Password: "p1"}}
	if _, err := p.Connect(t.Context(), "example.com:443"); err != nil {
		t.Fatalf("first connect: %v", err)
	}
	p.cfg.Username = "u2"
	p.cfg.Password = "p2"
	if _, err := p.Connect(t.Context(), "example.com:443"); err != nil {
		t.Fatalf("second connect:  %v", err)
	}
	// Wait for the server to have received both CONNECTs before asserting.
	for i := 0; i < 2; i++ {
		select {
		case <-got:
		case <-time.After(2 * time.Second):
			t.Fatalf("server did not receive both CONNECTs")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	// base64("u1:p1") = "dTE6cDE=", base64("u2:p2") = "dTI6cDI="
	if !strings.Contains(first, "Basic dTE6cDE=") {
		t.Errorf("first CONNECT used wrong token: %q", first)
	}
	if !strings.Contains(second, "Basic dTI6cDI=") {
		t.Errorf("second CONNECT reused stale token (expected dTI6cDI=): %q", second)
	}
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
