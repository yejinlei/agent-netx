package listener

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"agent-netx/config"
	"agent-netx/mitm"
)

// newTestInterceptor builds a throwaway CA + interceptor for tests.
func newTestInterceptor(t *testing.T) (*mitm.CACert, *mitm.Interceptor) {
	t.Helper()
	ca, err := mitm.GenerateCA("listener-test")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return ca, mitm.NewInterceptor(ca, t.TempDir())
}

func TestShouldIntercept(t *testing.T) {
	_, ic := newTestInterceptor(t)
	h := &MITMHandler{
		Interceptor: ic,
		Allowlist: []string{
			"DOMAIN,example.com",
			"DOMAIN-SUFFIX,.test.org",
			"IP-CIDR,10.0.0.0/8",
		},
	}

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"exact domain", "example.com", true},
		{"domain with port", "example.com:443", true},
		{"subdomain of suffix rule", "api.test.org", true},
		{"suffix with port", "deep.host.test.org:8443", true},
		{"ip inside cidr", "10.1.2.3", true},
		{"ip inside cidr with port", "10.9.9.9:443", true},
		{"unmatched domain", "evil.com", false},
		{"unmatched ip", "8.8.8.8", false},
		{"suffix lookalike without dot boundary", "nottest.org", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := h.ShouldIntercept(tt.target); got != tt.want {
				t.Errorf("ShouldIntercept(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestShouldInterceptEmptyAllowlistNeverIntercepts(t *testing.T) {
	// 安全红线: an empty allowlist must disable interception even when the
	// handler is fully configured with enable-equivalent state.
	_, ic := newTestInterceptor(t)
	h := &MITMHandler{Interceptor: ic}
	if h.ShouldIntercept("anything.example.com") {
		t.Error("empty allowlist intercepted — violates default-deny")
	}
	if h.ShouldInterceptIP("10.0.0.1") {
		t.Error("empty allowlist intercepted by IP — violates default-deny")
	}
	var nilH *MITMHandler
	if nilH.ShouldIntercept("example.com") || nilH.ShouldInterceptIP("10.0.0.1") {
		t.Error("nil receiver should report false, not panic")
	}
}

func TestSkipHostsOverridesAllowlist(t *testing.T) {
	_, ic := newTestInterceptor(t)
	h := &MITMHandler{
		Interceptor: ic,
		Allowlist:   []string{"MATCH,all"},
		SkipHosts:   []string{"DOMAIN,vault.internal"},
	}
	if !h.ShouldIntercept("allowed.example.com") {
		t.Error("allowlist MATCH should intercept non-skipped hosts")
	}
	if h.ShouldIntercept("vault.internal") {
		t.Error("skip-hosts rule must win over allowlist")
	}
	if h.ShouldIntercept("vault.internal:443") {
		t.Error("skip-hosts must apply after port stripping")
	}
	if !h.SkipHost("vault.internal") {
		t.Error("SkipHost(vault.internal) = false, want true")
	}
	if h.SkipHost("other.internal") {
		t.Error("SkipHost on unmatched host = true, want false")
	}
	var nilH *MITMHandler
	if nilH.SkipHost("vault.internal") {
		t.Error("nil receiver SkipHost should report false")
	}
}

func TestShouldInterceptIPMatchesCIDRNotDomains(t *testing.T) {
	_, ic := newTestInterceptor(t)
	h := &MITMHandler{
		Interceptor: ic,
		Allowlist: []string{
			"IP-CIDR,192.168.0.0/16",
			"DOMAIN,example.com", // DOMAIN rules can never match a raw IP
		},
	}
	if !h.ShouldInterceptIP("192.168.5.5") {
		t.Error("IP inside CIDR not intercepted")
	}
	if h.ShouldInterceptIP("192.169.0.1") {
		t.Error("IP outside CIDR intercepted")
	}
	// A hostname on the IP path matches only DOMAIN-style rules (exact/suffix/
	// keyword); IP-CIDR rules can never match it. This documents the deliberate
	// semantics: transparent connections deliver IPs, so DOMAIN rules there are
	// inert and IP-CIDR rules do all the work.
	if !h.ShouldInterceptIP("example.com") {
		t.Error("DOMAIN rule should still match a literal hostname string")
	}
	if h.ShouldInterceptIP("other.example.org") {
		t.Error("unmatched hostname intercepted via IP path")
	}
}

// TestInterceptConnectEndToEnd exercises the full double-TLS relay: a fake
// client speaks TLS to us (terminated with our per-host MITM cert), we dial
// and re-encrypt toward a real HTTPS origin (httptest TLS server), and the
// decrypted request/response must round-trip. This is the regression test for
// the upstream-plaintext defect: before the fix the first request went to :443
// as raw cleartext and nothing worked against a real HTTPS server.
func TestInterceptConnectEndToEnd(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Mitm-Echo", r.Header.Get("X-Mitm-Echo"))
		fmt.Fprintf(w, "hello from origin: %s %s", r.Method, r.URL.Path)
	}))
	defer origin.Close()

	originAddr := strings.TrimPrefix(origin.URL, "https://") // 127.0.0.1:port
	host, port, err := net.SplitHostPort(originAddr)
	if err != nil {
		t.Fatalf("split %q: %v", originAddr, err)
	}
	target := net.JoinHostPort(host, port)

	ca, ic := newTestInterceptor(t)
	pool, err := ca.CertPool()
	if err != nil {
		t.Fatalf("CertPool: %v", err)
	}

	h := &MITMHandler{
		Interceptor: ic,
		Allowlist:   []string{"IP-CIDR,127.0.0.0/8"},
	}
	if !h.ShouldIntercept(target) {
		t.Fatal("precondition: target should be allowlisted")
	}

	// net.Pipe is synchronous: a Write blocks until the peer Reads. The
	// client's Finished flight can only be drained while InterceptConnect is
	// dialing the upstream, so the client I/O must run concurrently with it —
	// hence handshake+write in their own goroutine.
	clientEnd, handlerEnd := net.Pipe()
	defer clientEnd.Close()

	clientTLS := tls.Client(clientEnd, &tls.Config{
		ServerName: host,
		RootCAs:    pool,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	clientErr := make(chan error, 1)
	go func() {
		// Client side: TLS handshake trusting our generated CA, then send a
		// GET over the terminated session.
		if err := clientTLS.Handshake(); err != nil {
			clientErr <- fmt.Errorf("client handshake: %w", err)
			return
		}
		_, werr := clientTLS.Write([]byte("GET /probe HTTP/1.1\r\nHost: " + target + "\r\nX-Mitm-Echo: tok123\r\nConnection: close\r\n\r\n"))
		clientErr <- werr
	}()

	type result struct {
		tlsClient, upstream net.Conn
		reqBytes            []byte
		err                 error
	}
	done := make(chan result, 1)
	go func() {
		c, u, b, err := h.InterceptConnect(handlerEnd, target)
		done <- result{c, u, b, err}
	}()

	res := <-done
	if res.err != nil {
		t.Fatalf("InterceptConnect: %v", res.err)
	}
	defer res.upstream.Close()
	if err := <-clientErr; err != nil {
		t.Fatalf("client side: %v", err)
	}

	// The returned first-request bytes must be the plaintext headers we sent.
	if !strings.Contains(string(res.reqBytes), "GET /probe HTTP/1.1") {
		t.Errorf("firstReq = %q, want it to contain the plaintext request line", res.reqBytes)
	}

	// Relay exactly like http.go's CONNECT branch does: the caller writes the
	// consumed first request to upstream, then pumps both directions. Every
	// byte crossing the wrapper's Read must be forwarded — a request body
	// lives in the buffered remainder, and dropping reads would silently lose
	// it (this is what caught the tlsBufConn ReadFrom/WriteTo defect).
	if _, err := res.upstream.Write(res.reqBytes); err != nil {
		t.Fatalf("forward first request: %v", err)
	}
	go io.Copy(res.upstream, res.tlsClient) // client → origin
	go io.Copy(res.tlsClient, res.upstream) // origin → client

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// Tear down: closing clientTLS EOFs the forward pump; the origin's
	// Connection: close already EOFs the reverse pump after the body drained.
	clientTLS.Close()
	if want := "hello from origin: GET /probe"; string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
	if got := resp.Header.Get("X-Mitm-Echo"); got != "tok123" {
		t.Errorf("X-Mitm-Echo = %q, want %q (request headers did not survive decryption)", got, "tok123")
	}
}

// TestInterceptConnectUpstreamFailureKeepsConnUsable verifies the fallback
// contract: when the origin is unreachable or not speaking TLS,
// InterceptConnect returns an error WITHOUT having touched the client conn —
// the caller can still write "200 Connection Established" and tunnel blindly.
func TestInterceptConnectUpstreamFailureKeepsConnUsable(t *testing.T) {
	// A plain TCP listener that never speaks TLS (simulates a non-HTTP
	// protocol on 443): the upstream handshake must fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			c.Close()
			return
		}
		// Read the client hello, then hard-close (RST) the socket: the
		// upstream handshake fails fast with a reset instead of hanging
		// forever waiting for a ServerHello that never comes.
		buf := make([]byte, 512)
		tc.SetReadDeadline(time.Now().Add(2 * time.Second))
		tc.Read(buf)
		tc.SetLinger(0)
		tc.Close()
	}()

	_, ic := newTestInterceptor(t)
	h := &MITMHandler{
		Interceptor: ic,
		Allowlist:   []string{"IP-CIDR,127.0.0.0/8"},
	}

	clientEnd, handlerEnd := net.Pipe()
	defer clientEnd.Close()
	defer handlerEnd.Close()

	_, _, _, err = h.InterceptConnect(handlerEnd, ln.Addr().String())
	if err == nil {
		t.Fatal("want upstream handshake failure, got success")
	}
	// The client-side conn must be untouched raw TCP: bytes written by the
	// caller's tunnel path arrive verbatim at the other half. net.Pipe is
	// synchronous — no reader means Write blocks forever — so the concurrent
	// Read stands in for the real tunnel relay and must be started BEFORE the
	// probe write. If the conn had been left TLS-wrapped/owned the read would
	// never resolve; that outcome is reported via a channel with a bounded
	// wait instead of hanging the whole test binary.
	readResult := make(chan error, 1)
	buf := make([]byte, 5)
	go func() {
		_, rerr := io.ReadFull(handlerEnd, buf)
		readResult <- rerr
	}()
	if _, werr := clientEnd.Write([]byte("probe")); werr != nil {
		t.Fatalf("client conn unusable after failed interception: %v", werr)
	}
	select {
	case rerr := <-readResult:
		if rerr != nil {
			t.Fatalf("handler conn did not receive probe bytes: %v", rerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler conn never received probe bytes — conn left owned by interception")
	}
	if string(buf) != "probe" {
		t.Errorf("bytes = %q, want %q", buf, "probe")
	}
}

func TestMatchURLActions(t *testing.T) {
	tests := []struct {
		name      string
		rules     []config.URLAction
		firstLine string
		path      string
		want      URLActionResult
	}{
		{
			name:      "no rules",
			rules:     nil,
			firstLine: "GET /foo HTTP/1.1",
			path:      "/foo",
			want:      URLActionResult{},
		},
		{
			name:      "no match",
			rules:     []config.URLAction{{Match: "/block", Action: "block"}},
			firstLine: "GET /other HTTP/1.1",
			path:      "/other",
			want:      URLActionResult{},
		},
		{
			name:      "substring block with defaults",
			rules:     []config.URLAction{{Match: "/admin", Action: "block"}},
			firstLine: "GET /admin/panel HTTP/1.1",
			path:      "/admin/panel",
			want:      URLActionResult{Action: "block", Status: 403, RuleMatch: "/admin"},
		},
		{
			name: "substring block custom status and body",
			rules: []config.URLAction{{
				Match: "/api/v2", Action: "block", Status: 429,
				Body: "rate limited",
			}},
			firstLine: "POST /api/v2/foo HTTP/1.1",
			path:      "/api/v2/foo",
			want:      URLActionResult{Action: "block", Status: 429, Body: "rate limited", RuleMatch: "/api/v2"},
		},
		{
			name: "redirect with explicit location",
			rules: []config.URLAction{{
				Match: "/old", Action: "redirect",
				Location: "https://example.com/new",
			}},
			firstLine: "GET /old HTTP/1.1",
			path:      "/old",
			want:      URLActionResult{Action: "redirect", Status: 302, Location: "https://example.com/new", RuleMatch: "/old"},
		},
		{
			name: "redirect with custom status",
			rules: []config.URLAction{{
				Match: "/moved", Action: "redirect", Status: 301,
				Location: "https://example.com/new",
			}},
			firstLine: "GET /moved HTTP/1.1",
			path:      "/moved",
			want:      URLActionResult{Action: "redirect", Status: 301, Location: "https://example.com/new", RuleMatch: "/moved"},
		},
		{
			name:      "redirect with empty location — rule skipped",
			rules:     []config.URLAction{{Match: "/x", Action: "redirect", Location: ""}},
			firstLine: "GET /x HTTP/1.1",
			path:      "/x",
			want:      URLActionResult{},
		},
		{
			name:      "empty match skipped",
			rules:     []config.URLAction{{Match: "", Action: "block"}},
			firstLine: "GET /foo HTTP/1.1",
			path:      "/foo",
			want:      URLActionResult{},
		},
		{
			name:      "regex match against full request line",
			rules:     []config.URLAction{{Match: "^GET /v2/.*", Regex: true, Action: "redirect", Location: "https://example.com/v3"}},
			firstLine: "GET /v2/users HTTP/1.1",
			path:      "/v2/users",
			want:      URLActionResult{Action: "redirect", Status: 302, Location: "https://example.com/v3", RuleMatch: "^GET /v2/.*"},
		},
		{
			name:      "regex doesn't match POST",
			rules:     []config.URLAction{{Match: "^GET /v2/.*", Regex: true, Action: "redirect", Location: "https://example.com/v3"}},
			firstLine: "POST /v2/users HTTP/1.1",
			path:      "/v2/users",
			want:      URLActionResult{},
		},
		{
			name:      "regex against path fragment",
			rules:     []config.URLAction{{Match: `/block[0-9]+`, Regex: true, Action: "block", Status: 403, Body: "gone"}},
			firstLine: "GET /block42 HTTP/1.1",
			path:      "/block42",
			want:      URLActionResult{Action: "block", Status: 403, Body: "gone", RuleMatch: `/block[0-9]+`},
		},
		{
			name:      "first match wins",
			rules:     []config.URLAction{{Match: "/api", Action: "block", Status: 403, Body: "first"}, {Match: "api/v2", Action: "block", Status: 404, Body: "second"}},
			firstLine: "GET /api/v2 HTTP/1.1",
			path:      "/api/v2",
			want:      URLActionResult{Action: "block", Status: 403, Body: "first", RuleMatch: "/api"},
		},
		{
			name:      "unknown action falls back to block 501",
			rules:     []config.URLAction{{Match: "/foo", Action: "munge"}},
			firstLine: "GET /foo HTTP/1.1",
			path:      "/foo",
			want:      URLActionResult{Action: "block", Status: 501, Body: "unsupported action", RuleMatch: "/foo"},
		},
		{
			name:      "case sensitive substring",
			rules:     []config.URLAction{{Match: "/Admin", Action: "block"}},
			firstLine: "GET /admin HTTP/1.1",
			path:      "/admin",
			want:      URLActionResult{},
		},
		{
			name:      "bad regex skipped",
			rules:     []config.URLAction{{Match: "(", Regex: true, Action: "block"}},
			firstLine: "GET /foo HTTP/1.1",
			path:      "/foo",
			want:      URLActionResult{},
		},
		{
			name:      "inject action default status",
			rules:     []config.URLAction{{Match: "/api", Action: "inject", Headers: []string{"Content-Type: application/json"}, Body: `{"ok":true}`}},
			firstLine: "GET /api/x HTTP/1.1",
			path:      "/api/x",
			want:      URLActionResult{Action: "inject", Status: 200, Body: `{"ok":true}`, Headers: []string{"Content-Type: application/json"}, RuleMatch: "/api"},
		},
		{
			name:      "inject action custom status",
			rules:     []config.URLAction{{Match: "/api", Action: "inject", Status: 503, Body: "gone"}},
			firstLine: "GET /api HTTP/1.1",
			path:      "/api",
			want:      URLActionResult{Action: "inject", Status: 503, Body: "gone", RuleMatch: "/api"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchURLActions(tt.rules, tt.firstLine, tt.path)
			// URLActionResult now contains a []string field, so != can't
			// compare; use reflect.DeepEqual.
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("matchURLActions() = %#v, want %#v", got, tt.want)
			}
		})
	}
}


