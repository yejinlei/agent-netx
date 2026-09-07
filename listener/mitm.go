package listener

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"agent-netx/config"
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
	// RewriteRules are substring replacements applied to decrypted MITM
	// traffic. Match is a plain-text substring; Replace is the replacement
	// string. Applied per-Read chunk in both directions.
	RewriteRules []config.RewriteRule
	// LogFile, when non-nil, receives JSON-lines of intercepted request lines
	// + first response status lines. nil = no disk logging.
	LogFile *os.File
	// URLActions are URL pattern → response rules, evaluated after the first
	// request line is read (once for MITM CONNECT interception, once for
	// plain HTTP proxy traffic). Match rules in config order; first hit
	// wins. Empty Match / unknown Action = rule skipped. Block writes
	// Status+Body, redirect writes a 302 with Location, inject writes
	// Status+Headers+Body with caller-controlled headers.
	//
	// The MITM path only sees hosts on the Allowlist (never a plain CONNECT
	// tunnel); the plain HTTP path sees everything routed through :HTTP.
	URLActions []config.URLAction
	// URLLog, when non-nil, receives one JSON line per triggered URLAction
	// (host, path, matched rule, action). Used to audit what fired.
	URLLog *os.File
	// ClientCert, when non-nil, is presented on the re-encrypted MITM
	// upstream TLS session (mTLS to the origin server). Loaded in
	// buildMITMHandler from config.MITM.ClientCrt/ClientKey. Rarely used —
	// most origins don't require client auth — but supported for corporate
	// endpoints that pin the caller's identity.
	ClientCert *tls.Certificate
}

// URLActionResult is the outcome of evaluating URLActions against a request.
type URLActionResult struct {
	Action   string // "block", "redirect", "inject", or "" (no rule matched)
	Status   int    // HTTP status for block, redirect, or inject
	Body     string // body for block/inject (may be empty)
	Location string // target for redirect (may be empty)
	Headers  []string // "Name: value" lines for inject (may be empty)
	RuleMatch string // the Match string of the firing rule, for audit/log
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

	// Log the intercepted request immediately — it has just been consumed
	// from br by readFirstHTTPRequest, so it never traverses a loggingConn
	// wrapper around tlsClient.
	if h.LogFile != nil {
		h.logHTTPRequest(reqBytes)
	}

	// URLAction short-circuit: if a rule fires on the decrypted request path,
	// reply to the client directly over the TLS session and don't write the
	// request upstream. This costs no outbound connection and lets operators
	// block or redirect specific paths on intercepted hosts without touching
	// the origin. Returning (nil, nil, nil, nil) tells the caller the client
	// side is done and should not relay.
	if len(h.URLActions) > 0 {
		firstLine := string(reqBytes)
		if i := strings.IndexByte(firstLine, '\n'); i > 0 {
			firstLine = firstLine[:i]
		}
		parts := strings.Fields(firstLine)
		path := ""
		if len(parts) >= 2 {
			path = parts[1]
		}
		if r := h.MatchURLAction(firstLine, path); r.Action != "" {
			WriteURLResponse(tlsServer, r)
			tlsServer.Close()
			upstreamTLS.Close()
			return nil, nil, nil, nil
		}
	}

	// Wrap the upstream TLS session with a loggingConn so the first response
	// status line is captured as it flows from the origin back to us.
	var wrappedUpstream net.Conn = upstreamTLS
	if h.LogFile != nil {
		wrappedUpstream = &loggingConn{Conn: wrappedUpstream, f: h.LogFile, dir: "upstream"}
	}

	tlsClient = &tlsBufConn{br: br, Conn: tlsServer}
	if len(h.RewriteRules) > 0 {
		tlsClient = &rewriteConn{tlsClient, h.RewriteRules, "client"}
	}
	return tlsClient, wrappedUpstream, reqBytes, nil
}

// logHTTPRequest writes one JSON entry for the captured plaintext request
// line. It ignores a nil/malformed line silently (we already have the bytes;
// a logging failure is not worth failing the connection over).
func (h *MITMHandler) logHTTPRequest(reqBytes []byte) {
	if h.LogFile == nil || len(reqBytes) == 0 {
		return
	}
	lineEnd := bytes.Index(reqBytes, []byte("\r\n"))
	if lineEnd < 0 {
		return
	}
	firstLine := string(reqBytes[:lineEnd])
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return
	}
	entry := mitmLogEntry{
		Timestamp: time.Now().Format("2006-01-02T15:04:05.000Z07:00"),
		Method:    parts[0],
		Path:      parts[1],
		Direction: "client",
		Protocol:  detectProtocol(reqBytes),
	}
	if len(parts) >= 3 {
		entry.Proto = parts[2]
	}
	jsonLine, _ := json.Marshal(entry)
	_, _ = h.LogFile.Write(append(jsonLine, '\n'))
}

// detectProtocol scans an HTTP request (first line + headers + trailing CRLF)
// for a WebSocket upgrade. Returns "ws" when any case-insensitive variant of
// "upgrade: websocket" is present; "http" otherwise. This is detection only —
// the relay still forwards bytes unchanged, and the substring rewrite rules
// (if configured) still apply to the plaintext handshake. Payload frames
// after 101 Switching Protocols are opaque to this layer and are not parsed.
func detectProtocol(reqBytes []byte) string {
	if len(reqBytes) == 0 {
		return "http"
	}
	upper := make([]byte, len(reqBytes))
	for i, b := range reqBytes {
		switch {
		case b >= 'a' && b <= 'z':
			upper[i] = b - 'a' + 'A'
		default:
			upper[i] = b
		}
	}
	s := string(upper)
	rest := s
	for {
		line, tail, ok := strings.Cut(rest, "\r\n")
		line = strings.TrimSpace(line)
		colon := strings.IndexByte(line, ':')
		if colon > 0 {
			if strings.TrimSpace(line[:colon]) == "UPGRADE" {
				if strings.Contains(strings.TrimSpace(line[colon+1:]), "WEBSOCKET") {
					return "ws"
				}
			}
		}
		if !ok {
			break
		}
		rest = tail
	}
	return "http"
}

// matchURLActions evaluates rules against firstLine (the HTTP request line,
// e.g. "GET /foo HTTP/1.1") and path (the u.Path portion). The first rule
// whose Match fires returns an action; no match returns an empty
// URLActionResult.
//
// Precedence: rules are checked in config order. Substring matching uses
// strings.Contains against path (case-sensitive — operators who need
// case-insensitive matching should use Regex with (?i:...) groups). RE2
// matching runs against the full request line, so `^GET /old/` anchors as
// expected.
//
// Empty Match, or a redirect action with empty Location, skip the rule.
// Unknown Action falls back to "block" with a 501 status.
func matchURLActions(rules []config.URLAction, firstLine, path string) URLActionResult {
	if len(rules) == 0 {
		return URLActionResult{}
	}
	for _, r := range rules {
		if r.Match == "" {
			continue
		}
		var hit bool
		if r.Regex {
			re, err := regexp.Compile(r.Match)
			if err != nil {
				continue // bad regex — skip, don't fail the request
			}
			hit = re.MatchString(firstLine)
		} else {
			hit = path != "" && strings.Contains(path, r.Match)
		}
		if !hit {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(r.Action))
		if action == "" {
			action = "block"
		}
		switch action {
		case "redirect":
			if r.Location == "" {
				continue // unusable redirect
			}
			st := r.Status
			if st == 0 {
				st = 302
			}
			return URLActionResult{Action: "redirect", Status: st, Location: r.Location, RuleMatch: r.Match}
		case "inject":
			st := r.Status
			if st == 0 {
				st = 200
			}
			return URLActionResult{Action: "inject", Status: st, Body: r.Body, Headers: r.Headers, RuleMatch: r.Match}
		case "block":
			st := r.Status
			if st == 0 {
				st = 403
			}
			return URLActionResult{Action: "block", Status: st, Body: r.Body, RuleMatch: r.Match}
		default:
			return URLActionResult{Action: "block", Status: 501, Body: "unsupported action", RuleMatch: r.Match}
		}
	}
	return URLActionResult{}
}

// MatchURLAction is the handler-scoped wrapper used by the MITM path.
func (h *MITMHandler) MatchURLAction(firstLine, path string) URLActionResult {
	if h == nil {
		return URLActionResult{}
	}
	return matchURLActions(h.URLActions, firstLine, path)
}

// WriteURLResponse emits an HTTP/1.1 response matching r to conn. It sets
// Content-Length, closes the connection (the proxy shouldn't reuse this
// socket for a fresh request from the same peer), and never hangs on a
// slow reader. For "inject" actions, r.Headers (each "Name: value")
// overrides the default Content-Type so callers can emit JSON, XML, or any
// content-type; Content-Length and Connection: close are always appended.
func WriteURLResponse(conn net.Conn, r URLActionResult) {
	if r.Action == "" {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	var reason string
	var body []byte
	if r.Action == "redirect" {
		reason = "Found"
		if r.Status == 301 {
			reason = "Moved Permanently"
		} else if r.Status == 303 {
			reason = "See Other"
		} else if r.Status == 307 {
			reason = "Temporary Redirect"
		} else if r.Status == 308 {
			reason = "Permanent Redirect"
		}
		body = []byte(fmt.Sprintf("<!doctype html><meta http-equiv='refresh' content='0;url=%s'><a href='%s'>Moved</a>", r.Location, r.Location))
	} else {
		reason = httpStatusText(r.Status)
		body = []byte(r.Body)
	}
	var header string
	if r.Action == "inject" {
		// Custom headers win over defaults; caller owns Content-Type.
		// Empty line in r.Headers is skipped defensively (trailing YAML
		// newline, empty entry, etc.).
		hdr := fmt.Sprintf("HTTP/1.1 %d %s\r\n", r.Status, reason)
		for _, h := range r.Headers {
			h = strings.TrimSpace(h)
			if h == "" || strings.Contains(h, "\n") || strings.Contains(h, "\r") {
				continue
			}
			hdr += h + "\r\n"
		}
		hdr += fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n", len(body))
		header = hdr
	} else {
		header = fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n",
			r.Status, reason, len(body))
		if r.Action == "redirect" {
			header += fmt.Sprintf("Location: %s\r\n", r.Location)
		}
		header += "\r\n"
	}
	_, _ = conn.Write([]byte(header))
	if len(body) > 0 {
		_, _ = conn.Write(body)
	}
}

// httpStatusText is a minimal status-code → reason-phrase map. Unknown codes
// get an empty phrase (still valid HTTP/1.1).
func httpStatusText(code int) string {
	switch code {
	case 200: return "OK"
	case 201: return "Created"
	case 204: return "No Content"
	case 301: return "Moved Permanently"
	case 302: return "Found"
	case 303: return "See Other"
	case 304: return "Not Modified"
	case 307: return "Temporary Redirect"
	case 308: return "Permanent Redirect"
	case 400: return "Bad Request"
	case 401: return "Unauthorized"
	case 403: return "Forbidden"
	case 404: return "Not Found"
	case 405: return "Method Not Allowed"
	case 408: return "Request Timeout"
	case 429: return "Too Many Requests"
	case 500: return "Internal Server Error"
	case 501: return "Not Implemented"
	case 502: return "Bad Gateway"
	case 503: return "Service Unavailable"
	case 504: return "Gateway Timeout"
	}
	return ""
}

// upstreamTLSConfig builds the client config for the re-encrypted upstream
// session. ServerName is the intercepted host (SNI); verification follows
// VerifyUpstream (default off — see field doc on MITMHandler). When
// ClientCert is set it is presented on the handshake for mTLS to origins
// that require client auth.
func (h *MITMHandler) upstreamTLSConfig(host string) *tls.Config {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if !h.VerifyUpstream {
		cfg.InsecureSkipVerify = true
	}
	if h.ClientCert != nil {
		cfg.Certificates = []tls.Certificate{*h.ClientCert}
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

// rewriteConn applies substring replacement rules (h.RewriteRules) on both
// reads and writes, so decrypted MITM traffic can be mutated in flight. It
// does NOT change Content-Length — the caller should handle that on the
// response side.
type rewriteConn struct {
	net.Conn
	rules []config.RewriteRule
	dir   string // "client" or "upstream"
}

func (c *rewriteConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		result := applyRules(b[:n], c.rules)
		if len(result) > cap(b) {
			n = copy(b, result)
		} else {
			n = copy(b, result)
		}
	}
	return n, err
}
func (c *rewriteConn) Write(b []byte) (int, error) {
	rewritten := applyRules(b, c.rules)
	return c.Conn.Write(rewritten)
}

// applyRules applies substring replacements in rule order. Single-chunk body
// assumption: large bodies split across multiple Read/Write calls may not
// match a replacement that spans the boundary. This matches what most
// intercepting proxies (mitmproxy inline scripts) do for simplicity.
func applyRules(data []byte, rules []config.RewriteRule) []byte {
	if len(rules) == 0 {
		return data
	}
	s := string(data)
	for _, r := range rules {
		if r.Match == "" {
			continue
		}
		s = strings.ReplaceAll(s, r.Match, r.Replace)
	}
	if s == string(data) {
		return data
	}
	return []byte(s)
}

// loggingConn appends JSON-lines of HTTP request lines and first response
// status lines to f. It tracks whether it has already logged the request line
// and response status line so each pair is recorded once per TCP stream.
type loggingConn struct {
	net.Conn
	f          *os.File
	dir        string
	requested  bool
	loggedResp bool
}

type mitmLogEntry struct {
	Timestamp string `json:"ts"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Proto     string `json:"proto,omitempty"`
	Status    string `json:"status,omitempty"`
	Direction string `json:"dir"`
	// Protocol is populated on request entries only. "ws" when the request
	// carries Upgrade: websocket (or WebSocket/WS, case-insensitive); "http"
	// otherwise. Lets an operator grep the log for WS upgrades without
	// re-parsing the request line — the log line itself no longer tells you
	// the app protocol on top of HTTP/1.1.
	Protocol string `json:"protocol,omitempty"`
}

func (c *loggingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.dir == "upstream" && !c.loggedResp {
		c.logFirstLine(b[:n], "status")
	}
	return n, err
}
func (c *loggingConn) Write(b []byte) (int, error) {
	if c.dir == "client" && !c.requested {
		c.logFirstLine(b, "request")
	}
	return c.Conn.Write(b)
}

func (c *loggingConn) logFirstLine(data []byte, kind string) {
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd < 0 {
		return
	}
	firstLine := string(data[:lineEnd])

	// Write raw bytes to LogFile before the buffered remainder is consumed.
	entry := mitmLogEntry{
		Timestamp: time.Now().Format("2006-01-02T15:04:05.000Z07:00"),
		Direction: c.dir,
	}
	if kind == "request" {
		parts := strings.Fields(firstLine)
		if len(parts) >= 2 {
			entry.Method = parts[0]
			entry.Path = parts[1]
			if len(parts) >= 3 {
				entry.Proto = parts[2]
			}
		}
	} else {
		parts := strings.Fields(firstLine)
		if len(parts) >= 2 {
			entry.Proto = parts[0]
			entry.Status = parts[1]
		}
	}

	jsonLine, _ := json.Marshal(entry)
	_, _ = c.f.Write(append(jsonLine, '\n'))

	if kind == "request" {
		c.requested = true
	} else {
		c.loggedResp = true
	}
}