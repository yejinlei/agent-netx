package listener

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Flow is a serializable snapshot of one HTTP request/response cycle passing
// through this proxy. It is the mitmproxy Flow analog: a discrete unit the
// request → response → error → done lifecycle runs on, and the unit every
// downstream consumer (log writer, web UI, script hook) receives.
//
// Scope of this first iteration:
//   - Captures header-level metadata only. Request/response bodies are NOT
//     captured to disk (privacy + disk cost; mitmproxy itself does not capture
//     bodies by default).
//   - One Flow per HTTP request line, not per TCP conn. HTTP keep-alive would
//     spawn one Flow per request on a single conn — but the current relay is
//     byte-forwarding, so we can only observe the first request/response of a
//     conn today. Follow-on work can wrap the relay in an HTTP parser to
//     produce per-request flows.
//   - Sinks receive the completed Flow exactly once, at the end of handleHTTP
//     or after InterceptConnect returns; hooks may run earlier.
type Flow struct {
	ID             string        `json:"id"`
	Timestamp      time.Time     `json:"timestamp"`
	Protocol       string        `json:"protocol"` // "http" | "https-mitm" | "socks5" | "tproxy"
	Target         string        `json:"target"`   // CONNECT target or absolute URL host:port
	Host           string        `json:"host"`
	Method         string        `json:"method,omitempty"`
	Path           string        `json:"path,omitempty"`
	FullURL        string        `json:"full_url,omitempty"`
	ClientAddr     string        `json:"client_addr"`
	ProxyName      string        `json:"proxy_name,omitempty"`
	ResponseStatus int           `json:"response_status,omitempty"`
	ResponseProto  string        `json:"response_proto,omitempty"`
	Error          string        `json:"error,omitempty"`
	Duration       time.Duration `json:"duration"`
	RequestBytes   int64         `json:"request_bytes"`
	ResponseBytes  int64         `json:"response_bytes"`
	Intercepted    bool          `json:"intercepted,omitempty"`
	RequestProto   string        `json:"request_proto,omitempty"`
	// RequestBody / ResponseBody are reserved for future body capture.
	// The current implementation captures body bytes as counters only
	// (RequestBytes / ResponseBytes) and does not retain the leading
	// payload bytes — populating these requires Content-Length /
	// chunked-aware parsing in relay, which is a larger rewrite.
	// Present as fields so consumers can plan against the eventual
	// schema without a breaking change. See MANUAL §3.17 for the
	// tradeoff and the deferred work.
	RequestBody   []byte `json:"request_body,omitempty"`
	ResponseBody  []byte `json:"response_body,omitempty"`
	// RequestHeaders / ResponseHeaders are line-by-line "Name: value"
	// strings in wire order (no trailing CRLF). Empty when we couldn't
	// read them or they weren't present.
	RequestHeaders  []string `json:"request_headers,omitempty"`
	ResponseHeaders []string `json:"response_headers,omitempty"`
}

// Cookie returns the value of the given request-header key (case-
// insensitive), or "" if absent. mitmproxy exposes `flow.request.cookies`
// as a parsed dict; we return the raw Cookie header value so callers
// that need parsed pairs split on ";" themselves.
func (f *Flow) Cookie(name string) string {
	if f == nil {
		return ""
	}
	target := strings.ToLower(name)
	for _, h := range f.RequestHeaders {
		if col := strings.IndexByte(h, ':'); col > 0 {
			k := strings.TrimSpace(h[:col])
			if strings.ToLower(k) == target {
				return strings.TrimSpace(h[col+1:])
			}
		}
	}
	return ""
}

// CookiePair is one Name=Value parsed out of the Cookie header. Values
// are not URL-decoded — callers use url.QueryUnescape if they need the
// decoded content. Domain/Path/Expires/etc. always empty: a client's
// Cookie header is a bare list of pairs; those attributes live only on
// the server's Set-Cookie response header.
type CookiePair struct {
	Name  string
	Value string
}

// Cookies parses the request Cookie header into a slice of pairs in wire
// order. Empty (nil) when no Cookie header is present. This is the closest
// analog to mitmproxy's `flow.request.cookies` dict — Go doesn't have a
// map with order guarantee, so callers get a slice.
func (f *Flow) Cookies() []CookiePair {
	raw := f.Cookie("Cookie")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	out := make([]CookiePair, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if eq := strings.IndexByte(p, '='); eq > 0 {
			out = append(out, CookiePair{
				Name:  strings.TrimSpace(p[:eq]),
				Value: strings.TrimSpace(p[eq+1:]),
			})
		} else {
			// Malformed (no "=") — keep as Name-only pair so callers
			// can decide whether to drop.
			out = append(out, CookiePair{Name: p})
		}
	}
	return out
}

// ResponseCookie returns the value of a given response-header key, or
// "" if absent. Case-insensitive. The returned string is the raw header
// value — for Set-Cookie attributes (Domain, Path, Expires, Secure,
// HttpOnly) callers can use net/http's CookieParser against the raw
// value if they need parsed form.
func (f *Flow) ResponseCookie(name string) string {
	if f == nil {
		return ""
	}
	target := strings.ToLower(name)
	for _, h := range f.ResponseHeaders {
		if col := strings.IndexByte(h, ':'); col > 0 {
			k := strings.TrimSpace(h[:col])
			if strings.ToLower(k) == target {
				return strings.TrimSpace(h[col+1:])
			}
		}
	}
	return ""
}

// FlowHook is called on a Flow at specific lifecycle points. Return false to
// abort the pipeline for this flow — the caller closes the connection and
// marks the flow with an error. Return true to continue. Hooks must not
// mutate the flow's identity fields (ID, Timestamp, ClientAddr, Target);
// anything else is fair game.
type FlowHook func(phase string, f *Flow) bool

type FlowHooks []FlowHook

// Emit runs every hook in order and returns false as soon as one refuses.
// `phase` is one of "request", "response", "error", "done". Nil entries
// in the slice are skipped (defensive: a caller that appends a nil
// hook shouldn't panic the whole pipeline).
func (hs FlowHooks) Emit(phase string, f *Flow) bool {
	for _, h := range hs {
		if h == nil {
			continue
		}
		if !h(phase, f) {
			return false
		}
	}
	return true
}

// FlowSink receives each completed Flow. Implementations should be
// goroutine-safe; the caller invokes Write concurrently for different flows
// but never concurrently for the same flow.
type FlowSink interface {
	Write(f *Flow)
}

// JSONFlowSink writes one JSON line per completed Flow to f. Concurrent
// writes are serialized with a mutex; a slow disk is not supposed to block
// request handling, so Write returns as soon as the buffer flush is
// scheduled. The file is not fsync'd on every line — a crash loses the tail.
type JSONFlowSink struct {
	f  *os.File
	mu sync.Mutex
}

func NewJSONFlowSink(path string) (*JSONFlowSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &JSONFlowSink{f: f}, nil
}

func (s *JSONFlowSink) Write(fl *Flow) {
	if s == nil || s.f == nil || fl == nil {
		return
	}
	line, err := json.Marshal(fl)
	if err != nil {
		return
	}
	line = append(line, '\n')
	s.mu.Lock()
	_, _ = s.f.Write(line)
	s.mu.Unlock()
}

// Close flushes and closes the underlying file.
func (s *JSONFlowSink) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// flowCounter is a process-wide sequence for Flow IDs. Hex-encoded
// (8 hex chars = 32 bits of entropy) — combined with the Timestamp field,
// IDs remain unique across restarts.
var flowCounter uint64

func nextFlowID() string {
	n := atomic.AddUint64(&flowCounter, 1)
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(n >> uint(56-i*8))
	}
	return hex.EncodeToString(b[:])
}

// NewFlow is the constructor callers use when building a Flow from scratch.
// It fills in ID, Timestamp, and defaults Protocol to "http". Callers
// override Protocol and other fields as they learn more about the request.
func NewFlow(protocol, target, clientAddr string) *Flow {
	return &Flow{
		ID:         nextFlowID(),
		Timestamp:  time.Now(),
		Protocol:   protocol,
		Target:     target,
		ClientAddr: clientAddr,
	}
}

// MarkError sets the flow's Error field if one is not already set and
// populates Duration if it was zero (so we always report a duration for
// failed flows, measured from Timestamp to now).
func (f *Flow) MarkError(err error) {
	if f == nil || err == nil {
		return
	}
	if f.Error == "" {
		f.Error = err.Error()
	}
	if f.Duration == 0 {
		f.Duration = time.Since(f.Timestamp)
	}
}

// Finalize stamps the duration if not already set. Callers invoke this
// before pushing to a Sink so the sink always sees a populated duration.
func (f *Flow) Finalize() {
	if f == nil {
		return
	}
	if f.Duration == 0 {
		f.Duration = time.Since(f.Timestamp)
	}
}

// HashForID returns a stable 12-hex-char digest of the given key material.
// Exported for callers that want deterministic IDs (e.g. tests); the default
// nextFlowID is a counter for throughput.
func HashForID(parts ...string) string {
	h := sha1.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte("|"))
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// countingConn wraps a net.Conn and tallies bytes written and read into the
// given int64 pointers (atomic). It exists so relay() can stamp RequestBytes
// and ResponseBytes onto a Flow after the connection drains.
//
// direction="write" means local→peer (for the client-side conn this is
// proxy→client = ResponseBytes; for the upstream conn it is proxy→upstream
// = RequestBytes). The mapping is done by the caller; this wrapper is
// direction-agnostic.
type countingConn struct {
	net.Conn
	wrote *int64
	readN *int64
}

func newCountingConn(c net.Conn, wrote, readN *int64) *countingConn {
	return &countingConn{Conn: c, wrote: wrote, readN: readN}
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && c.wrote != nil {
		atomic.AddInt64(c.wrote, int64(n))
	}
	return n, err
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.readN != nil {
		atomic.AddInt64(c.readN, int64(n))
	}
	return n, err
}

// FlowCarrier is implemented by connection wrappers that carry a Flow.
// relay() can type-assert against this to update byte counters on the
// Flow, then invoke emitDone at the end. Not required for every conn.
type FlowCarrier interface {
	Flow() *Flow
}

// clientWithFlow is the concrete FlowCarrier used by handleHTTP. It exists
// to avoid adding a Flow field to every net.Conn wrapper already in use
// (statsConn, loggingConn, winTProxyConn). All the net.Conn methods are
// pass-through.
type clientWithFlow struct {
	conn net.Conn
	flow *Flow
}

func (c *clientWithFlow) Read(b []byte) (int, error)       { return c.conn.Read(b) }
func (c *clientWithFlow) Write(b []byte) (int, error)      { return c.conn.Write(b) }
func (c *clientWithFlow) Close() error                     { return c.conn.Close() }
func (c *clientWithFlow) LocalAddr() net.Addr              { return c.conn.LocalAddr() }
func (c *clientWithFlow) RemoteAddr() net.Addr             { return c.conn.RemoteAddr() }
func (c *clientWithFlow) SetDeadline(t time.Time) error    { return c.conn.SetDeadline(t) }
func (c *clientWithFlow) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *clientWithFlow) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *clientWithFlow) Flow() *Flow                      { return c.flow }

// extractFlowCarrier returns the FlowCarrier from either conn, or nil. If
// both carry (rare), the client-side one wins because its Flow is the one
// we created in handleHTTP.
func extractFlowCarrier(client, remote net.Conn) FlowCarrier {
	if c, ok := client.(FlowCarrier); ok {
		return c
	}
	if c, ok := remote.(FlowCarrier); ok {
		return c
	}
	return nil
}
