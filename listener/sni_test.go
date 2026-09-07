package listener

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

// bufConn is a minimal net.Conn backed by two byte buffers (one for read, one
// for write) plus a manual Close. It's the cheapest way to feed a known byte
// stream into peekClientHello without standing up a real listener.
type bufConn struct {
	rc     *bytes.Reader
	wc     *bytes.Buffer
	closed bool
}

func (c *bufConn) Read(b []byte) (int, error) {
	if c.closed {
		return 0, io.EOF
	}
	return c.rc.Read(b)
}
func (c *bufConn) Write(b []byte) (int, error) { return c.wc.Write(b) }
func (c *bufConn) Close() error                 { c.closed = true; return nil }
func (c *bufConn) LocalAddr() net.Addr          { return &net.TCPAddr{} }
func (c *bufConn) RemoteAddr() net.Addr         { return &net.TCPAddr{} }
func (c *bufConn) SetDeadline(t time.Time) error { return nil }
func (c *bufConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		return nil
	}
	c.rc = bytes.NewReader(nil)
	return nil
}
func (c *bufConn) SetWriteDeadline(t time.Time) error { return nil }

// craftClientHello builds a minimal TLS ClientHello record with the given SNI.
// sniLen == 0 produces a ClientHello with an empty extensions block (no SNI
// extension), which is the shape some older clients still send.
//
// Wire layout (RFC 5246 §7.4.1.2 + RFC 6066 §3):
//
//	record: type(1)=0x16 | ver(2) | recLen(2)
//	handshake: type(1)=0x01 | hsLen(3)
//	client_hello body:
//	  client_version(2) | random(32) | sid_len(1) | sid(sid_len)
//	  cipher_suites_len(2) | cipher_suites(cs_len)
//	  compression_len(1) | compression(comp_len)
//	  extensions_len(2) | extensions(ext_len)
//	extension (SNI):
//	  etype(2) | elen(2) | SNL_len(2) | NameType(1) | hl(2) | host(hl)
func craftClientHello(host string, sniLen int) []byte {
	body := make([]byte, 0, 100+len(host))
	body = append(body, 0x03, 0x03)                    // TLS 1.2
	body = append(body, make([]byte, 32)...)           // random
	body = append(body, 0x00)                          // sid_len
	body = append(body, 0x00, 0x02)                    // cipher_suites_len
	body = append(body, 0x00, 0x15)                    // cipher_suite 0x0015
	body = append(body, 0x01)                          // compression_len
	body = append(body, 0x00)                          // compression_method
	if sniLen == 0 {
		body = append(body, 0x00, 0x00) // extensions_len = 0
	} else {
		snl := sniLen + 3 // NameType(1) + hl(2) + host(hl)
		// elen (2) = snl + 2 (the SNL_len field itself, which is part of the
		// extension's elen-counted content).
		elen := snl + 2
		ext := make([]byte, 0, 9+sniLen)
		ext = append(ext, 0x00, 0x00)               // etype = server_name
		ext = append(ext, byte(elen>>8), byte(elen)) // elen
		ext = append(ext, byte(snl>>8), byte(snl))   // SNL_len
		ext = append(ext, 0x00)                      // NameType = host_name
		ext = append(ext, 0x00, byte(sniLen))        // hl (2)
		ext = append(ext, []byte(host)...)           // host
		body = append(body, byte(len(ext)>>8), byte(len(ext))) // extensions_len (2)
		body = append(body, ext...)
	}

	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01)                              // HandshakeType = ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x01)                // record type + TLS 1.0
	rec = append(rec, byte(len(hs)>>8), byte(len(hs))) // record_len (2)
	rec = append(rec, hs...)
	return rec
}

func TestParseSNIRoundTrip(t *testing.T) {
	for _, host := range []string{
		"example.com",
		"a",
		"sub.domain.example.com",
		"EXAMPLE.COM",
		"my-cdn.example.org",
		"0.0.0.0",
	} {
		if got := parseSNI(craftClientHello(host, len(host))); got != host {
			t.Errorf("parseSNI round-trip %q = %q", host, got)
		}
	}
	// Host just under the boundary — the parser caps hn at 255.
	long := "x" + string(bytes.Repeat([]byte("a"), 254))
	if got := parseSNI(craftClientHello(long, len(long))); got != long {
		t.Errorf("parseSNI 255-char host = %q (len %d)", got, len(got))
	}
	// Non-alpha is not rejected (IPv4 literals, DNS wildcards, and
	// DNS-underscore labels are all legitimate SNI values).
	{
		host := "a-1.b_2"
		if got := parseSNI(craftClientHello(host, len(host))); got != host {
			t.Errorf("parseSNI non-alpha = %q (len %d)", got, len(got))
		}
	}
}

func TestParseSNIMalformed(t *testing.T) {
	cases := []struct {
		name string
		blob []byte
	}{
		{"empty", nil},
		{"one byte", []byte{0x16}},
		{"four bytes", []byte{0x16, 0x03, 0x01, 0x00}},
		{"bad record type", []byte{0x17, 0x03, 0x01, 0x00, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"oversize record", []byte{0x16, 0x03, 0x01, 0xFF, 0xFF, 0, 0, 0, 0, 0}},
		{"truncated handshake", []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x02, 0x03}},
		{"empty handshake", craftClientHello("", 0)},
		{"no SNI extension", craftClientHello("", 0)},
		{"sni_len 0", craftClientHello("example.com", 0)},
		{"sni_len 256", craftClientHello("x", 256)},
	}
	for _, c := range cases {
		if got := parseSNI(c.blob); got != "" {
			t.Errorf("%s: parseSNI returned %q, want empty", c.name, got)
		}
	}
}

func TestWrapWithPrefillRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		prefill []byte
		under   string
		want    string
	}{
		{"prefill-then-underlying", []byte("head-"), "tail", "head-tail"},
		{"prefill-only", []byte("head"), "", "head"},
		{"underlying-only", nil, "tail", "tail"},
		{"empty-empty", nil, "", ""},
		{"multi-read-prefill", []byte{1, 2, 3, 4}, "56", "\x01\x02\x03\x0456"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			under := &bufConn{rc: bytes.NewReader([]byte(tt.under))}
			got := wrapWithPrefill(under, tt.prefill)
			out, err := io.ReadAll(got)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(out) != tt.want {
				t.Errorf("wrapWithPrefill read = %q, want %q", out, tt.want)
			}
		})
	}
}

func TestWrapWithPrefillIdentity(t *testing.T) {
	// Empty prefill returns the underlying conn unchanged (identity shortcut).
	under := &bufConn{rc: bytes.NewReader([]byte("abc"))}
	if got := wrapWithPrefill(under, nil); !reflect.DeepEqual(got, net.Conn(under)) {
		t.Errorf("empty prefill: got %v (type %T), want identity with %T", got, got, under)
	}
	if got := wrapWithPrefill(under, []byte("xyz")); got == nil || got == net.Conn(under) {
		t.Errorf("non-empty prefill: got %v (type %T), want a wrapper distinct from %T", got, got, under)
	}
}
