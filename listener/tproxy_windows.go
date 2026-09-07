//go:build windows

package listener

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/one-api/godivert"
)

// Windows TProxy via WinDivert, using the pure-Go user-mode library
// one-api/godivert (it embeds WinDivert64.sys and auto-installs the kernel
// driver on first open — Administrator privileges required).
//
// Linux TProxy gives us three primitives Windows does not have: the iptables
// TPROXY target (deliver third-party packets to a bound socket), IP_TRANSPARENT
// (accept connect requests aimed at foreign addresses), and IP_ORIGDSTADDR
// (recover the original destination on accept). WinDivert replaces all three
// with a user-mode packet loop:
//
//  1. One divert handle watches FORWARD-layer outbound IPv4 TCP traffic —
//     i.e. packets transiting THIS machine toward another host, which is what
//     LAN clients send when this box is their default gateway. Loopback and
//     locally-generated traffic are excluded by the layer itself, so the
//     agent's own upstream dials are never touched.
//  2. On each new flow (clientIP, clientPort) -> (origIP, origPort) is recorded
//     in conntrack, then EVERY packet of that flow has BOTH endpoints rewritten
//     to 127.0.0.1: the client becomes 127.0.0.1:<fake ephemeral port>, the
//     destination becomes 127.0.0.1:<tproxy port>. The packet enters the local
//     stack, our plain net.Listener accepts it as an ordinary loopback
//     connection, and the reply path (127.0.0.1 <-> 127.0.0.1) needs no
//     translation at all — full NAT both ways is what keeps the conversation
//     coherent without touching the real client's stack expectations.
//  3. Accept looks the fake 127.0.0.1:<fake port> peer up in conntrack and
//     wraps the conn so RemoteAddr() reports the ORIGINAL destination and
//     ClientAddr() the REAL client — exactly the contract tproxyConn /
//     tproxy_linux.go exposes, so serveTProxy / handleTProxy and the MITM
//     IP-allowlist path work unchanged.
//
// Egress note: the agent's OWN connections to 127.0.0.1:<tproxy port> are
// never diverted (loopback is not forwarded), but they would collide with
// redirected client conns inside the listener, so they must not use the
// tproxy port as their destination.
//
// IPv6 scope: the TCP/UDP divert filters include both families, but only v4
// is NAT-rewritten into the 127.0.0.1 listener. v6 packets are recorded as
// capture-only flows — the same treatment as DNS UDP — because NAT-ing a v6
// SYN to v4 loopback would produce a broken half-connection (the SYN-ACK
// would come back on ::1, which the client never asked for). Extending
// transparent v6 interception to a real ::1 listener is a follow-on task
// that would need a second net.Listener bound on [::1] plus a v6-aware
// lookupFake branch. The flow key and conntrack table are v6-capable so
// that upgrade can be a mechanical follow-up.
//
// godivert does not expose IPv6 headers (PacketHeaders.IP6 was not added in
// the vendored version, and godivert.Address carries no v6 address field).
// We parse v6 packets from raw bytes via parseV6Flow, walking any extension
// headers needed to find the L4 endpoint ports.
//
// Scope of this prototype: one divert handle per process per protocol
// (tproxyListen may be called once); mark/table (Linux fwmark routing
// knobs) are accepted and ignored — installTProxyRouting is a documented
// no-op here, matching tproxy_other.go's convention for non-Linux
// platforms.
//
// 安全红线 note: this file performs NO interception decisions. It only makes
// the original destination visible to handleTProxy, which applies
// ShouldInterceptIP/SkipHost exactly as on Linux. Empty allowlist still means
// never decrypt; enable=false still means this listener never starts.

const (
	winPacketMax = 40 + 0xFFFF // godivert.MtuMax-sized scratch buffers
	tproxyIdle   = 10 * time.Minute
	fakeSrcBase  = 40000 // fake 127.0.0.1 source port allocation start
	fakeSrcSpan  = 20000 // ...and pool size (40000..59999 avoids typical ephemerals)
)

// winFilterTCP captures forwarded outbound IPv4+IPv6 TCP toward the web
// ports. LayerNetworkForward only sees transit traffic: locally-generated
// packets (agent egress) take the OUTBOUND path instead and never match, and
// the "!impostor" term stops our own reinjected packets from looping back in.
const winFilterTCP = "forward and outbound and (ip or ip6) and !impostor and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)"

// winFilterUDP is the UDP sibling of winFilterTCP, added for transparent DNS
// (port 53) relay via a second, independent divert handle. UDP has no
// handshake, so rewriteUDP keys flows on any packet rather than just SYN.
const winFilterUDP = "forward and outbound and (ip or ip6) and !impostor and udp and udp.DstPort == 53"

// loopbackIPv4 is the network-order uint32 for 127.0.0.1 — the address every
// redirected v4 endpoint is normalized to.
const loopbackIPv4 uint32 = 0x0100007F

type winFlow struct {
	origDstIP [16]byte // network-order IP, v4 zero-extended at offset 12
	origDstP  uint16   // ...and port (host order)
	clientIP  [16]byte // network-order real client IP
	clientP   uint16   // real client ephemeral port (host order)
	proto     byte     // 4 or 6 — needed so lookupFake can distinguish families
	fakeP     uint16   // fake 127.0.0.1:<fakeP> assigned to this flow
	last      time.Time
}

type winTProxyState struct {
	mu       sync.Mutex
	byReal   map[string]*winFlow // key: "v<N>|<16-byte IP>|<port-byte>" -> flow
	byFake   map[uint16]*winFlow // key: fake port -> flow
	nextFake uint16
	ln       net.Listener
	closeCh  chan struct{}
	wg       sync.WaitGroup
	once     sync.Once
}

func tproxyListen(addr string) (net.Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tproxy windows resolve %s: %w", addr, err)
	}
	ip4 := tcpAddr.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("tproxy windows bind %s: listener binds 127.0.0.1; use 0.0.0.0:%d or 127.0.0.1:%d", addr, tcpAddr.Port, tcpAddr.Port)
	}
	// Redirected packets always land on 127.0.0.1:<port>, so a wildcard or
	// loopback bind is equivalent here; any other explicit IP would silently
	// never receive the traffic — fail loudly instead.
	if !ip4.IsUnspecified() && !ip4.IsLoopback() {
		return nil, fmt.Errorf("tproxy windows bind %s: WinDivert redirects land on loopback; use 0.0.0.0:%d or 127.0.0.1:%d", addr, tcpAddr.Port, tcpAddr.Port)
	}

	// Open the divert handle BEFORE listening: any failure (no admin token,
	// driver install rejected) must leave no half-started listener behind.
	div, err := godivert.New(winFilterTCP, godivert.LayerNetworkForward, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("tproxy windows windivert open (administrator privileges required): %w", err)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(tcpAddr.Port)))
	if err != nil {
		div.Close()
		return nil, fmt.Errorf("tproxy windows listen 127.0.0.1:%d: %w", tcpAddr.Port, err)
	}

	st := &winTProxyState{
		byReal:   make(map[string]*winFlow),
		byFake:   make(map[uint16]*winFlow),
		nextFake: fakeSrcBase,
		ln:       ln,
		closeCh:  make(chan struct{}),
	}

	st.wg.Go(func() { winPump(div, st) })
	st.wg.Go(func() { st.gcLoop() })
	// The UDP divert is a second, independent handle: WinDivert treats
	// each New() as its own capture queue. Isolating it here means a
	// failure in either protocol only disables that protocol — the TCP
	// listener still works if UDP capture fails.
	if divU, udpErr := godivert.New(winFilterUDP, godivert.LayerNetworkForward, 0, 0); udpErr != nil {
		log.Printf("tproxy windows windivert udp open: %v (udp tproxy unavailable)", udpErr)
	} else {
		st.wg.Go(func() { winPumpUDP(divU, st) })
	}

	return &winTProxyListener{st: st}, nil
}

// gcLoop periodically evicts idle flows. UDP has no explicit teardown
// (no FIN/RST), so periodic reaping is the only way to keep the fake-port
// pool bounded — otherwise a chatty DNS resolver eventually exhausts it.
// TCP also benefits: it has a shorter natural life and the same tproxyIdle
// bound, so this supersedes the on-exhaustion gcLocked call in allocFakeLocked.
func (st *winTProxyState) gcLoop() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-st.closeCh:
			return
		case now := <-t.C:
			st.mu.Lock()
			st.gcLocked(now)
			st.mu.Unlock()
		}
	}
}

// winPump runs the divert capture/rewrite/reinject loop. One OS thread is
// locked because the overlapped Recv blocks in the driver for long stretches.
func winPump(div *godivert.Divert, st *winTProxyState) {
	defer runtime.UnlockOSThread()
	runtime.LockOSThread()
	defer div.Close()

	buf := make([]byte, winPacketMax)
	var addr godivert.Address
	for {
		n, err := div.Recv(buf, &addr)
		if err != nil {
			select {
			case <-st.closeCh:
				return // Close() broke the overlapped Recv: clean exit
			default:
			}
			// Transient driver error: keep going rather than kill interception
			// silently, but back off so a dead handle can't spin the CPU.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		pkt := buf[:n]

		h := godivert.ParsePacket(pkt)
		if h == nil || h.TCP == nil {
			_, _ = div.Send(pkt, &addr)
			continue
		}
		// godivert only fills h.IP for IPv4. A v6 TCP packet shows up as
		// h.IP==nil but h.TCP!=nil (the L4 header is positioned by walking
		// the v6 extension-header chain inside godivert's parser). Record
		// it capture-only; we don't rewrite v6 -> v4 loopback.
		if h.IP == nil {
			if srcIP, dstIP, srcP, dstP, ok := parseV6Flow(pkt); ok {
				st.captureOnlyV6(6, srcIP, dstIP, srcP, dstP)
			}
			_, _ = div.Send(pkt, &addr)
			continue
		}

		st.rewrite(pkt, h, div, &addr)
	}
}

// captureOnlyV6 records a v6 TCP flow in conntrack but does not rewrite the
// packet. See the file header for why: NAT-ing v6 -> v4 loopback breaks the
// handshake (SYN-ACK would return on ::1, which the client never dialed).
// The record is available for audit tooling and for a future v6-aware
// listener.
func (st *winTProxyState) captureOnlyV6(proto byte, clientIP, origDstIP [16]byte, clientP, origDstP uint16) {
	key := flowKey(proto, clientIP, clientP)
	st.mu.Lock()
	defer st.mu.Unlock()
	f, ok := st.byReal[key]
	if !ok {
		f = &winFlow{
			origDstIP: origDstIP,
			origDstP:  origDstP,
			clientIP:  clientIP,
			clientP:   clientP,
			proto:     proto,
		}
		if fp, ok := st.allocFakeLocked(); ok {
			f.fakeP = fp
			st.byReal[key] = f
			st.byFake[fp] = f
		} else {
			st.gcLocked(time.Now())
		}
	}
	if f != nil {
		f.last = time.Now()
	}
}

// rewrite handles one forwarded client->origin v4 packet. Tracked flows get
// both endpoints normalized to loopback. An untracked SYN opens a flow
// (recorded, then rewritten); anything else untracked passes through
// untouched — only port 80/443 SYNs create flows, so the table stays
// bounded to web traffic, and claiming mid-stream packets would yield
// broken half-connections.
func (st *winTProxyState) rewrite(pkt []byte, h *godivert.PacketHeaders, div *godivert.Divert, addr *godivert.Address) {
	clientIP := v4To16(h.IP.SrcAddr)
	origDstIP := v4To16(h.IP.DstAddr)
	key := flowKey(4, clientIP, be16(h.TCP.SrcPort))

	st.mu.Lock()
	f, known := st.byReal[key]
	if !known {
		if !h.TCP.Syn() || h.TCP.Ack() {
			st.mu.Unlock()
			_, _ = div.Send(pkt, addr) // let it route normally
			return
		}
		f = &winFlow{
			origDstIP: origDstIP,
			origDstP:  be16(h.TCP.DstPort),
			clientIP:  clientIP,
			clientP:   be16(h.TCP.SrcPort),
			proto:     4,
		}
		fp, ok := st.allocFakeLocked()
		if !ok {
			// Fake-port pool exhausted: drop (client times out) rather than
			// risk aliasing two flows onto one loopback tuple.
			st.gcLocked(time.Now())
			st.mu.Unlock()
			return
		}
		f.fakeP = fp
		st.byReal[key] = f
		st.byFake[fp] = f
	}
	f.last = time.Now()
	fakeSrc := f.fakeP
	st.mu.Unlock()

	// Full NAT to loopback. Idempotent: retransmitted SYNs after the first
	// rewrite already carry the loopback tuple and skip the checksum work.
	if h.IP.SrcAddr == loopbackIPv4 && h.IP.DstAddr == loopbackIPv4 &&
		be16(h.TCP.DstPort) == uint16(st.ln.Addr().(*net.TCPAddr).Port) {
		_, _ = div.Send(pkt, addr)
		return
	}
	h.IP.SrcAddr = loopbackIPv4
	h.IP.DstAddr = loopbackIPv4
	h.TCP.SrcPort = h16(fakeSrc)
	h.TCP.DstPort = h16(uint16(st.ln.Addr().(*net.TCPAddr).Port))
	godivert.CalcChecksums(pkt, 0)
	// Deliver into the local stack: clearing the outbound flag makes the
	// packet arrive at listening sockets (the dns_sinkhole idiom).
	addr.SetOutbound(false)
	_, _ = div.Send(pkt, addr)
}

// allocFakeLocked hands out the next fake loopback source port. Caller holds
// st.mu. Returns false when the pool is exhausted.
func (st *winTProxyState) allocFakeLocked() (uint16, bool) {
	for range fakeSrcSpan {
		p := st.nextFake
		st.nextFake++
		if st.nextFake >= uint16(fakeSrcBase+fakeSrcSpan) {
			st.nextFake = fakeSrcBase
		}
		if _, taken := st.byFake[p]; !taken {
			return p, true
		}
	}
	return 0, false
}

// lookupFake returns the flow that owns fakeP, or (0, nil, nil, false).
// proto == 4 means the byte slices are v4 in bytes 12..15; proto == 6 means
// they are raw v6. Callers use proto to pick the unpack form.
func (st *winTProxyState) lookupFake(fakeP uint16) (proto byte, clientIP, origDstIP *[16]byte, clientP, origDstP uint16, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	f, ok := st.byFake[fakeP]
	if !ok {
		return 0, nil, nil, 0, 0, false
	}
	return f.proto, &f.clientIP, &f.origDstIP, f.clientP, f.origDstP, true
}

// ---- UDP packet handling -------------------------------------------------
//
// WinDivert supports UDP with exactly the same rewrite recipe as TCP: no
// handshake exists, so we key flows on any packet (not just SYN) rather than
// gating on Syn/Ack. The flow key is identical (clientIP+clientPort -> flow)
// so TCP and UDP shares the same fake-port pool without collisions.

// winPumpUDP is the UDP sibling of winPump. One OS thread per handle is
// required because the overlapped Recv blocks in the driver.
func winPumpUDP(div *godivert.Divert, st *winTProxyState) {
	defer runtime.UnlockOSThread()
	runtime.LockOSThread()
	defer div.Close()

	buf := make([]byte, winPacketMax)
	var addr godivert.Address
	for {
		n, err := div.Recv(buf, &addr)
		if err != nil {
			select {
			case <-st.closeCh:
				return
			default:
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		pkt := buf[:n]

		h := godivert.ParsePacket(pkt)
		if h == nil || h.UDP == nil {
			_, _ = div.Send(pkt, &addr)
			continue
		}
		st.rewriteUDP(pkt, h, div, &addr)
	}
}

// rewriteUDP handles one forwarded client->DNS packet. Capture-only: the
// flow is recorded in conntrack (so Accept4 could later serve it up for
// audit tooling) but the packet itself is re-sent UNCHANGED, so DNS keeps
// working. This is the safe minimal form of "UDP 透明代理" — observability
// without a routing hole. If we ever add a real UDP proxy backend (e.g.
// a DoH/DoT egress path) the rewrite branch becomes the passthrough branch
// and vice versa.
func (st *winTProxyState) rewriteUDP(pkt []byte, h *godivert.PacketHeaders, div *godivert.Divert, addr *godivert.Address) {
	var proto byte
	var clientIP, origDstIP [16]byte
	var clientP, origDstP uint16

	if h.IP != nil {
		proto = 4
		clientIP = v4To16(h.IP.SrcAddr)
		origDstIP = v4To16(h.IP.DstAddr)
		clientP = be16(h.UDP.SrcPort)
		origDstP = be16(h.UDP.DstPort)
	} else if src, dst, sp, dp, ok := parseV6Flow(pkt); ok {
		proto = 6
		clientIP, origDstIP, clientP, origDstP = src, dst, sp, dp
	} else {
		_, _ = div.Send(pkt, addr)
		return
	}

	key := flowKey(proto, clientIP, clientP)

	st.mu.Lock()
	if _, known := st.byReal[key]; !known {
		f := &winFlow{
			origDstIP: origDstIP,
			origDstP:  origDstP,
			clientIP:  clientIP,
			clientP:   clientP,
			proto:     proto,
		}
		fp, ok := st.allocFakeLocked()
		if ok {
			f.fakeP = fp
			st.byReal[key] = f
			st.byFake[fp] = f
		} else {
			st.gcLocked(time.Now())
		}
	}
	if f, ok := st.byReal[key]; ok {
		f.last = time.Now()
	}
	st.mu.Unlock()

	// Capture-only: emit unchanged. If pool was exhausted and the flow was
	// never tracked, we still re-emit — the whole point is that DNS works.
	_, _ = div.Send(pkt, addr)
}

// gcLocked evicts idle flows. Caller holds st.mu.
func (st *winTProxyState) gcLocked(now time.Time) {
	for k, f := range st.byReal {
		if now.Sub(f.last) > tproxyIdle {
			delete(st.byReal, k)
			delete(st.byFake, f.fakeP)
		}
	}
}

// ---- net.Listener plumbing ---------------------------------------------

type winTProxyListener struct{ st *winTProxyState }

func (l *winTProxyListener) Accept() (net.Conn, error) {
	for {
		c, err := l.st.ln.Accept()
		if err != nil {
			return nil, err
		}
		tc, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok || tc.IP.To4() == nil || !tc.IP.IsLoopback() || tc.Port < fakeSrcBase || tc.Port >= fakeSrcBase+fakeSrcSpan {
			// Not a redirected client (probe scan, stale entry, or a local
			// process dialing the fake range): reject, never guess.
			c.Close()
			continue
		}
		proto, clientIP, origDstIP, clientP, origDstP, known := l.st.lookupFake(uint16(tc.Port))
		if !known || proto != 4 || clientIP == nil || origDstIP == nil {
			// Fail closed exactly like tproxy_linux.go: without the original
			// destination we cannot honor the transparent contract, and
			// guessing would let a connection escape interception decisions.
			// Also enforces that we never serve a v6 flow through this v4
			// listener (capture-only v6 flows have no listener).
			c.Close()
			continue
		}
		client := &net.TCPAddr{IP: net.IPv4((*clientIP)[12], (*clientIP)[13], (*clientIP)[14], (*clientIP)[15]), Port: int(clientP)}
		orig := &net.TCPAddr{IP: net.IPv4((*origDstIP)[12], (*origDstIP)[13], (*origDstIP)[14], (*origDstIP)[15]), Port: int(origDstP)}
		return &winTProxyConn{Conn: c, orig: orig, client: client}, nil
	}
}

func (l *winTProxyListener) Close() error {
	l.st.once.Do(func() {
		close(l.st.closeCh)
		_ = l.st.ln.Close()
	})
	l.st.wg.Wait()
	return nil
}

func (l *winTProxyListener) Addr() net.Addr { return l.st.ln.Addr() }

// winTProxyConn mirrors tproxyConn (tproxy_linux.go): RemoteAddr is the
// ORIGINAL destination (what handleTProxy targets), ClientAddr is the real
// client (what clientAddrStr logs / uses for routing decisions).
type winTProxyConn struct {
	net.Conn
	orig   *net.TCPAddr
	client *net.TCPAddr
}

func (c *winTProxyConn) RemoteAddr() net.Addr { return c.orig }
func (c *winTProxyConn) ClientAddr() net.Addr { return c.client }

// ---- routing hooks (no-ops on Windows) ---------------------------------

// installTProxyRouting has nothing to do here: there is no fwmark policy
// routing to set up — WinDivert itself is the redirection mechanism. Kept as
// a symmetric no-op with the Linux signature so cmd wiring stays identical.
func installTProxyRouting(_ int, _ int) error { return nil }

// teardownTProxyRouting undoes installTProxyRouting: nothing to undo.
func teardownTProxyRouting(_ int, _ int) {}

// ---- byte-order / addressing helpers -----------------------------------
//
// godivert header fields are raw network-byte-order memory images. These
// convert between that image and host-order numbers WITHOUT importing
// encoding/binary, so the endian swap is explicit in one place.

// be16 converts a wire-order uint16 field to host order.
func be16(v uint16) uint16 { return uint16(v>>8 | v<<8) }

// h16 converts a host-order uint16 to its wire-order memory image.
func h16(v uint16) uint16 { return be16(v) } // symmetric byte swap

// v4To16 stores a network-order IPv4 word into a [16]byte slot, zero-padded
// in bytes 0..11 with the 4 bytes at 12..15. It only needs to be a stable
// identifier here, never interpreted numerically. Accept() reads the v4
// back from bytes 12..15.
func v4To16(w uint32) [16]byte {
	var out [16]byte
	out[12] = byte(w >> 24)
	out[13] = byte(w >> 16)
	out[14] = byte(w >> 8)
	out[15] = byte(w)
	return out
}

// flowKey packs (proto, network-order IP as [16]byte, host-order port) into
// a stable string map key. Proto is a prefix so the same client IP+port on
// two families cannot collide.
func flowKey(proto byte, ip [16]byte, port uint16) string {
	var b [19]byte
	b[0] = byte('v')
	b[1] = proto
	copy(b[2:18], ip[:])
	b[18] = byte(port)
	return string(b[:])
}

// parseV6Flow returns the L4 endpoints of an IPv6 packet, walking any
// extension headers. Returns (srcIP, dstIP, srcPort, dstPort, ok).
//
// The IPv6 header is 40 bytes: 4B version+TC+flow, 1B next-header, 1B
// hop-limit, 16B src, 16B dst. When next-header is 6 (TCP) or 17 (UDP) we
// return immediately; otherwise we skip the extension header. Extension
// headers use two different length conventions:
//   - Type 0 (HbH), 44 (Routing), 51 (Fragment), 135 (Destination):
//     the "Length" field is (size - 8) in 8-byte units
//   - Type 43 (ESP), 50 (AH): the "Length" field is (size - 2) in bytes
//
// We bail out after 8 extension hops to avoid malformed packets looping us.
func parseV6Flow(pkt []byte) (srcIP, dstIP [16]byte, srcPort, dstPort uint16, ok bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return
	}
	copy(srcIP[:], pkt[8:24])
	copy(dstIP[:], pkt[24:40])

	off := 40
	nh := pkt[6]
	for hops := 0; nh != 6 && nh != 17; hops++ {
		if hops >= 8 || off+2 > len(pkt) {
			return
		}
		var size int
		switch nh {
		case 0, 43, 44, 51, 135:
			size = int(pkt[off+1])*8 + 8
		case 50:
			size = int(pkt[off+1]) + 2
		default:
			return
		}
		off += size
		if off >= len(pkt) {
			return
		}
		nh = pkt[off]
	}
	if off+4 > len(pkt) {
		return
	}
	srcPort = uint16(pkt[off])<<8 | uint16(pkt[off+1])
	dstPort = uint16(pkt[off+2])<<8 | uint16(pkt[off+3])
	ok = true
	return
}
