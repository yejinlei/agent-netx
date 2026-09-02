//go:build windows

package listener

import (
	"fmt"
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
// Scope of this prototype: IPv4 only (v6 flows pass through un-intercepted);
// one divert handle per process (tproxyListen may be called once); mark/table
// (Linux fwmark routing knobs) are accepted and ignored — installTProxyRouting
// is a documented no-op here, matching tproxy_other.go's convention for
// non-Linux platforms.
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

// winFilter captures forwarded outbound IPv4 TCP toward the web ports.
// LayerNetworkForward only sees transit traffic: locally-generated packets
// (agent egress) take the OUTBOUND path instead and never match, and the
// "!impostor" term stops our own reinjected packets from looping back in.
const winFilter = "forward and outbound and ip and !impostor and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)"

// loopbackIPv4 is the network-order uint32 for 127.0.0.1 — the address every
// redirected endpoint is normalized to.
const loopbackIPv4 uint32 = 0x0100007F

type winFlow struct {
	origDstIP uint32 // network-order IP the client actually dialed
	origDstP  uint16 // ...and port (host order)
	clientIP  uint32 // network-order real client IP
	clientP   uint16 // real client ephemeral port (host order)
	fakeP     uint16 // fake 127.0.0.1:<fakeP> assigned to this flow
	last      time.Time
}

type winTProxyState struct {
	mu       sync.Mutex
	byReal   map[uint64]*winFlow // key: clientIP+clientPort -> flow
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
		return nil, fmt.Errorf("tproxy windows bind %s: IPv4 only in this prototype", addr)
	}
	// Redirected packets always land on 127.0.0.1:<port>, so a wildcard or
	// loopback bind is equivalent here; any other explicit IP would silently
	// never receive the traffic — fail loudly instead.
	if !ip4.IsUnspecified() && !ip4.IsLoopback() {
		return nil, fmt.Errorf("tproxy windows bind %s: WinDivert redirects land on loopback; use 0.0.0.0:%d or 127.0.0.1:%d", addr, tcpAddr.Port, tcpAddr.Port)
	}

	// Open the divert handle BEFORE listening: any failure (no admin token,
	// driver install rejected) must leave no half-started listener behind.
	div, err := godivert.New(winFilter, godivert.LayerNetworkForward, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("tproxy windows windivert open (administrator privileges required): %w", err)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(tcpAddr.Port)))
	if err != nil {
		div.Close()
		return nil, fmt.Errorf("tproxy windows listen 127.0.0.1:%d: %w", tcpAddr.Port, err)
	}

	st := &winTProxyState{
		byReal:   make(map[uint64]*winFlow),
		byFake:   make(map[uint16]*winFlow),
		nextFake: fakeSrcBase,
		ln:       ln,
		closeCh:  make(chan struct{}),
	}

	st.wg.Go(func() { winPump(div, st) })

	return &winTProxyListener{st: st}, nil
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
		if h == nil || h.IP == nil || h.TCP == nil {
			_, _ = div.Send(pkt, &addr)
			continue
		}

		st.rewrite(pkt, h, div, &addr)
	}
}

// rewrite handles one forwarded client->origin packet. Tracked flows get both
// endpoints normalized to loopback. An untracked SYN opens a flow (recorded,
// then rewritten); anything else untracked passes through untouched — only
// port 80/443 SYNs create flows, so the table stays bounded to web traffic,
// and claiming mid-stream packets would yield broken half-connections.
func (st *winTProxyState) rewrite(pkt []byte, h *godivert.PacketHeaders, div *godivert.Divert, addr *godivert.Address) {
	key := flowKey(h.IP.SrcAddr, be16(h.TCP.SrcPort))

	st.mu.Lock()
	f, known := st.byReal[key]
	if !known {
		if !h.TCP.Syn() || h.TCP.Ack() {
			st.mu.Unlock()
			_, _ = div.Send(pkt, addr) // let it route normally
			return
		}
		f = &winFlow{
			origDstIP: h.IP.DstAddr,
			origDstP:  be16(h.TCP.DstPort),
			clientIP:  h.IP.SrcAddr,
			clientP:   be16(h.TCP.SrcPort),
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

func (st *winTProxyState) lookupFake(fakeP uint16) (clientIP uint32, clientP uint16, origDstIP uint32, origDstP uint16, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	f, ok := st.byFake[fakeP]
	if !ok {
		return 0, 0, 0, 0, false
	}
	return f.clientIP, f.clientP, f.origDstIP, f.origDstP, true
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
		clientIP, clientP, origDstIP, origDstP, known := l.st.lookupFake(uint16(tc.Port))
		if !known {
			// Fail closed exactly like tproxy_linux.go: without the original
			// destination we cannot honor the transparent contract, and
			// guessing would let a connection escape interception decisions.
			c.Close()
			continue
		}
		client := &net.TCPAddr{IP: net.IPv4(byte(clientIP>>24), byte(clientIP>>16), byte(clientIP>>8), byte(clientIP)).To4(), Port: int(clientP)}
		orig := &net.TCPAddr{IP: net.IPv4(byte(origDstIP>>24), byte(origDstIP>>16), byte(origDstIP>>8), byte(origDstIP)).To4(), Port: int(origDstP)}
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

// ---- byte-order helpers --------------------------------------------------
//
// godivert header fields are raw network-byte-order memory images. These
// convert between that image and host-order numbers WITHOUT importing
// encoding/binary, so the endian swap is explicit in one place.

// be16 converts a wire-order uint16 field to host order.
func be16(v uint16) uint16 { return uint16(v>>8 | v<<8) }

// h16 converts a host-order uint16 to its wire-order memory image.
func h16(v uint16) uint16 { return be16(v) } // symmetric byte swap

// flowKey packs a network-order client IP and host-order port into one map
// key. The IP word is kept in wire order throughout — it only needs to be a
// stable identifier here, never interpreted numerically.
func flowKey(ipWord uint32, port uint16) uint64 {
	return uint64(ipWord)<<16 | uint64(port)
}
