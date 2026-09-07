//go:build linux

package listener

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// tproxyListen creates a TCP TPROXY listener on the given address. It opens a
// dual-stack raw socket with IP_TRANSPARENT / IPV6_TRANSPARENT so the kernel's
// TPROXY redirect lands on it for both IPv4 and IPv6, then returns a
// net.Listener that accepts incoming connections with their original
// destination intact.
//
// Imported by Options.TProxyPort in http.go. Config schema: `listen.tproxy:
// <port>` (Listen.TProxyPort in config.go).
//
// Original destination extraction: after unix.Accept we issue a zero-length
// recvmsg with MSG_PEEK; the kernel attaches an IP_ORIGDSTADDR /
// IPV6_ORIGDSTADDR cmsg carrying the originally-targeted endpoint. We return
// that as a *net.TCPAddr so serveTProxy can feed it to Router.Pick.
func tproxyListen(addr string) (net.Listener, error) {
	lsa, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	if lsa.IP.To4() != nil {
		return tproxyListenV4(addr)
	}
	return tproxyListenV6(addr, lsa.IP)
}

// tproxyListenV4 opens an IPv4-only TPROXY socket.
func tproxyListenV4(addr string) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("tproxy socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy setsockopt SO_REUSEADDR: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy setsockopt IP_TRANSPARENT: %w", err)
	}
	lsa, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ip4 := lsa.IP.To4()
	if ip4 == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy bind %s: not an IPv4 address", addr)
	}
	sa := &unix.SockaddrInet4{Port: lsa.Port, Addr: [4]byte(ip4)}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy bind %s: %w", addr, err)
	}
	if err := unix.Listen(fd, 128); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy listen %s: %w", addr, err)
	}
	return &tproxyListener{fd: fd, addr: &net.TCPAddr{IP: lsa.IP, Port: lsa.Port}}, nil
}

// tproxyListenV6 opens a dual-stack (IPv4+IPv6) TPROXY socket bound on v6, so
// a single listener + a single set of conntrack entries serves both families.
// IPV6_V6ONLY=0 is what makes AF_INET6 also receive IPv4 traffic on Linux;
// the same socket then needs both IP_TRANSPARENT (for v4 TPROXY) and
// IPV6_TRANSPARENT (for v6 TPROXY) or the kernel refuses the connection from
// whichever family's iptables/nftables rule fires. The IPv6 wildcard bind
// ("::" or "[::]") is required for dual-stack; a specific v6 address binds
// v6-only, and 0.0.0.0 binds v4-only, which is what the callers already
// handle separately via tproxyListenV4.
func tproxyListenV6(addr string, ip6 net.IP) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("tproxy v6 socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy setsockopt SO_REUSEADDR: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy setsockopt IPV6_V6ONLY=0 (dual-stack): %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy setsockopt IP_TRANSPARENT: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy setsockopt IPV6_TRANSPARENT: %w", err)
	}
	port := 0
	if lsa, err := net.ResolveTCPAddr("tcp", addr); err == nil {
		port = lsa.Port
	}
	// Prefer "::" for the dual-stack wildcard; use the caller's explicit
	// address otherwise. The kernel needs IPv6 wildcard to accept the v4
	// mapped portion of a dual-stack socket.
	var ip6Bind net.IP
	if ip6.IsUnspecified() {
		ip6Bind = net.IPv6unspecified
	} else {
		ip6Bind = ip6
	}
	sa, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(ip6Bind.String(), strconv.Itoa(port)))
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	s6 := &unix.SockaddrInet6{Port: sa.Port}
	copy(s6.Addr[:], sa.IP.To16())
	if err := unix.Bind(fd, s6); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy bind %s: %w", addr, err)
	}
	if err := unix.Listen(fd, 128); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tproxy listen %s: %w", addr, err)
	}
	return &tproxyListener{fd: fd, addr: &net.TCPAddr{IP: sa.IP, Port: sa.Port}, v6: true}, nil
}

type tproxyListener struct {
	fd     int
	mu     sync.Mutex
	closed bool
	addr   *net.TCPAddr
	v6     bool // dual-stack socket — peer sockaddrs arrive as *SockaddrInet6
}

func (l *tproxyListener) Accept() (net.Conn, error) {
	for {
		// unix.Accept returns the peer (client) sockaddr as its second value.
		// Under TPROXY the client source is unchanged on the connection, so this
		// is the real client address — distinct from the (redirected) target we
		// read below via IP_ORIGDSTADDR / IPV6_ORIGDSTADDR.
		cfd, peerSA, err := unix.Accept(l.fd)
		if err != nil {
			return nil, err
		}
		// Both families must be permitted on the accepted conn or the
		// kernel will refuse traffic arriving on the mismatched protocol.
		_ = unix.SetsockoptInt(cfd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		if l.v6 {
			_ = unix.SetsockoptInt(cfd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		}
		orig := origDst(cfd)
		if orig == nil {
			// We cannot safely guess the target without an ORIGDSTADDR
			// cmsg. Fail closed rather than reusing the client address as
			// the target (that poison made every conn look like it
			// targeted itself).
			unix.Close(cfd)
			continue
		}
		client := sockToTCPAddr(peerSA)
		f := os.NewFile(uintptr(cfd), fmt.Sprintf("tproxy-conn-%d", cfd))
		conn, err := net.FileConn(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		tc, ok := conn.(net.Conn)
		if !ok {
			conn.Close()
			return nil, fmt.Errorf("net.FileConn returned non-Conn")
		}
		return &tproxyConn{Conn: tc, orig: orig, client: client}, nil
	}
}

func (l *tproxyListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return unix.Close(l.fd)
}

func (l *tproxyListener) Addr() net.Addr { return l.addr }

type tproxyConn struct {
	net.Conn
	orig   *net.TCPAddr
	client *net.TCPAddr
}

func (c *tproxyConn) RemoteAddr() net.Addr { return c.orig }
func (c *tproxyConn) ClientAddr() net.Addr { return c.client }

// sockToTCPAddr turns a SockaddrInet4 or SockaddrInet6 (typically the peer
// returned by Accept) into a *net.TCPAddr. For dual-stack v6 sockets, v4
// peers arrive as v6-mapped v6 addrs (ffff:0:0:0:0:0:0:<v4>). Returns nil
// when the family is unrecognized.
func sockToTCPAddr(sa unix.Sockaddr) *net.TCPAddr {
	switch pa := sa.(type) {
	case *unix.SockaddrInet4:
		if pa == nil {
			return nil
		}
		return &net.TCPAddr{IP: net.IP(pa.Addr[:]), Port: pa.Port}
	case *unix.SockaddrInet6:
		if pa == nil {
			return nil
		}
		ip := make(net.IP, 16)
		copy(ip, pa.Addr[:])
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		return &net.TCPAddr{IP: ip, Port: pa.Port}
	}
	return nil
}

// origDst peeks at the first cmsg the kernel attached to the connection and
// returns the pre-TPROXY destination. IP_ORIGDSTADDR is emitted by the v4
// TPROXY target with an 8-byte payload (port + family + v4); IPV6_ORIGDSTADDR
// (level SOL_IPV6, optname IPV6_ORIGDSTADDR) is emitted by the v6 target
// with a 20-byte payload (port + family + v6). Both share the wire format:
// 2-byte port in network order, 2-byte family in host order, then 4 or 16
// bytes of address in network order.
func origDst(fd int) *net.TCPAddr {
	oob := make([]byte, 1024)
	_, oobn, _, _, err := unix.Recvmsg(fd, nil, oob, unix.MSG_PEEK)
	if err != nil || oobn == 0 {
		return nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil
	}
	for _, msg := range msgs {
		switch {
		case msg.Header.Level == unix.IPPROTO_IP && msg.Header.Type == unix.IP_ORIGDSTADDR:
			if len(msg.Data) < 8 {
				continue
			}
			port := binary.BigEndian.Uint16(msg.Data[0:2])
			family := binary.LittleEndian.Uint16(msg.Data[2:4])
			if family != unix.AF_INET {
				continue
			}
			return &net.TCPAddr{
				IP:   net.IPv4(msg.Data[4], msg.Data[5], msg.Data[6], msg.Data[7]),
				Port: int(port),
			}
		case msg.Header.Level == unix.IPPROTO_IPV6 && msg.Header.Type == unix.IPV6_ORIGDSTADDR:
			if len(msg.Data) < 20 {
				continue
			}
			port := binary.BigEndian.Uint16(msg.Data[0:2])
			family := binary.LittleEndian.Uint16(msg.Data[2:4])
			if family != unix.AF_INET6 {
				continue
			}
			ip := make(net.IP, 16)
			copy(ip, msg.Data[4:20])
			return &net.TCPAddr{IP: ip, Port: int(port)}
		}
	}
	return nil
}

// fwmarkRoute installs the ip-rule / ip-route half of a Linux TPROXY redirect
// loop so redirected packets route back to this host instead of looping:
//
//	ip rule add fwmark MARK lookup TABLE
//	ip route add local 0.0.0.0/0 dev lo table TABLE
//
// MARK is the value matching the user's iptables/ip6tables `--set-mark` /
// `--tproxy-mark` rule; TABLE is the local routing table. 0 for either
// argument disables the auto-installed loop (the user owns the routing
// rules). The iptables/ip6tables TPROXY target rules themselves are left to
// the user / systemd unit. Idempotent on a second install: `ip rule` /
// `ip route add` fail harmlessly if the entry already exists (silenced).
// Requires CAP_NET_ADMIN.
//
// The ::/0 line is added whenever the fwmark loop is enabled — the same
// fwmark rule is consulted by the v6 routing decision, so without a
// matching local route any v6 TPROXY redirect would escape back out the
// WAN interface instead of being delivered to this host's socket.
func installTProxyRouting(mark, table int) error {
	if mark == 0 || table == 0 {
		return nil // user manages routing
	}
	if err := runIP(strings.Fields("rule add fwmark " + strconv.Itoa(mark) + " lookup " + strconv.Itoa(table))); err != nil {
		return fmt.Errorf("tproxy routing ip rule: %w", err)
	}
	if err := runIP(strings.Fields("route add local 0.0.0.0/0 dev lo table " + strconv.Itoa(table))); err != nil {
		// Best-effort teardown of the rule we just added so we don't leave a
		// half-installed loop.
		runIP(strings.Fields("rule del fwmark " + strconv.Itoa(mark) + " lookup " + strconv.Itoa(table)))
		return fmt.Errorf("tproxy routing ip route: %w", err)
	}
	_ = runIP(strings.Fields("route add local ::/0 dev lo table " + strconv.Itoa(table)))
	return nil
}

// teardownTProxyRouting removes the ip-rule / ip-route entries installed by
// installTProxyRouting. Silently swallows "no such rule/route" so Stop is
// safe to call when routing was never installed or was removed externally.
func teardownTProxyRouting(mark, table int) {
	if mark == 0 || table == 0 {
		return
	}
	runIP(strings.Fields("rule del fwmark " + strconv.Itoa(mark) + " lookup " + strconv.Itoa(table)))
	runIP(strings.Fields("rule del local 0.0.0.0/0 dev lo table " + strconv.Itoa(table)))
	runIP(strings.Fields("route del local ::/0 dev lo table " + strconv.Itoa(table)))
}

func runIP(args []string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}