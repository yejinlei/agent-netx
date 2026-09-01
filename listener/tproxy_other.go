//go:build !linux

package listener

import (
	"fmt"
	"net"
	"runtime"
)

// tproxyListen returns a platform error on non-Linux. It is the
// non-Linux counterpart of tproxy_linux.go.
func tproxyListen(addr string) (net.Listener, error) {
	return nil, fmt.Errorf("TProxy is only supported on Linux (platform=%s/%s)", runtime.GOOS, runtime.GOARCH)
}

// installTProxyRouting / teardownTProxyRouting are no-ops off Linux.
// See tproxy_linux.go for the Linux implementation.
func installTProxyRouting(mark, table int) error { return nil }
func teardownTProxyRouting(mark, table int)      {}