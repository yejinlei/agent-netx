//go:build !linux && !windows

package listener

import (
	"fmt"
	"net"
	"runtime"
)

// tproxyListen returns a platform error on platforms without a TProxy
// implementation. Counterpart of tproxy_linux.go (Linux) and
// tproxy_windows.go (WinDivert).
func tproxyListen(addr string) (net.Listener, error) {
	return nil, fmt.Errorf("TProxy is only supported on Linux and Windows (platform=%s/%s)", runtime.GOOS, runtime.GOARCH)
}

// installTProxyRouting / teardownTProxyRouting are no-ops off Linux.
// See tproxy_linux.go for the Linux implementation.
func installTProxyRouting(mark, table int) error { return nil }
func teardownTProxyRouting(mark, table int)      {}