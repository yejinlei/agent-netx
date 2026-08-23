//go:build windows
// +build windows

package agent

import "golang.org/x/sys/windows"

// getVisibleTerminalSize returns the actual visible dimensions of the Windows
// console window. golang.org/x/term.GetSize returns the buffer size (often
// thousands of rows and hundreds of cols), which makes the scroll region and
// status bar land far off-screen. GetConsoleScreenBufferInfo.Window gives us
// the real visible area. If Window is zero-sized we fall back to the buffer
// size.
func getVisibleTerminalSize() (int, int) {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil || h == windows.InvalidHandle {
		return 80, 24
	}
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(h, &info); err != nil {
		return 80, 24
	}

	// Prefer the visible window dimensions. The buffer can be much larger than
	// the window (e.g. buffer 240 cols but visible window 120).
	w := int(info.Window.Right - info.Window.Left + 1)
	hi := int(info.Window.Bottom - info.Window.Top + 1)

	// Fall back to the buffer dimensions if the window is zero-sized (rare,
	// e.g. freshly opened cmd with no Window set).
	if w <= 0 {
		w = int(info.Size.X)
	}
	if hi <= 0 {
		hi = int(info.Size.Y)
	}
	if w < 40 {
		w = 40
	}
	if hi < 12 {
		hi = 12
	}
	return w, hi
}
