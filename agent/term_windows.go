//go:build windows
// +build windows

package agent

import (
	"golang.org/x/sys/windows"
)

func init() {
	enableVT()
}

func enableVT() {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil || h == windows.InvalidHandle {
		return
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	mode = mode | windows.ENABLE_PROCESSED_OUTPUT |
		windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING |
		windows.DISABLE_NEWLINE_AUTO_RETURN
	_ = windows.SetConsoleMode(h, mode)
}

func flushStdout() {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil || h == windows.InvalidHandle {
		return
	}
	_ = windows.FlushFileBuffers(h)
}

func flushStdin() {
	h, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil || h == windows.InvalidHandle {
		return
	}
	_ = windows.FlushConsoleInputBuffer(h)
}
