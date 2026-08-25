//go:build windows
// +build windows

package agent

import (
	"golang.org/x/sys/windows"
)

func init() {
	enableVT()
}

// enableVT 只开 VT 序列处理，保留控制台的换行自动回车（\n -> \r\n）。
// 注意：不能设置 DISABLE_NEWLINE_AUTO_RETURN，否则普通命令（如 -h 帮助）
// 的每个 \n 都不回行首，输出会变成阶梯状乱码。
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
		windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
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
