//go:build !windows
// +build !windows

package agent

import (
	"os"

	"golang.org/x/term"
)

func getVisibleTerminalSize() (int, int) {
	if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		return w, h
	}
	return 80, 24
}
