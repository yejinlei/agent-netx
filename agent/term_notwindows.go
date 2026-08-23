//go:build !windows
// +build !windows

package agent

import "os"

func enableVT()    {}
func flushStdout() { os.Stdout.Sync() }
func flushStdin()  {}
