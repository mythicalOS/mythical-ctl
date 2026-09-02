//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package ui

import "golang.org/x/sys/unix"

// The BSD family (macOS included) spells "read the terminal attributes" TIOCGETA.
const ioctlReadTermios = unix.TIOCGETA
