//go:build linux

package ui

import "golang.org/x/sys/unix"

// Linux spells "read the terminal attributes" TCGETS.
const ioctlReadTermios = unix.TCGETS
