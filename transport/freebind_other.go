//go:build !linux

package transport

import "syscall"

// applyFreebind is a Linux-only feature; on other platforms it's a no-op.
// macOS / Windows / BSD don't have an equivalent socket option and rely on
// the bound address being configured on the interface.
func applyFreebind(_ syscall.RawConn) {}
