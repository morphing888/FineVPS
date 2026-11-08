//go:build !windows

package tgproxy

import (
	"syscall"
)

func bindDeviceControl(device string) func(network, address string, c syscall.RawConn) error {
	if device == "" || device == "direct" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
