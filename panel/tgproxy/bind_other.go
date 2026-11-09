//go:build windows

package tgproxy

import (
	"syscall"
)

func bindDeviceControl(device string) func(network, address string, c syscall.RawConn) error {
	return nil
}
