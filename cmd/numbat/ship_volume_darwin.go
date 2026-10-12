//go:build darwin

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func shipVolumeIdentity(f *os.File) (string, error) {
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Volattr: unix.ATTR_VOL_INFO | unix.ATTR_VOL_UUID}
	var result [20]byte
	_, _, errno := unix.Syscall6(
		unix.SYS_FGETATTRLIST,
		f.Fd(),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&result[0])),
		uintptr(len(result)), 0, 0,
	)
	runtime.KeepAlive(f)
	if errno == unix.ENOTSUP || errno == unix.EINVAL {
		return "", nil
	}
	if errno != 0 {
		return "", fmt.Errorf("read filesystem UUID: %w", errno)
	}
	if binary.NativeEndian.Uint32(result[:4]) != uint32(len(result)) {
		return "", nil
	}
	for _, b := range result[4:] {
		if b != 0 {
			return hex.EncodeToString(result[4:]), nil
		}
	}
	return "", nil
}
