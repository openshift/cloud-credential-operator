<<<<<<< HEAD
//go:build (linux || aix || zos) && !js && !wasi
=======
//go:build (linux || aix || zos) && !js
>>>>>>> baeadee06 (mockgen deprecated: use uber-go/mock instead)
// +build linux aix zos
// +build !js
// +build !wasi

package logrus

import "golang.org/x/sys/unix"

const ioctlReadTermios = unix.TCGETS

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	return err == nil
}
