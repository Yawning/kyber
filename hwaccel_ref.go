// hwaccel_ref.go - Unaccelerated stubs.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build !amd64 gccgo noasm !go1.10

package kyber

func initHardwareAcceleration() {
	forceDisableHardwareAcceleration()
}
