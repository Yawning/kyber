// hwaccel.go - Hardware acceleration hooks.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

const implReference = "Reference"

var (
	isHardwareAccelerated = false
	hardwareAccelImpl     = implReference

	nttFn    = nttRef
	invnttFn = invnttRef
)

func forceDisableHardwareAcceleration() {
	// This is for the benefit of testing, so that it's possible to test
	// all versions that are supported by the host.
	isHardwareAccelerated = false
	hardwareAccelImpl = implReference
	nttFn = nttRef
	invnttFn = invnttRef
}

// IsHardwareAccelerated returns true iff the Kyber implementation will use
// hardware acceleration (eg: AVX2).
func IsHardwareAccelerated() bool {
	return isHardwareAccelerated
}

func init() {
	initHardwareAcceleration()
}
