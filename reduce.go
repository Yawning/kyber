// reduce.go - Montgomery, Barret, and Full reduction.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

const (
	qinv = 7679 // -inverse_mod(q,2^18)
	rlog = 18
)

// Montgomery reduction; given a 32-bit integer a, computes 16-bit integer
// congruent to a * R^-1 mod q, where R=2^18 (see value of rlog).
func montgomeryReduce(a uint32) uint16 {
	u := a * qinv
	u &= (1 << rlog) - 1
	u *= kyberQ
	a += u
	return uint16(a >> rlog)
}

// Barrett reduction; given a 16-bit integer a, computes 16-bit integer
// congruent to a mod q in {0,...,11768}.
func barrettReduce(a uint16) uint16 {
	u := uint32(a >> 13) // ((uint32_t) a * sinv) >> 16
	u *= kyberQ
	a -= uint16(u)
	return a
}

// Full reduction; given a 16-bit integer a, computes unsigned integer a mod q.
func freeze(x uint16) uint16 {
	r := barrettReduce(x)

	m := r - kyberQ
	c := int16(m)
	c >>= 15
	r = m ^ ((r ^ m) & uint16(c))
	return r
}
