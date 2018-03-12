// ntt.go - Number-Theoretic Transform.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

// Computes negacyclic number-theoretic transform (NTT) of a polynomial (vector
// of 256 coefficients) in place; inputs assumed to be in normal order, output
// in bitreversed order.
func nttRef(p *[kyberN]uint16) {
	var j int
	k := 1
	for level := 7; level >= 0; level-- {
		distance := 1 << uint(level)
		for start := 0; start < kyberN; start = j + distance {
			zeta := zetas[k]
			k++
			for j = start; j < start+distance; j++ {
				t := montgomeryReduce(uint32(zeta) * uint32(p[j+distance]))
				p[j+distance] = barrettReduce(p[j] + 4*kyberQ - t)

				if level&1 == 1 { // odd level
					p[j] = p[j] + t // Omit reduction (be lazy)
				} else {
					p[j] = barrettReduce(p[j] + t)
				}
			}
		}
	}
}

// Computes inverse of negacyclic number-theoretic transform (NTT) of a
// polynomial (vector of 256 coefficients) in place; inputs assumed to be in
// bitreversed order, output in normal order.
func invnttRef(a *[kyberN]uint16) {
	for level := 0; level < 8; level++ {
		distance := 1 << uint(level)
		for start := 0; start < distance; start++ {
			var jTwiddle int
			for j := start; j < kyberN-1; j += 2 * distance {
				w := uint32(omegasInvBitrevMontgomery[jTwiddle])
				jTwiddle++

				temp := a[j]

				if level&1 == 1 { // odd level
					a[j] = barrettReduce(temp + a[j+distance])
				} else {
					a[j] = temp + a[j+distance] // Omit reduction (be lazy)
				}

				t := w * (uint32(temp) + 4*kyberQ - uint32(a[j+distance]))

				a[j+distance] = montgomeryReduce(t)
			}
		}
	}

	for i, v := range psisInvMontgomery {
		a[i] = montgomeryReduce(uint32(a[i]) * uint32(v))
	}
}
