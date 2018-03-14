// polyvec.go - Vector of Kyber polynomials.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

type polyVec struct {
	vec []*poly
}

// Compress and serialize vector of polynomials.
func (v *polyVec) compress(r []byte) {
	var off int
	for _, vec := range v.vec {
		for j := 0; j < kyberN/8; j++ {
			var t [8]uint16
			for k := 0; k < 8; k++ {
				t[k] = uint16((((uint32(freeze(vec.coeffs[8*j+k])) << 11) + kyberQ/2) / kyberQ) & 0x7ff)
			}

			r[off+11*j+0] = byte(t[0] & 0xff)
			r[off+11*j+1] = byte((t[0] >> 8) | ((t[1] & 0x1f) << 3))
			r[off+11*j+2] = byte((t[1] >> 5) | ((t[2] & 0x03) << 6))
			r[off+11*j+3] = byte((t[2] >> 2) & 0xff)
			r[off+11*j+4] = byte((t[2] >> 10) | ((t[3] & 0x7f) << 1))
			r[off+11*j+5] = byte((t[3] >> 7) | ((t[4] & 0x0f) << 4))
			r[off+11*j+6] = byte((t[4] >> 4) | ((t[5] & 0x01) << 7))
			r[off+11*j+7] = byte((t[5] >> 1) & 0xff)
			r[off+11*j+8] = byte((t[5] >> 9) | ((t[6] & 0x3f) << 2))
			r[off+11*j+9] = byte((t[6] >> 6) | ((t[7] & 0x07) << 5))
			r[off+11*j+10] = byte((t[7] >> 3))
		}
		off += compressedCoeffSize
	}
}

// De-serialize and decompress vector of polynomials; approximate inverse of
// polyVec.compress().
func (v *polyVec) decompress(a []byte) {
	var off int
	for _, vec := range v.vec {
		for j := 0; j < kyberN/8; j++ {
			vec.coeffs[8*j+0] = uint16((((uint32(a[off+11*j+0]) | ((uint32(a[off+11*j+1]) & 0x07) << 8)) * kyberQ) + 1024) >> 11)
			vec.coeffs[8*j+1] = uint16(((((uint32(a[off+11*j+1]) >> 3) | ((uint32(a[off+11*j+2]) & 0x3f) << 5)) * kyberQ) + 1024) >> 11)
			vec.coeffs[8*j+2] = uint16(((((uint32(a[off+11*j+2]) >> 6) | ((uint32(a[off+11*j+3]) & 0xff) << 2) | ((uint32(a[off+11*j+4]) & 0x01) << 10)) * kyberQ) + 1024) >> 11)
			vec.coeffs[8*j+3] = uint16(((((uint32(a[off+11*j+4]) >> 1) | ((uint32(a[off+11*j+5]) & 0x0f) << 7)) * kyberQ) + 1024) >> 11)
			vec.coeffs[8*j+4] = uint16(((((uint32(a[off+11*j+5]) >> 4) | ((uint32(a[off+11*j+6]) & 0x7f) << 4)) * kyberQ) + 1024) >> 11)
			vec.coeffs[8*j+5] = uint16(((((uint32(a[off+11*j+6]) >> 7) | ((uint32(a[off+11*j+7]) & 0xff) << 1) | ((uint32(a[off+11*j+8]) & 0x03) << 9)) * kyberQ) + 1024) >> 11)
			vec.coeffs[8*j+6] = uint16(((((uint32(a[off+11*j+8]) >> 2) | ((uint32(a[off+11*j+9]) & 0x1f) << 6)) * kyberQ) + 1024) >> 11)
			vec.coeffs[8*j+7] = uint16(((((uint32(a[off+11*j+9]) >> 5) | ((uint32(a[off+11*j+10]) & 0xff) << 3)) * kyberQ) + 1024) >> 11)
		}
		off += compressedCoeffSize
	}
}

// Serialize vector of polynomials.
func (v *polyVec) toBytes(r []byte) {
	for i, p := range v.vec {
		p.toBytes(r[i*polySize:])
	}
}

// De-serialize vector of polynomials; inverse of polyVec.toBytes().
func (v *polyVec) fromBytes(a []byte) {
	for i, p := range v.vec {
		p.fromBytes(a[i*polySize:])
	}
}

// Apply forward NTT to all elements of a vector of polynomials.
func (v *polyVec) ntt() {
	for _, p := range v.vec {
		p.ntt()
	}
}

// Apply inverse NTT to all elements of a vector of polynomials.
func (v *polyVec) invntt() {
	for _, p := range v.vec {
		p.invntt()
	}
}

// Pointwise multiply elements of a and b and accumulate into p.
func (p *poly) pointwiseAcc(a, b *polyVec) {
	hardwareAccelImpl.pointwiseAccFn(p, a, b)
}

// Add vectors of polynomials.
func (v *polyVec) add(a, b *polyVec) {
	for i, p := range v.vec {
		p.add(a.vec[i], b.vec[i])
	}
}

// Get compressed and serialized size in bytes.
func (v *polyVec) compressedSize() int {
	return len(v.vec) * compressedCoeffSize
}

func pointwiseAccRef(p *poly, a, b *polyVec) {
	for j := 0; j < kyberN; j++ {
		t := montgomeryReduce(4613 * uint32(b.vec[0].coeffs[j])) // 4613 = 2^{2*18} % q
		p.coeffs[j] = montgomeryReduce(uint32(a.vec[0].coeffs[j]) * uint32(t))
		for i := 1; i < len(a.vec); i++ { // len(a.vec) == kyberK
			t = montgomeryReduce(4613 * uint32(b.vec[i].coeffs[j]))
			p.coeffs[j] += montgomeryReduce(uint32(a.vec[i].coeffs[j]) * uint32(t))
		}

		p.coeffs[j] = barrettReduce(p.coeffs[j])
	}
}
