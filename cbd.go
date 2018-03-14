// cbd.go - Centered binomial distribution.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

// Load bytes into a 64-bit integer in little-endian order.
func loadLittleEndian(x []byte, bytes int) uint64 {
	var r uint64
	for i, v := range x[:bytes] {
		r |= uint64(v) << (8 * uint(i))
	}
	return r
}

// Given an array of uniformly random bytes, compute polynomial with
// coefficients distributed according to a centered binomial distribution
// with parameter eta.
func (p *poly) cbd(buf []byte, eta int) {
	hardwareAccelImpl.cbdFn(p, buf, eta)
}

func cbdRef(p *poly, buf []byte, eta int) {
	switch eta {
	case 3:
		var a, b [4]uint32
		for i := 0; i < kyberN/4; i++ {
			t := loadLittleEndian(buf[3*i:], 3)
			var d uint32
			for j := 0; j < 3; j++ {
				d += uint32((t >> uint(j)) & 0x249249)
			}

			a[0] = d & 0x7
			b[0] = (d >> 3) & 0x7
			a[1] = (d >> 6) & 0x7
			b[1] = (d >> 9) & 0x7
			a[2] = (d >> 12) & 0x7
			b[2] = (d >> 15) & 0x7
			a[3] = (d >> 18) & 0x7
			b[3] = (d >> 21)

			p.coeffs[4*i+0] = uint16(a[0] + kyberQ - b[0])
			p.coeffs[4*i+1] = uint16(a[1] + kyberQ - b[1])
			p.coeffs[4*i+2] = uint16(a[2] + kyberQ - b[2])
			p.coeffs[4*i+3] = uint16(a[3] + kyberQ - b[3])
		}
	case 4:
		var a, b [4]uint32
		for i := 0; i < kyberN/4; i++ {
			t := loadLittleEndian(buf[4*i:], 4)
			var d uint32
			for j := 0; j < 4; j++ {
				d += uint32((t >> uint(j)) & 0x11111111)
			}

			a[0] = d & 0xf
			b[0] = (d >> 4) & 0xf
			a[1] = (d >> 8) & 0xf
			b[1] = (d >> 12) & 0xf
			a[2] = (d >> 16) & 0xf
			b[2] = (d >> 20) & 0xf
			a[3] = (d >> 24) & 0xf
			b[3] = (d >> 28)

			p.coeffs[4*i+0] = uint16(a[0] + kyberQ - b[0])
			p.coeffs[4*i+1] = uint16(a[1] + kyberQ - b[1])
			p.coeffs[4*i+2] = uint16(a[2] + kyberQ - b[2])
			p.coeffs[4*i+3] = uint16(a[3] + kyberQ - b[3])
		}
	case 5:
		var a, b [4]uint64
		for i := 0; i < kyberN/4; i++ {
			t := loadLittleEndian(buf[5*i:], 5)
			var d uint64
			for j := 0; j < 5; j++ {
				d += (t >> uint(j)) & 0x0842108421
			}

			a[0] = d & 0x1f
			b[0] = (d >> 5) & 0x1f
			a[1] = (d >> 10) & 0x1f
			b[1] = (d >> 15) & 0x1f
			a[2] = (d >> 20) & 0x1f
			b[2] = (d >> 25) & 0x1f
			a[3] = (d >> 30) & 0x1f
			b[3] = (d >> 35)

			p.coeffs[4*i+0] = uint16(a[0] + kyberQ - b[0])
			p.coeffs[4*i+1] = uint16(a[1] + kyberQ - b[1])
			p.coeffs[4*i+2] = uint16(a[2] + kyberQ - b[2])
			p.coeffs[4*i+3] = uint16(a[3] + kyberQ - b[3])
		}
	default:
		panic("kyber: eta must be in {3,4,5}")
	}
}
