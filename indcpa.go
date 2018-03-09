// indcpa.go - Kyber IND-CPA encryption.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

import (
	"io"

	"golang.org/x/crypto/sha3"
)

// Serialize the public key as concatenation of the compressed and serialized
// vector of polynomials pk and the public seed used to generate the matrix A.
func packPublicKey(r []byte, pk *polyVec, seed []byte) {
	pk.compress(r)
	copy(r[pk.compressedSize():], seed[:SymSize])
}

// De-serialize and decompress public key from a byte array; approximate
// inverse of packPublicKey.
func unpackPublicKey(pk *polyVec, seed, packedPk []byte) {
	pk.decompress(packedPk)

	off := pk.compressedSize()
	copy(seed, packedPk[off:off+SymSize])
}

// Serialize the ciphertext as concatenation of the compressed and serialized
// vector of polynomials b and the compressed and serialized polynomial v.
func packCiphertext(r []byte, b *polyVec, v *poly) {
	b.compress(r)
	v.compress(r[b.compressedSize():])
}

// De-serialize and decompress ciphertext from a byte array; approximate
// inverse of packCiphertext.
func unpackCiphertext(b *polyVec, v *poly, c []byte) {
	b.decompress(c)
	v.decompress(c[b.compressedSize():])
}

// Serialize the secret key.
func packSecretKey(r []byte, sk *polyVec) {
	sk.toBytes(r)
}

// De-serialize the secret key; inverse of packSecretKey.
func unpackSecretKey(sk *polyVec, packedSk []byte) {
	sk.fromBytes(packedSk)
}

// Deterministically generate matrix A (or the transpose of A) from a seed.
// Entries of the matrix are polynomials that look uniformly random. Performs
// rejection sampling on output of SHAKE-128.
func genMatrix(a []polyVec, seed []byte, transposed bool) {
	const (
		shake128Rate = 168 // xof.BlockSize() is not a constant.
		maxBlocks    = 4
	)
	var buf [shake128Rate * maxBlocks]byte

	var extSeed [SymSize + 2]byte
	copy(extSeed[:SymSize], seed)

	xof := sha3.NewShake128()

	for i, v := range a {
		for j, p := range v.vec {
			if transposed {
				extSeed[SymSize] = byte(i)
				extSeed[SymSize+1] = byte(j)
			} else {
				extSeed[SymSize] = byte(j)
				extSeed[SymSize+1] = byte(i)
			}

			xof.Write(extSeed[:])
			xof.Read(buf[:])

			for ctr, pos, maxPos := 0, 0, len(buf); ctr < kyberN; {
				val := (uint16(buf[pos]) | (uint16(buf[pos+1]) << 8)) & 0x1fff
				if val < kyberQ {
					p.coeffs[ctr] = val
					ctr++
				}
				if pos += 2; pos == maxPos {
					// On the unlikely chance 4 blocks is insufficient,
					// incrementally squeeze out 1 block at a time.
					xof.Read(buf[:shake128Rate])
					pos, maxPos = 0, shake128Rate
				}
			}

			xof.Reset()
		}
	}
}

type indcpaPublicKey struct {
	packed []byte
	h      [32]byte
}

func (pk *indcpaPublicKey) toBytes() []byte {
	return pk.packed
}

func (pk *indcpaPublicKey) fromBytes(p *ParameterSet, b []byte) error {
	if len(b) != p.indcpaPublicKeySize {
		return ErrInvalidKeySize
	}

	pk.packed = make([]byte, len(b))
	copy(pk.packed, b)
	pk.h = sha3.Sum256(b)

	return nil
}

type indcpaSecretKey struct {
	packed []byte
}

func (sk *indcpaSecretKey) fromBytes(p *ParameterSet, b []byte) error {
	if len(b) != p.indcpaSecretKeySize {
		return ErrInvalidKeySize
	}

	sk.packed = make([]byte, len(b))
	copy(sk.packed, b)

	return nil
}

// Generates public and private key for the CPA-secure public-key encryption
// scheme underlying Kyber.
func (p *ParameterSet) indcpaKeyPair(rng io.Reader) (*indcpaPublicKey, *indcpaSecretKey, error) {
	buf := make([]byte, SymSize+SymSize)
	if _, err := io.ReadFull(rng, buf[:SymSize]); err != nil {
		return nil, nil, err
	}

	sk := &indcpaSecretKey{
		packed: make([]byte, p.indcpaSecretKeySize),
	}
	pk := &indcpaPublicKey{
		packed: make([]byte, p.indcpaPublicKeySize),
	}

	h := sha3.New512()
	h.Write(buf[:SymSize])
	buf = buf[:0] // Reuse the backing store.
	buf = h.Sum(buf)
	publicSeed, noiseSeed := buf[:SymSize], buf[SymSize:]

	a := p.allocMatrix()
	genMatrix(a, publicSeed, false)

	var nonce byte
	skpv := p.allocPolyVec()
	for _, pv := range skpv.vec {
		pv.getNoise(noiseSeed, nonce, p.eta)
		nonce++
	}

	skpv.ntt()

	e := p.allocPolyVec()
	for _, pv := range e.vec {
		pv.getNoise(noiseSeed, nonce, p.eta)
		nonce++
	}

	// matrix-vector multiplication
	pkpv := p.allocPolyVec()
	for i, pv := range pkpv.vec {
		pv.pointwiseAcc(&skpv, &a[i])
	}

	pkpv.invntt()
	pkpv.add(&pkpv, &e)

	packSecretKey(sk.packed, &skpv)
	packPublicKey(pk.packed, &pkpv, publicSeed)
	pk.h = sha3.Sum256(pk.packed)

	return pk, sk, nil
}

// Encryption function of the CPA-secure public-key encryption scheme
// underlying Kyber.
func (p *ParameterSet) indcpaEncrypt(c, m []byte, pk *indcpaPublicKey, coins []byte) {
	var k, v, epp poly
	var seed [SymSize]byte

	pkpv := p.allocPolyVec()
	unpackPublicKey(&pkpv, seed[:], pk.packed)

	k.fromMsg(m)

	pkpv.ntt()

	at := p.allocMatrix()
	genMatrix(at, seed[:], true)

	var nonce byte
	sp := p.allocPolyVec()
	for _, pv := range sp.vec {
		pv.getNoise(coins, nonce, p.eta)
		nonce++
	}

	sp.ntt()

	ep := p.allocPolyVec()
	for _, pv := range ep.vec {
		pv.getNoise(coins, nonce, p.eta)
		nonce++
	}

	// matrix-vector multiplication
	bp := p.allocPolyVec()
	for i, pv := range bp.vec {
		pv.pointwiseAcc(&sp, &at[i])
	}

	bp.invntt()
	bp.add(&bp, &ep)

	v.pointwiseAcc(&pkpv, &sp)
	v.invntt()

	epp.getNoise(coins, nonce, p.eta) // Don't need to increment nonce.

	v.add(&v, &epp)
	v.add(&v, &k)

	packCiphertext(c, &bp, &v)
}

// Decryption function of the CPA-secure public-key encryption scheme
// underlying Kyber.
func (p *ParameterSet) indcpaDecrypt(m, c []byte, sk *indcpaSecretKey) {
	var v, mp poly

	skpv, bp := p.allocPolyVec(), p.allocPolyVec()
	unpackCiphertext(&bp, &v, c)
	unpackSecretKey(&skpv, sk.packed)

	bp.ntt()

	mp.pointwiseAcc(&skpv, &bp)
	mp.invntt()

	mp.sub(&mp, &v)

	mp.toMsg(m)
}

func (p *ParameterSet) allocMatrix() []polyVec {
	m := make([]polyVec, 0, p.k)
	for i := 0; i < p.k; i++ {
		m = append(m, p.allocPolyVec())
	}
	return m
}

func (p *ParameterSet) allocPolyVec() polyVec {
	vec := make([]*poly, 0, p.k)
	for i := 0; i < p.k; i++ {
		vec = append(vec, new(poly))
	}

	return polyVec{vec}
}
