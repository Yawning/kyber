// kem.go - Kyber key encapsulation mechanism.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrInvalidKeySize is the error returned when a byte serailized key is
	// an invalid size.
	ErrInvalidKeySize = errors.New("kyber: invalid key size")

	// ErrInvalidCipherTextSize is the error thrown via a panic when a byte
	// serialized ciphertext is an invalid size.
	ErrInvalidCipherTextSize = errors.New("kyber: invalid ciphertext size")

	// ErrInvalidPrivateKey is the error returned when a byte serialized
	// private key is malformed.
	ErrInvalidPrivateKey = errors.New("kyber: invalid private key")
)

// PrivateKey is a Kyber private key.
type PrivateKey struct {
	PublicKey
	sk *indcpaSecretKey
	z  []byte
}

// Bytes returns the byte serialization of a PrivateKey.
func (sk *PrivateKey) Bytes() []byte {
	p := sk.PublicKey.p

	b := make([]byte, 0, p.secretKeySize)
	b = append(b, sk.sk.packed...)
	b = append(b, sk.PublicKey.pk.packed...)
	b = append(b, sk.PublicKey.pk.h[:]...)
	b = append(b, sk.z...)

	return b
}

// PrivateKeyFromBytes deserializes a byte serialized PrivateKey.
func (p *ParameterSet) PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != p.secretKeySize {
		return nil, ErrInvalidKeySize
	}

	sk := new(PrivateKey)
	sk.sk = new(indcpaSecretKey)
	sk.z = make([]byte, SymSize)
	sk.PublicKey.pk = new(indcpaPublicKey)
	sk.PublicKey.p = p

	// De-serialize the public key first.
	off := p.indcpaSecretKeySize
	if err := sk.PublicKey.pk.fromBytes(p, b[off:off+p.publicKeySize]); err != nil {
		return nil, err
	}
	off += p.publicKeySize
	if !bytes.Equal(sk.PublicKey.pk.h[:], b[off:off+SymSize]) {
		return nil, ErrInvalidPrivateKey
	}
	off += SymSize
	copy(sk.z, b[off:])

	// Then go back to de-serialize the private key.
	if err := sk.sk.fromBytes(p, b[:p.indcpaSecretKeySize]); err != nil {
		return nil, err
	}

	return sk, nil
}

// PublicKey is a Kyber public key.
type PublicKey struct {
	pk *indcpaPublicKey
	p  *ParameterSet
}

// Bytes returns the byte serialization of a PublicKey.
func (pk *PublicKey) Bytes() []byte {
	return pk.pk.toBytes()
}

// PublicKeyFromBytes deserializes a byte serialized PublicKey.
func (p *ParameterSet) PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	pk := &PublicKey{
		pk: new(indcpaPublicKey),
		p:  p,
	}

	if err := pk.pk.fromBytes(p, b); err != nil {
		return nil, err
	}

	return pk, nil
}

// GenerateKeyPair generates a private and public key parameterized with the
// given ParameterSet.
func (p *ParameterSet) GenerateKeyPair(rng io.Reader) (*PublicKey, *PrivateKey, error) {
	kp := new(PrivateKey)

	var err error
	if kp.PublicKey.pk, kp.sk, err = p.indcpaKeyPair(rng); err != nil {
		return nil, nil, err
	}

	kp.PublicKey.p = p
	kp.z = make([]byte, SymSize)
	if _, err := io.ReadFull(rng, kp.z); err != nil {
		return nil, nil, err
	}

	return &kp.PublicKey, kp, nil
}

// KEMEncrypt generates cipher text and shared secret via the CCA-secure Kyber
// key encapsulation mechanism.
func (pk *PublicKey) KEMEncrypt(rng io.Reader) (cipherText []byte, sharedSecret []byte, err error) {
	var buf [SymSize]byte
	if _, err = io.ReadFull(rng, buf[:]); err != nil {
		return nil, nil, err
	}
	buf = sha3.Sum256(buf[:]) // Don't release system RNG output

	hKr := sha3.New512()
	hKr.Write(buf[:])
	hKr.Write(pk.pk.h[:]) // Multitarget countermeasures for coins + contributory KEM
	kr := hKr.Sum(nil)

	cipherText = make([]byte, pk.p.cipherTextSize)
	pk.p.indcpaEncrypt(cipherText, buf[:], pk.pk, kr[SymSize:]) // coins are in kr[SymSize:]

	hc := sha3.Sum256(cipherText)
	copy(kr[SymSize:], hc[:]) // overwrite coins in kr with H(c)
	hSs := sha3.New256()
	hSs.Write(kr)
	sharedSecret = hSs.Sum(nil) // hash concatenation of pre-k and H(c) to k

	return
}

// KEMDecrypt generates shared secret for given cipher text via the CCA-secure
// Kyber key encapsulation mechanism.
//
// On failures, sharedSecret will contain a randomized value.  Providing a
// cipher text that is obviously malformed (too large/small) will result in a
// panic.
func (sk *PrivateKey) KEMDecrypt(cipherText []byte) (sharedSecret []byte) {
	var buf [2 * SymSize]byte

	p := sk.PublicKey.p
	if len(cipherText) != p.CipherTextSize() {
		panic(ErrInvalidCipherTextSize)
	}
	p.indcpaDecrypt(buf[:SymSize], cipherText, sk.sk)

	copy(buf[SymSize:], sk.PublicKey.pk.h[:]) // Multitarget countermeasure for coins + contributory KEM
	kr := sha3.Sum512(buf[:])

	cmp := make([]byte, p.cipherTextSize)
	p.indcpaEncrypt(cmp, buf[:SymSize], sk.PublicKey.pk, kr[SymSize:]) // coins are in kr[SymSize:]

	hc := sha3.Sum256(cipherText)
	copy(kr[SymSize:], hc[:]) // overwrite coins in kr with H(c)

	fail := subtle.ConstantTimeSelect(subtle.ConstantTimeCompare(cipherText, cmp), 0, 1)
	subtle.ConstantTimeCopy(fail, kr[SymSize:], sk.z) // Overwrite pre-k with z on re-encryption failure

	h := sha3.New256()
	h.Write(kr[:])
	sharedSecret = h.Sum(nil)

	return
}
