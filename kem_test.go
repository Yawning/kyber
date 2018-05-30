// kem_test.go - Kyber KEM tests.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

const nTests = 100

var (
	allParams = []*ParameterSet{
		Kyber512,
		Kyber768,
		Kyber1024,
	}

	canAccelerate bool
)

func mustInitHardwareAcceleration() {
	initHardwareAcceleration()
	if !IsHardwareAccelerated() {
		panic("initHardwareAcceleration() failed")
	}
}

func TestKEM(t *testing.T) {
	forceDisableHardwareAcceleration()
	doTestKEM(t)

	if !canAccelerate {
		t.Log("Hardware acceleration not supported on this host.")
		return
	}
	mustInitHardwareAcceleration()
	doTestKEM(t)
}

func doTestKEM(t *testing.T) {
	impl := "_" + hardwareAccelImpl.name
	for _, p := range allParams {
		t.Run(p.Name()+"_Keys"+impl, func(t *testing.T) { doTestKEMKeys(t, p) })
		t.Run(p.Name()+"_Invalid_SecretKey_A"+impl, func(t *testing.T) { doTestKEMInvalidSkA(t, p) })
		t.Run(p.Name()+"_Invalid_CipherText"+impl, func(t *testing.T) { doTestKEMInvalidCipherText(t, p) })
	}
}

func doTestKEMKeys(t *testing.T, p *ParameterSet) {
	require := require.New(t)

	t.Logf("PrivateKeySize(): %v", p.PrivateKeySize())
	t.Logf("PublicKeySize(): %v", p.PublicKeySize())
	t.Logf("CipherTextSize(): %v", p.CipherTextSize())

	for i := 0; i < nTests; i++ {
		// Generate a key pair.
		pk, sk, err := p.GenerateKeyPair(rand.Reader)
		require.NoError(err, "GenerateKeyPair()")

		// Test serialization.
		b := sk.Bytes()
		require.Len(b, p.PrivateKeySize(), "sk.Bytes(): Length")
		sk2, err := p.PrivateKeyFromBytes(b)
		require.NoError(err, "PrivateKeyFromBytes(b)")
		requirePrivateKeyEqual(require, sk, sk2)

		b = pk.Bytes()
		require.Len(b, p.PublicKeySize(), "pk.Bytes(): Length")
		pk2, err := p.PublicKeyFromBytes(b)
		require.NoError(err, "PublicKeyFromBytes(b)")
		requirePublicKeyEqual(require, pk, pk2)

		// Test encrypt/decrypt.
		ct, ss, err := pk.KEMEncrypt(rand.Reader)
		require.NoError(err, "KEMEncrypt()")
		require.Len(ct, p.CipherTextSize(), "KEMEncrypt(): ct Length")
		require.Len(ss, SymSize, "KEMEncrypt(): ss Length")

		ss2 := sk.KEMDecrypt(ct)
		require.Equal(ss, ss2, "KEMDecrypt(): ss")
	}
}

func doTestKEMInvalidSkA(t *testing.T, p *ParameterSet) {
	require := require.New(t)

	for i := 0; i < nTests; i++ {
		// Alice generates a public key.
		pk, skA, err := p.GenerateKeyPair(rand.Reader)
		require.NoError(err, "GenerateKeyPair()")

		// Bob derives a secret key and creates a response.
		sendB, keyB, err := pk.KEMEncrypt(rand.Reader)
		require.NoError(err, "KEMEncrypt()")

		// Replace secret key with random values.
		_, err = rand.Read(skA.sk.packed)
		require.NoError(err, "rand.Read()")

		// Alice uses Bob's response to get her secret key.
		keyA := skA.KEMDecrypt(sendB)
		require.NotEqual(keyA, keyB, "KEMDecrypt(): ss")
	}
}

func doTestKEMInvalidCipherText(t *testing.T, p *ParameterSet) {
	require := require.New(t)
	var rawPos [2]byte

	ciphertextSize := p.CipherTextSize()

	for i := 0; i < nTests; i++ {
		_, err := rand.Read(rawPos[:])
		require.NoError(err, "rand.Read()")
		pos := (int(rawPos[0]) << 8) | int(rawPos[1])

		// Alice generates a public key.
		pk, skA, err := p.GenerateKeyPair(rand.Reader)
		require.NoError(err, "GenerateKeyPair()")

		// Bob derives a secret key and creates a response.
		sendB, keyB, err := pk.KEMEncrypt(rand.Reader)
		require.NoError(err, "KEMEncrypt()")

		// Change some byte in the ciphertext (i.e., encapsulated key).
		sendB[pos%ciphertextSize] ^= 23

		// Alice uses Bob's response to get her secret key.
		keyA := skA.KEMDecrypt(sendB)
		require.NotEqual(keyA, keyB, "KEMDecrypt(): ss")
	}
}

func requirePrivateKeyEqual(require *require.Assertions, a, b *PrivateKey) {
	require.EqualValues(a.sk, b.sk, "sk (indcpaSecretKey)")
	require.Equal(a.z, b.z, "z (random bytes)")
	requirePublicKeyEqual(require, &a.PublicKey, &b.PublicKey)
}

func requirePublicKeyEqual(require *require.Assertions, a, b *PublicKey) {
	require.EqualValues(a.pk, b.pk, "pk (indcpaPublicKey)")
	require.Equal(a.p, b.p, "p (ParameterSet)")
}

func BenchmarkKEM(b *testing.B) {
	forceDisableHardwareAcceleration()
	doBenchmarkKEM(b)

	if !canAccelerate {
		b.Log("Hardware acceleration not supported on this host.")
		return
	}
	mustInitHardwareAcceleration()
	doBenchmarkKEM(b)
}

func doBenchmarkKEM(b *testing.B) {
	impl := "_" + hardwareAccelImpl.name
	for _, p := range allParams {
		b.Run(p.Name()+"_GenerateKeyPair"+impl, func(b *testing.B) { doBenchKEMGenerateKeyPair(b, p) })
		b.Run(p.Name()+"_KEMEncrypt"+impl, func(b *testing.B) { doBenchKEMEncDec(b, p, true) })
		b.Run(p.Name()+"_KEMDecrypt"+impl, func(b *testing.B) { doBenchKEMEncDec(b, p, false) })
	}
}

func doBenchKEMGenerateKeyPair(b *testing.B, p *ParameterSet) {
	for i := 0; i < b.N; i++ {
		_, _, err := p.GenerateKeyPair(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateKeyPair(): %v", err)
		}
	}
}

func doBenchKEMEncDec(b *testing.B, p *ParameterSet, isEnc bool) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		pk, skA, err := p.GenerateKeyPair(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateKeyPair(): %v", err)
		}

		if isEnc {
			b.StartTimer()
		}

		sendB, keyB, err := pk.KEMEncrypt(rand.Reader)
		if err != nil {
			b.Fatalf("KEMEncrypt(): %v", err)
		}
		if isEnc {
			b.StopTimer()
		} else {
			b.StartTimer()
		}

		keyA := skA.KEMDecrypt(sendB)
		if !isEnc {
			b.StopTimer()
		}

		if !bytes.Equal(keyA, keyB) {
			b.Fatalf("KEMDecrypt(): key mismatch")
		}
	}
}

func init() {
	canAccelerate = IsHardwareAccelerated()
}
