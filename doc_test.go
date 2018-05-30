// doc_test.go - Kyber godoc examples.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

import (
	"bytes"
	"crypto/rand"
)

func Example_keyEncapsulationMechanism() {
	// Unauthenticated Key Encapsulation Mechanism (KEM)

	// Alice, step 1: Generate a key pair.
	alicePublicKey, alicePrivateKey, err := Kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Alice, step 2: Send the public key to Bob (Not shown).

	// Bob, step 1: Deserialize Alice's public key from the binary encoding.
	peerPublicKey, err := Kyber768.PublicKeyFromBytes(alicePublicKey.Bytes())
	if err != nil {
		panic(err)
	}

	// Bob, step 2: Generate the KEM cipher text and shared secret.
	cipherText, bobSharedSecret, err := peerPublicKey.KEMEncrypt(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Bob, step 3: Send the cipher text to Alice (Not shown).

	// Alice, step 3: Decrypt the KEM cipher text.
	aliceSharedSecret := alicePrivateKey.KEMDecrypt(cipherText)

	// Alice and Bob have identical values for the shared secrets.
	if bytes.Equal(aliceSharedSecret, bobSharedSecret) {
		panic("Shared secrets mismatch")
	}
}

func Example_keyExchangeUnilateralAuth() {
	// Unilaterally-Authenticated Key Exchange (UAKE)

	// Alice, step 0: Generate a long-term (static) key pair, the public
	// component of which is shared with Bob prior to the actual key exchange.
	aliceStaticPublicKey, aliceStaticPrivateKey, err := Kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Bob, step 1: Initialize the key exchange.
	//
	// WARNING: The state MUST NOT be use for more than one key exchange,
	// successful or not.
	bobState, err := aliceStaticPublicKey.NewUAKEInitiatorState(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Bob, step 2: Send the key exchange message to Alice (Not shown).

	// Alice, step 1: Generates a responder message and shared secret.
	aliceMessage, aliceSharedSecret := aliceStaticPrivateKey.UAKEResponderShared(rand.Reader, bobState.Message)

	// Alice, step 2: Send the responder message to Bob (Not shown).

	// Bob, step 3: Generate the shared secret.
	bobSharedSecret := bobState.Shared(aliceMessage)

	// Alice and Bob have identical values for the shared secrets, and Bob is
	// certain that the peer posesses aliceStaticPrivateKey.
	if bytes.Equal(aliceSharedSecret, bobSharedSecret) {
		panic("Shared secrets mismatch")
	}
}

func Example_keyExchangeMutualAuth() {
	// Authenticated Key Exchange (AKE)

	// Alice, Bob: Generate a long-term (static) key pair, for authentication,
	// the public component of which is shared with the peer prior to the
	// actual key exchange.
	aliceStaticPublicKey, aliceStaticPrivateKey, err := Kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}
	bobStaticPublicKey, bobStaticPrivateKey, err := Kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Bob, step 1: Initialize the key exchange.
	//
	// WARNING: The state MUST NOT be use for more than one key exchange,
	// successful or not.
	bobState, err := aliceStaticPublicKey.NewAKEInitiatorState(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Bob, step 2: Send the key exchange message to Alice (Not shown).

	// Alice, step 1: Generates a responder message and shared secret.
	aliceMessage, aliceSharedSecret := aliceStaticPrivateKey.AKEResponderShared(rand.Reader, bobState.Message, bobStaticPublicKey)

	// Alice, step 2: Send the responder message to Bob (Not shown).

	// Bob, step 3: Generate the shared secret.
	bobSharedSecret := bobState.Shared(aliceMessage, bobStaticPrivateKey)

	// Alice and Bob have identical values for the shared secrets, and each
	// party is certain that the peer posesses the appropriate long-term
	// private key.
	if bytes.Equal(aliceSharedSecret, bobSharedSecret) {
		panic("Shared secrets mismatch")
	}
}
