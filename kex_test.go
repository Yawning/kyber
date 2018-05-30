// kex_test.go - Kyber key exchange tests.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAKE(t *testing.T) {
	forceDisableHardwareAcceleration()
	doTestKEX(t)

	if !canAccelerate {
		t.Log("Hardware acceleration not supported on this host.")
		return
	}
	mustInitHardwareAcceleration()
	doTestKEX(t)
}

func doTestKEX(t *testing.T) {
	impl := "_" + hardwareAccelImpl.name
	for _, p := range allParams {
		t.Run(p.Name()+"_UAKE"+impl, func(t *testing.T) { doTestUAKE(t, p) })
		t.Run(p.Name()+"_AKE"+impl, func(t *testing.T) { doTestAKE(t, p) })
	}
}

func doTestUAKE(t *testing.T, p *ParameterSet) {
	require := require.New(t)

	t.Logf("UAKEInitiatorMessageSize(): %v", p.UAKEInitiatorMessageSize())
	t.Logf("UAKEResponderMessageSize(): %v", p.UAKEResponderMessageSize())

	for i := 0; i < nTests; i++ {
		// Generate the responder key pair.
		pkB, skB, err := p.GenerateKeyPair(rand.Reader)
		require.NoError(err, "GenerateKeyPair()")

		// Create the initiator state.
		stateA, err := pkB.NewUAKEInitiatorState(rand.Reader)
		require.NoError(err, "NewUAKEInitiatorState()")
		require.Len(stateA.Message, p.UAKEInitiatorMessageSize(), "stateA.Message: Length")

		// Create the responder message and shared secret.
		msgB, ssB := skB.UAKEResponderShared(rand.Reader, stateA.Message)
		require.Len(msgB, p.UAKEResponderMessageSize(), "UAKEResponderShared(): msgB Length")
		require.Len(ssB, SymSize, "UAKEResponderShared(): ssB Length")

		// Create the initiator shared secret.
		ssA := stateA.Shared(msgB)
		require.Equal(ssA, ssB, "Shared secret mismatch")
	}
}

func doTestAKE(t *testing.T, p *ParameterSet) {
	require := require.New(t)

	t.Logf("AKEInitiatorMessageSize(): %v", p.AKEInitiatorMessageSize())
	t.Logf("AKEResponderMessageSize(): %v", p.AKEResponderMessageSize())

	for i := 0; i < nTests; i++ {
		// Generate the initiator and responder key pairs.
		pkB, skB, err := p.GenerateKeyPair(rand.Reader)
		require.NoError(err, "GenerateKeyPair(): Responder")

		pkA, skA, err := p.GenerateKeyPair(rand.Reader)
		require.NoError(err, "GenerateKeyPair(): Initiator")

		// Create the initiator state.
		stateA, err := pkB.NewAKEInitiatorState(rand.Reader)
		require.NoError(err, "NewAKEInitiatorState()")
		require.Len(stateA.Message, p.AKEInitiatorMessageSize(), "stateA.Message: Length")

		// Create the responder message and shared secret.
		msgB, ssB := skB.AKEResponderShared(rand.Reader, stateA.Message, pkA)
		require.Len(msgB, p.AKEResponderMessageSize(), "AKEResponderShared(): msgB Length")
		require.Len(ssB, SymSize, "AKEResponderShared(): ssB Length")

		// Create the initiator shared secret.
		ssA := stateA.Shared(msgB, skA)
		require.Equal(ssA, ssB, "Shared secret mismatch")
	}
}
