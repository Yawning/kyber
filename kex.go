// kex.go - Kyber key exchange.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

import (
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrInvalidMessageSize is the error thrown via a panic when a initator
	// or responder message is an invalid size.
	ErrInvalidMessageSize = errors.New("kyber: invalid message size")

	// ErrParameterSetMismatch is the error thrown via a panic when there
	// is a mismatch between parameter sets.
	ErrParameterSetMismatch = errors.New("kyber: parameter set mismatch")
)

// UAKEInitiatorMessageSize returns the size of the initiator UAKE message
// in bytes.
func (p *ParameterSet) UAKEInitiatorMessageSize() int {
	return p.PublicKeySize() + p.CipherTextSize()
}

// UAKEResponderMessageSize returns the size of the responder UAKE message
// in bytes.
func (p *ParameterSet) UAKEResponderMessageSize() int {
	return p.CipherTextSize()
}

// UAKEInitiatorState is a initiator UAKE instance.  Each instance MUST only
// be used for one key exchange and never reused.
type UAKEInitiatorState struct {
	// Message is the UAKE message to send to the responder.
	Message []byte

	eSk *PrivateKey
	tk  []byte
}

// Shared generates a shared secret for the given UAKE instance and responder
// message.
//
// On failures, sharedSecret will contain a randomized value.  Providing a
// cipher text that is obviously malformed (too large/small) will result in a
// panic.
func (s *UAKEInitiatorState) Shared(recv []byte) (sharedSecret []byte) {
	xof := sha3.NewShake256()
	var tk []byte

	tk = s.eSk.KEMDecrypt(recv)
	xof.Write(tk)
	xof.Write(s.tk)
	sharedSecret = make([]byte, SymSize)
	xof.Read(sharedSecret)

	return
}

// NewUAKEInitiatorState creates a new initiator UAKE instance.
func (pk *PublicKey) NewUAKEInitiatorState(rng io.Reader) (*UAKEInitiatorState, error) {
	s := new(UAKEInitiatorState)
	s.Message = make([]byte, 0, pk.p.UAKEInitiatorMessageSize())

	var err error
	_, s.eSk, err = pk.p.GenerateKeyPair(rng)
	if err != nil {
		return nil, err
	}
	s.Message = append(s.Message, s.eSk.PublicKey.Bytes()...)

	var ct []byte
	ct, s.tk, err = pk.KEMEncrypt(rng)
	if err != nil {
		return nil, err
	}

	s.Message = append(s.Message, ct...)

	return s, nil
}

// UAKEResponderShared generates a responder message and shared secret given
// a initiator UAKE message.
//
// On failures, sharedSecret will contain a randomized value.  Providing a
// cipher text that is obviously malformed (too large/small) will result in a
// panic.
func (sk *PrivateKey) UAKEResponderShared(rng io.Reader, recv []byte) (message, sharedSecret []byte) {
	p := sk.PublicKey.p
	pkLen := p.PublicKeySize()

	// Deserialize the peer's ephemeral public key.
	if len(recv) != p.UAKEInitiatorMessageSize() {
		panic(ErrInvalidMessageSize)
	}
	rawPk, ct := recv[:pkLen], recv[pkLen:]
	pk, err := p.PublicKeyFromBytes(rawPk)
	if err != nil {
		panic(err)
	}

	xof := sha3.NewShake256()
	var tk []byte

	message, tk, err = pk.KEMEncrypt(rng)
	if err != nil {
		panic(err)
	}
	xof.Write(tk)

	tk = sk.KEMDecrypt(ct)
	xof.Write(tk)
	sharedSecret = make([]byte, SymSize)
	xof.Read(sharedSecret)

	return
}

// AKEInitiatorMessageSize returns the size of the initiator AKE message
// in bytes.
func (p *ParameterSet) AKEInitiatorMessageSize() int {
	return p.PublicKeySize() + p.CipherTextSize()
}

// AKEResponderMessageSize returns the size of the responder AKE message
// in bytes.
func (p *ParameterSet) AKEResponderMessageSize() int {
	return 2 * p.CipherTextSize()
}

// AKEInitiatorState is a initiator AKE instance.  Each instance MUST only be
// used for one key exchange and never reused.
type AKEInitiatorState struct {
	// Message is the AKE message to send to the responder.
	Message []byte

	eSk *PrivateKey
	tk  []byte
}

// Shared generates a shared secret for the given AKE instance, responder
// message, and long term initiator private key.
//
// On failures sharedSecret will contain a randomized value.   Providing a
// malformed responder message, or a private key that uses a different
// ParamterSet than the AKEInitiatorState will result in a panic.
func (s *AKEInitiatorState) Shared(recv []byte, initiatorPrivateKey *PrivateKey) (sharedSecret []byte) {
	p := s.eSk.PublicKey.p

	if initiatorPrivateKey.PublicKey.p != p {
		panic(ErrParameterSetMismatch)
	}
	if len(recv) != p.AKEResponderMessageSize() {
		panic(ErrInvalidMessageSize)
	}
	ctLen := p.CipherTextSize()

	xof := sha3.NewShake256()
	var tk []byte

	tk = s.eSk.KEMDecrypt(recv[:ctLen])
	xof.Write(tk)

	tk = initiatorPrivateKey.KEMDecrypt(recv[ctLen:])
	xof.Write(tk)

	xof.Write(s.tk)
	sharedSecret = make([]byte, SymSize)
	xof.Read(sharedSecret)

	return
}

// NewAKEInitiatorState creates a new initiator AKE instance.
func (pk *PublicKey) NewAKEInitiatorState(rng io.Reader) (*AKEInitiatorState, error) {
	s := new(AKEInitiatorState)

	// This is identical to the UAKE case, so just reuse the code.
	us, err := pk.NewUAKEInitiatorState(rng)
	if err != nil {
		return nil, err
	}

	s.Message = us.Message
	s.eSk = us.eSk
	s.tk = us.tk

	return s, nil
}

// AKEResponderShared generates a responder message and shared secret given
// a initiator AKE message and long term initiator public key.
//
// On failures sharedSecret will contain a randomized value.   Providing a
// malformed responder message, or a private key that uses a different
// ParamterSet than the AKEInitiatorState will result in a panic.
func (sk *PrivateKey) AKEResponderShared(rng io.Reader, recv []byte, peerPublicKey *PublicKey) (message, sharedSecret []byte) {
	p := sk.PublicKey.p
	pkLen := p.PublicKeySize()

	if peerPublicKey.p != p {
		panic(ErrParameterSetMismatch)
	}

	// Deserialize the peer's ephemeral public key.
	if len(recv) != p.AKEInitiatorMessageSize() {
		panic(ErrInvalidMessageSize)
	}
	rawPk, ct := recv[:pkLen], recv[pkLen:]
	pk, err := p.PublicKeyFromBytes(rawPk)
	if err != nil {
		panic(err)
	}

	message = make([]byte, 0, p.AKEResponderMessageSize())

	xof := sha3.NewShake256()
	var tk, tmp []byte

	tmp, tk, err = pk.KEMEncrypt(rng)
	if err != nil {
		panic(err)
	}
	xof.Write(tk)
	message = append(message, tmp...)

	tmp, tk, err = peerPublicKey.KEMEncrypt(rng)
	if err != nil {
		panic(err)
	}
	xof.Write(tk)
	message = append(message, tmp...)

	tk = sk.KEMDecrypt(ct)
	xof.Write(tk)
	sharedSecret = make([]byte, SymSize)
	xof.Read(sharedSecret)

	return
}
