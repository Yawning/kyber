// params.go - Kyber parameterization.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

const (
	// SymSize is the size of the shared key (and certain internal parameters
	// such as hashes and seeds) in bytes.
	SymSize = 32

	kyberN = 256
	kyberQ = 7681

	polySize           = 416
	polyCompressedSize = 96

	compressedCoeffSize = 352
)

var (
	// Kyber512 is the Kyber-512 parameter set, which aims to provide security
	// equivalent to AES-128.
	//
	// This parameter set has a 1632 byte private key, 736 byte public key,
	// and a 800 byte cipher text.
	Kyber512 = newParameterSet("Kyber-512", 2)

	// Kyber768 is the Kyber-768 parameter set, which aims to provide security
	// equivalent to AES-192.
	//
	// This parameter set has a 2400 byte private key, 1088 byte public key,
	// and a 1152 byte cipher text.
	Kyber768 = newParameterSet("Kyber-768", 3)

	// Kyber1024 is the Kyber-1024 parameter set, which aims to provide
	// security equivalent to AES-256.
	//
	// This parameter set has a 3168 byte private key, 1440 byte public key,
	// and a 1504 byte cipher text.
	Kyber1024 = newParameterSet("Kyber-1024", 4)
)

// ParameterSet is a Kyber parameter set.
type ParameterSet struct {
	name string

	k   int
	eta int

	polyVecSize           int
	polyVecCompressedSize int

	indcpaMsgSize       int
	indcpaPublicKeySize int
	indcpaSecretKeySize int
	indcpaSize          int

	publicKeySize  int
	secretKeySize  int
	cipherTextSize int
}

// Name returns the name of a given ParameterSet.
func (p *ParameterSet) Name() string {
	return p.name
}

// PublicKeySize returns the size of a public key in bytes.
func (p *ParameterSet) PublicKeySize() int {
	return p.publicKeySize
}

// PrivateKeySize returns the size of a private key in bytes.
func (p *ParameterSet) PrivateKeySize() int {
	return p.secretKeySize
}

// CipherTextSize returns the size of a cipher text in bytes.
func (p *ParameterSet) CipherTextSize() int {
	return p.cipherTextSize
}

func newParameterSet(name string, k int) *ParameterSet {
	var p ParameterSet

	p.name = name
	p.k = k
	switch k {
	case 2:
		p.eta = 5
	case 3:
		p.eta = 4
	case 4:
		p.eta = 3
	default:
		panic("kyber: k must be in {2,3,4}")
	}

	p.polyVecSize = k * polySize
	p.polyVecCompressedSize = k * compressedCoeffSize

	p.indcpaMsgSize = SymSize
	p.indcpaPublicKeySize = p.polyVecCompressedSize + SymSize
	p.indcpaSecretKeySize = p.polyVecSize
	p.indcpaSize = p.polyVecCompressedSize + polyCompressedSize

	p.publicKeySize = p.indcpaPublicKeySize
	p.secretKeySize = p.indcpaSecretKeySize + p.indcpaPublicKeySize + 2*SymSize // 32 bytes of additional space to save H(pk)
	p.cipherTextSize = p.indcpaSize

	return &p
}
