// kem_vectors_test.go - Kyber KEM test vector tests.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package kyber

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const nrTestVectors = 1000 // WARNING: Must match the reference code.

var compactTestVectors = make(map[string][]byte)

func TestKEMVectors(t *testing.T) {
	if err := loadCompactTestVectors(); err != nil {
		t.Fatalf("loadCompactTestVectors(): %v", err)
	}

	forceDisableHardwareAcceleration()
	doTestKEMVectors(t)

	if !canAccelerate {
		t.Log("Hardware acceleration not supported on this host.")
		return
	}
	mustInitHardwareAcceleration()
	doTestKEMVectors(t)
}

func doTestKEMVectors(t *testing.T) {
	impl := "_" + hardwareAccelImpl.name
	for _, p := range allParams {
		t.Run(p.Name()+impl, func(t *testing.T) { doTestKEMVectorsPick(t, p) })
	}
}

func doTestKEMVectorsPick(t *testing.T, p *ParameterSet) {
	require := require.New(t)

	// The full test vectors are gigantic, and aren't checked into the
	// git repository.
	vecs, err := loadTestVectors(p)
	if err == nil {
		// If they exist because someone generated them and placed them in
		// the correct location, use them.
		doTestKEMVectorsFull(require, p, vecs)
	} else {
		// Otherwise use the space saving representation based on comparing
		// digests.
		doTestKEMVectorsCompact(require, p)
	}
}

func doTestKEMVectorsFull(require *require.Assertions, p *ParameterSet, vecs []*vector) {
	rng := newTestRng()
	for idx, vec := range vecs {
		pk, sk, err := p.GenerateKeyPair(rng)
		require.NoError(err, "GenerateKeyPair(): %v", idx)
		require.Equal(vec.rndKP, rng.PopHist(), "randombytes() kp: %v", idx)
		require.Equal(vec.rndZ, rng.PopHist(), "randombytes() z: %v", idx)
		require.Equal(vec.pk, pk.Bytes(), "pk: %v", idx)
		require.Equal(vec.skA, sk.Bytes(), "skA: %v", idx)

		sendB, keyB, err := pk.KEMEncrypt(rng)
		require.NoError(err, "KEMEncrypt(): %v", idx)
		require.Equal(vec.rndEnc, rng.PopHist(), "randombytes() enc: %v", idx)
		require.Equal(vec.sendB, sendB, "sendB: %v", idx)
		require.Equal(vec.keyB, keyB, "keyB: %v", idx)

		keyA := sk.KEMDecrypt(sendB)
		require.Equal(vec.keyA, keyA, "keyA: %v", idx)
	}
}

func doTestKEMVectorsCompact(require *require.Assertions, p *ParameterSet) {
	h := sha256.New()

	rng := newTestRng()
	for idx := 0; idx < nrTestVectors; idx++ {
		pk, sk, err := p.GenerateKeyPair(rng)
		require.NoError(err, "GenerateKeyPair(): %v", idx)
		h.Write([]byte(hex.EncodeToString(rng.PopHist()) + "\n"))
		h.Write([]byte(hex.EncodeToString(rng.PopHist()) + "\n"))
		h.Write([]byte(hex.EncodeToString(pk.Bytes()) + "\n"))
		h.Write([]byte(hex.EncodeToString(sk.Bytes()) + "\n"))

		sendB, keyB, err := pk.KEMEncrypt(rng)
		require.NoError(err, "KEMEncrypt(): %v", idx)
		h.Write([]byte(hex.EncodeToString(rng.PopHist()) + "\n"))
		h.Write([]byte(hex.EncodeToString(sendB) + "\n"))
		h.Write([]byte(hex.EncodeToString(keyB) + "\n"))

		keyA := sk.KEMDecrypt(sendB)
		h.Write([]byte(hex.EncodeToString(keyA) + "\n"))
	}

	require.Equal(compactTestVectors[p.Name()], h.Sum(nil), "Digest mismatch")
}

func loadCompactTestVectors() error {
	f, err := os.Open(filepath.Join("testdata", "compactVectors.json"))
	if err != nil {
		return err
	}
	defer f.Close()

	rawMap := make(map[string]string)
	dec := json.NewDecoder(f)
	if err = dec.Decode(&rawMap); err != nil {
		return err
	}

	for k, v := range rawMap {
		digest, err := hex.DecodeString(v)
		if err != nil {
			return err
		}

		compactTestVectors[k] = digest
	}

	return nil
}

type vector struct {
	rndKP  []byte
	rndZ   []byte
	pk     []byte
	skA    []byte
	rndEnc []byte
	sendB  []byte
	keyB   []byte
	keyA   []byte
}

func loadTestVectors(p *ParameterSet) ([]*vector, error) {
	fn := "KEM-" + p.Name() + ".full"

	f, err := os.Open(filepath.Join("testdata", fn))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var vectors []*vector
	scanner := bufio.NewScanner(f)
	for {
		v, err := getNextVector(scanner)
		switch err {
		case nil:
			vectors = append(vectors, v)
		case io.EOF:
			return vectors, nil
		default:
			return nil, err
		}
	}
}

func getNextVector(scanner *bufio.Scanner) (*vector, error) {
	var v [][]byte

	for i := 0; i < 8; i++ {
		if ok := scanner.Scan(); !ok {
			if i == 0 {
				return nil, io.EOF
			}
			return nil, errors.New("truncated file")
		}
		b, err := hex.DecodeString(scanner.Text())
		if err != nil {
			return nil, err
		}
		v = append(v, b)
	}

	vec := &vector{
		rndKP:  v[0],
		rndZ:   v[1],
		pk:     v[2],
		skA:    v[3],
		rndEnc: v[4],
		sendB:  v[5],
		keyB:   v[6],
		keyA:   v[7],
	}

	return vec, nil
}

type testRNG struct {
	seed    [32]uint32
	in      [12]uint32
	out     [8]uint32
	outleft int

	hist [][]byte
}

func newTestRng() *testRNG {
	r := new(testRNG)
	r.seed = [32]uint32{
		3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3, 8, 4, 6, 2, 6, 4, 3, 3, 8, 3, 2, 7, 9, 5,
	}
	for i := range r.in {
		r.in[i] = 0
	}
	r.outleft = 0
	return r
}

func (r *testRNG) surf() {
	var t [12]uint32
	var sum uint32

	for i, v := range r.in {
		t[i] = v ^ r.seed[12+i]
	}
	for i := range r.out {
		r.out[i] = r.seed[24+i]
	}
	x := t[11]
	rotate := func(x uint32, b uint) uint32 {
		return (((x) << (b)) | ((x) >> (32 - (b))))
	}
	mush := func(i int, b uint) {
		t[i] += (((x ^ r.seed[i]) + sum) ^ rotate(x, b))
		x = t[i]
	}
	for loop := 0; loop < 2; loop++ {
		for rr := 0; rr < 16; rr++ {
			sum += 0x9e3779b9
			mush(0, 5)
			mush(1, 7)
			mush(2, 9)
			mush(3, 13)
			mush(4, 5)
			mush(5, 7)
			mush(6, 9)
			mush(7, 13)
			mush(8, 5)
			mush(9, 7)
			mush(10, 9)
			mush(11, 13)
		}
		for i := range r.out {
			r.out[i] ^= t[i+4]
		}
	}
}

func (r *testRNG) Read(x []byte) (n int, err error) {
	dst := x

	xlen, ret := len(x), len(x)
	for xlen > 0 {
		if r.outleft == 0 {
			r.in[0]++
			if r.in[0] == 0 {
				r.in[1]++
				if r.in[1] == 0 {
					r.in[2]++
					if r.in[2] == 0 {
						r.in[3]++
					}
				}
			}
			r.surf()
			r.outleft = 8
		}
		r.outleft--
		x[0] = byte(r.out[r.outleft])
		x = x[1:]
		xlen--
	}

	r.hist = append(r.hist, append([]byte{}, dst...))

	return ret, nil
}

func (r *testRNG) PopHist() []byte {
	if len(r.hist) == 0 {
		panic("pop underflow")
	}

	b := r.hist[0]
	r.hist = append([][]byte{}, r.hist[1:]...)

	return b
}
