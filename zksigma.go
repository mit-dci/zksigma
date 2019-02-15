/*
**WARNING: zkSigma is research code and should not be used with sensitive data.  It definitely has bugs!**

zkSigma is a library for generating non-interactive zero-knowledge proofs, also known as NIZKs. The proofs in zkSigma are based on Generalized Schnorr Proofs; they can be publicly verified and do not require any trusted setup.

Features:

* Generating non-interactive zero-knowledge proofs for various logical statements

* Simplified elliptic curve operations

* Plug and Play API

More info on Github
*/
package zksigma

import (
	"crypto/sha256"
	"math/big"

	"github.com/mit-dci/zksigma/btcec"
)

// Side is an enum to pick what side of the proof you want to generate
type Side int

const (
	// Left generates the left side of a proof
	Left Side = 0
	// Right generates the right side of a proof
	Right Side = 1
)

// TestCurve is a global cache for the curve and two generator points used in the test cases.
// It is equal to ZKLedger's curve - but for abstraction the actual curve parameters are
// passed into the proof functions. We just test with the same params that ZKLedger uses.
var TestCurve ZKPCurveParams

func generateH2tothe() []ECPoint {
	Hslice := make([]ECPoint, 64)
	for i := range Hslice {
		m := big.NewInt(1 << uint(i))
		Hslice[i].X, Hslice[i].Y = TestCurve.C.ScalarBaseMult(m.Bytes())
	}
	return Hslice
}

func init() {
	s256 := sha256.New()
	hashedString := s256.Sum([]byte("This is the new random point in zksigma"))
	HX, HY := btcec.S256().ScalarMult(btcec.S256().Gx, btcec.S256().Gy, hashedString)
	TestCurve = ZKPCurveParams{
		C: btcec.S256(),
		G: ECPoint{btcec.S256().Gx, btcec.S256().Gy},
		H: ECPoint{HX, HY},
	}
	TestCurve.HPoints = generateH2tothe()
}
