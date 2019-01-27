package zksigma

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// EquivalenceProof is an Equivalence Proof. A proof that both A and B both use the same x as a discrete log
//
//  Public: generator points G and H
//
//  Prover                              Verifier
//  ======                              ========
//  know x                              knows A = xG ; B = xH
//  selects random u
//  T1 = uG
//  T2 = uH
//  c = HASH(G, H, xG, xH, uG, uH)
//  s = u + c * x
//
//  T1, T2, s, c ---------------------->
//                                      c ?= HASH(G, H, A, B, T1, T2)
//                                      sG ?= T1 + cA
//                                      sH ?= T2 + cB
type EquivalenceProof struct {
	UG          ECPoint  // uG is the scalar mult of u (random num) with base G
	UH          ECPoint  // uH is the scalar mult of u (random num) with base H
	Challenge   *big.Int // Challenge is hash sum of challenge commitment
	HiddenValue *big.Int // Hidden Value hides the discrete log x that we want to prove equivalence for
}

// NewEquivalenceProof generates an equivalence proof that Result1 is the scalar multiple of base Base1,
// and Result2 is the scalar multiple of base Base2. Both using the same x as discrete log.
func NewEquivalenceProof(
	Base1, Result1, Base2, Result2 ECPoint, x *big.Int) (*EquivalenceProof, error) {
	// Base1and Base2 will most likely be G and H, Result1 and Result2 will be xG and xH
	// x trying to be proved that both G and H are raised with x


	modValue := new(big.Int).Mod(x, ZKCurve.C.Params().N)
	check1 := Base1.Mult(modValue)

	if !check1.Equal(Result1) {
		return nil, &errorProof{"EquivalenceProve", "Base1 and Result1 are not related by x"}
	}

	check2 := Base2.Mult(modValue)
	if !check2.Equal(Result2) {
		return nil, &errorProof{"EquivalenceProve", "Base2 and Result2 are not related by x"}
	}

	// random number
	u, err := rand.Int(rand.Reader, ZKCurve.C.Params().N) // random number to hide x later
	if err != nil {
		return nil, err
	}

	// uG
	uBase1 := Base1.Mult(u)
	// uH
	uBase2 := Base2.Mult(u)

	// HASH(G, H, xG, xH, uG, uH)
	Challenge := GenerateChallenge(Base1.Bytes(), Result1.Bytes(),
		Base2.Bytes(), Result2.Bytes(),
		uBase1.Bytes(), uBase2.Bytes())

	// s = u + c * x
	HiddenValue := new(big.Int).Add(u, new(big.Int).Mul(Challenge, modValue))
	HiddenValue = HiddenValue.Mod(HiddenValue, ZKCurve.C.Params().N)

	return &EquivalenceProof{
		uBase1, // uG
		uBase2, // uH
		Challenge,
		HiddenValue}, nil

}

// Verify checks if EquivalenceProof eqProof is a valid proof that Result1 is
// the scalar multiple of base Base1, and Result2 is the scalar multiple of base
// Base2. Both using the same x as discrete log.
func (eqProof *EquivalenceProof) Verify(
	Base1, Result1, Base2, Result2 ECPoint) (bool, error) {

	if eqProof == nil {
		return false, &errorProof{"EquivalenceVerify", fmt.Sprintf("passed proof is nil")}
	}

	// Regenerate challenge string
	c := GenerateChallenge(Base1.Bytes(), Result1.Bytes(),
		Base2.Bytes(), Result2.Bytes(),
		eqProof.UG.Bytes(), eqProof.UH.Bytes())

	if c.Cmp(eqProof.Challenge) != 0 {
		return false, &errorProof{"EquivalenceVerify", fmt.Sprintf("challenge comparison failed. proof: %v calculated: %v",
			eqProof.Challenge, c)}
	}

	// sG ?= uG + cA
	sG := Base1.Mult(eqProof.HiddenValue)
	cG := Result1.Mult(eqProof.Challenge)
	test := eqProof.UG.Add(cG)

	if !sG.Equal(test) {
		return false, &errorProof{"EquivalenceVerify", "sG comparison did not pass"}
	}

	// sH ?= uH + cB
	sH := Base2.Mult(eqProof.HiddenValue)
	cH := Result2.Mult(eqProof.Challenge)
	test = eqProof.UH.Add(cH)

	if !sH.Equal(test) {
		return false, &errorProof{"EquivalenceVerify", "sH comparison did not pass"}
	}

	// All three checks passed, proof must be correct
	return true, nil

}
