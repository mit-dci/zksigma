package zksigma

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
)

// EquivalenceProof is an Equivalence Proof. A proof that both A and B both use the
// same scalar, x.
//
//  Public: generator points G and H
//
//  Prover                              Verifier
//  ======                              ========
//  know x
//	A = xG ; B = xH						learns A, B
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
// and Result2 is the scalar multiple of base Base2 and that both results are using the same x as discrete log.
func NewEquivalenceProof(
	zkpcp ZKPCurveParams, Base1, Result1, Base2, Result2 ECPoint, x *big.Int) (*EquivalenceProof, error) {

	modValue := new(big.Int).Mod(x, zkpcp.C.Params().N)
	check1 := zkpcp.Mult(Base1, modValue)

	if !check1.Equal(Result1) {
		return nil, &errorProof{"EquivalenceProve", "Base1 and Result1 are not related by x"}
	}

	check2 := zkpcp.Mult(Base2, modValue)
	if !check2.Equal(Result2) {
		return nil, &errorProof{"EquivalenceProve", "Base2 and Result2 are not related by x"}
	}

	// random number
	u, err := rand.Int(rand.Reader, zkpcp.C.Params().N) // random number to hide x later
	if err != nil {
		return nil, err
	}

	// uG
	uBase1 := zkpcp.Mult(Base1, u)
	// uH
	uBase2 := zkpcp.Mult(Base2, u)

	// HASH(G, H, xG, xH, uG, uH)
	Challenge := GenerateChallenge(zkpcp, Base1.Bytes(), Result1.Bytes(),
		Base2.Bytes(), Result2.Bytes(),
		uBase1.Bytes(), uBase2.Bytes())

	// s = u + c * x
	HiddenValue := new(big.Int).Add(u, new(big.Int).Mul(Challenge, modValue))
	HiddenValue = HiddenValue.Mod(HiddenValue, zkpcp.C.Params().N)

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
	zkpcp ZKPCurveParams, Base1, Result1, Base2, Result2 ECPoint) (bool, error) {

	if eqProof == nil {
		return false, &errorProof{"EquivalenceVerify", fmt.Sprintf("passed proof is nil")}
	}

	// Regenerate challenge string
	c := GenerateChallenge(zkpcp, Base1.Bytes(), Result1.Bytes(),
		Base2.Bytes(), Result2.Bytes(),
		eqProof.UG.Bytes(), eqProof.UH.Bytes())

	if c.Cmp(eqProof.Challenge) != 0 {
		return false, &errorProof{"EquivalenceVerify", fmt.Sprintf("challenge comparison failed. proof: %v calculated: %v",
			eqProof.Challenge, c)}
	}

	// sG ?= uG + cA
	sG := zkpcp.Mult(Base1, eqProof.HiddenValue)
	cG := zkpcp.Mult(Result1, eqProof.Challenge)
	test := zkpcp.Add(eqProof.UG, cG)

	if !sG.Equal(test) {
		return false, &errorProof{"EquivalenceVerify", "sG comparison did not pass"}
	}

	// sH ?= uH + cB
	sH := zkpcp.Mult(Base2, eqProof.HiddenValue)
	cH := zkpcp.Mult(Result2, eqProof.Challenge)
	test = zkpcp.Add(eqProof.UH, cH)

	if !sH.Equal(test) {
		return false, &errorProof{"EquivalenceVerify", "sH comparison did not pass"}
	}

	// All three checks passed, proof must be correct
	return true, nil

}

// Bytes returns a byte slice with a serialized representation of EquivalenceProof proof
func (proof *EquivalenceProof) Bytes() []byte {
	var buf bytes.Buffer

	WriteECPoint(&buf, proof.UG)
	WriteECPoint(&buf, proof.UH)
	WriteBigInt(&buf, proof.Challenge)
	WriteBigInt(&buf, proof.HiddenValue)

	return buf.Bytes()
}

// NewEquivalenceProofFromBytes returns a EquivalenceProof generated from the
// deserialization of byte slice b
func NewEquivalenceProofFromBytes(b []byte) (*EquivalenceProof, error) {
	proof := new(EquivalenceProof)
	buf := bytes.NewBuffer(b)
	proof.UG, _ = ReadECPoint(buf)
	proof.UH, _ = ReadECPoint(buf)
	proof.Challenge, _ = ReadBigInt(buf)
	proof.HiddenValue, _ = ReadBigInt(buf)
	return proof, nil
}
