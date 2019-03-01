package zksigma

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
)

// GSPFSProof is proof of knowledge of x in commitment A(=xG)
// GSPFS is Generalized Schnorr Proofs with Fiat-Shamir transform.
//
//  Public: generator points G and H
//
//  Prover                              Verifier
//  ======                              ========
//  know x
// 	A = xG								learns A
//  selects random u
//  T1 = uG
//  c = HASH(G, xG, uG)
//  s = u + c * x
//
//  T1, s, c -------------------------->
//                                      c ?= HASH(G, A, T1)
//                                      sG ?= T1 + cA
type GSPFSProof struct {
	Base        ECPoint  // Base point
	RandCommit  ECPoint  // this is H = uG, where u is random value and G is a generator point
	HiddenValue *big.Int // s = x * c + u, here c is the challenge and x is what we want to prove knowledge of
	Challenge   *big.Int // challenge string hash sum, only use for sanity checks
}

// NewGSPFSProof generates a Schnorr proof for the value x using the
// first ZKCurve base point. It checks if the passed A is indeed
// value x multiplied by the generator point.
func NewGSPFSProof(zkpcp ZKPCurveParams, A ECPoint, x *big.Int) (*GSPFSProof, error) {
	return NewGSPFSProofBase(zkpcp, zkpcp.G, A, x)
}

// NewGSPFSProofBase is the same as NewGSPFSProof, except it allows you to specify
// your own base point in parameter base, instead of using the first base point from zkpcp.
func NewGSPFSProofBase(zkpcp ZKPCurveParams, base, A ECPoint, x *big.Int) (*GSPFSProof, error) {
	modValue := new(big.Int).Mod(x, zkpcp.C.Params().N)

	// A = xG, G is any base point in this proof
	cX, cY := zkpcp.C.ScalarMult(base.X, base.Y, modValue.Bytes())
	C := ECPoint{cX, cY}
	if !C.Equal(A) {
		return nil, &errorProof{"GSPFSProve:", "the point given is not xG"}
	}

	u, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}

	// generate random point uG
	uG := zkpcp.Mult(base, u)

	// generate hashed string challenge
	c := GenerateChallenge(zkpcp, A.Bytes(), uG.Bytes())

	// v = u - c * x
	v := new(big.Int).Sub(u, new(big.Int).Mul(c, modValue))
	v = v.Mod(v, zkpcp.C.Params().N)

	return &GSPFSProof{base, uG, v, c}, nil
}

// Verify (GSPFSVerify) checks if GSPFSProof proof is a valid proof for commitment A
func (proof *GSPFSProof) Verify(zkpcp ZKPCurveParams, A ECPoint) (bool, error) {

	if proof == nil {
		return false, &errorProof{"GSPFSProof.Verify", fmt.Sprintf("passed proof is nil")}
	}

	// A = xG and RandCommit = uG
	testC := GenerateChallenge(zkpcp, A.Bytes(), proof.RandCommit.Bytes())

	if testC.Cmp(proof.Challenge) != 0 {
		return false, &errorProof{"GSPFSProof.Verify", "calculated challenge and proof's challenge do not agree!"}
	}

	// (u - c * x)G, look at HiddenValue from GSPFS.Proof()
	s := zkpcp.Mult(proof.Base, proof.HiddenValue)

	// cResult = c(xG), we use testC as that follows the proof verficaion process more closely than using Challenge
	c := zkpcp.Mult(A, proof.Challenge)

	// cxG + (u - cx)G = uG
	tot := zkpcp.Add(s, c)

	if !proof.RandCommit.Equal(tot) {
		return false, &errorProof{"GSPFSProof.Verify", "proof's final value and verification final value do not agree!"}
	}
	return true, nil
}

// Bytes returns a byte slice with a serialized representation of GSPFSProof proof
func (proof *GSPFSProof) Bytes() []byte {
	var buf bytes.Buffer

	WriteECPoint(&buf, proof.Base)
	WriteECPoint(&buf, proof.RandCommit)
	WriteBigInt(&buf, proof.HiddenValue)
	WriteBigInt(&buf, proof.Challenge)

	return buf.Bytes()
}

// NewGSPFSProofFromBytes returns a GSPFSProof generated from the
// deserialization of byte slice b
func NewGSPFSProofFromBytes(b []byte) (*GSPFSProof, error) {
	proof := new(GSPFSProof)
	buf := bytes.NewBuffer(b)
	proof.Base, _ = ReadECPoint(buf)
	proof.RandCommit, _ = ReadECPoint(buf)
	proof.HiddenValue, _ = ReadBigInt(buf)
	proof.Challenge, _ = ReadBigInt(buf)
	return proof, nil
}
