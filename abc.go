package zksigma

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"github.com/mit-dci/zksigma/wire"
)

// ABCProof is a proof that generates a proof that the relationship between three
//  scalars a, b and c is ab = c
//
//  MAPPING[a, b, c] :: [v, inv(v), c]
//
//  Public: G, H, CM, B, C, CMTok where
//  - CM = vG + uaH // we do not know ua, only v
//  - B = inv(v)G + ubH //inv is multiplicative inverse, in the case of v = 0, inv(v) = 0
//  - C = (v * inv(v))G + ucH // c = v * inv(v)
//  - CMTok = uaPK = ua(skH) // ua is r from CM
//
//  Prover									Verifier
//  ======                                  ======
//  generate in order:
//  - commitment of inv(v), B
//  - commitment of v * inv(v), C // either 0 or 1 ONLY
//  - Disjunctive proof of v = 0 or c = 1
//  select u1, u2, u3 at random
//  select ub, uc at random // ua was before proof
//  Compute:
//  - T1 = u1G + u2CMTok
//  - T2 = u1B + u3H
//  - chal = HASH(G,H,CM,CMTok,B,C,T1,T2)
//  Compute:
//  - j = u1 + v * chal
//  - k = u2 + inv(sk) * chal
//  - l = u3 + (uc - v * ub) * chal
//
//  disjuncAC, B, C, T1, T2, c, j, k, l ------->
//         									disjuncAC ?= true
//         									chal ?= HASH(G,H,CM,CMTok,B,C,T1,T2)
//         									chal*CM + T1 ?= jG + kCMTok
//         									chal*C + T2 ?= jB + lH˜
type ABCProof struct {
	B         ECPoint  // commitment for b = 0 OR inv(v)
	C         ECPoint  // commitment for c = 0 OR 1 ONLY
	T1        ECPoint  // T1 = u1G + u2MTok
	T2        ECPoint  // T2 = u1B + u3H
	Challenge *big.Int // chal = HASH(G,H,CM,CMTok,B,C,T1,T2)
	j         *big.Int // j = u1 + v * chal
	k         *big.Int // k = u2 + inv(sk) * chal
	l         *big.Int // l = u3 + (uc - v * ub) * chal
	CToken    ECPoint
	disjuncAC *DisjunctiveProof
}

// NewABCProof generates a proof that the relationship between three scalars a,b and c is ab = c,
// in commitments A, B and C respectively.
// Option Left is proving that A and C commit to zero and simulates that A, B and C commit to v, inv(v) and 1 respectively.
// Option Right is proving that A, B and C commit to v, inv(v) and 1 respectively and simulating that A and C commit to 0.
func NewABCProof(zkpcp ZKPCurveParams, CM, CMTok ECPoint, value, sk *big.Int, option Side) (*ABCProof, error) {

	// We cannot check that CM log is actually the value, but the verification should catch that

	u1, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}
	u2, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}

	u3, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}

	ub, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}
	uc, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}

	B := ECPoint{}
	C := ECPoint{}
	CToken := zkpcp.Mult(zkpcp.Mult(zkpcp.H, sk), uc)

	var disjuncAC *DisjunctiveProof
	var e error
	// Disjunctive Proof of a = 0 or c = 1
	if option == Left && value.Cmp(BigZero) == 0 {
		// MUST: a = 0! ; side = left
		// No inverse if value=0; set B to 0.  Do we confirm somewhere else that a=0?
		B = PedCommitR(zkpcp, big.NewInt(0), ub)

		// C = 0 + ucH
		C = PedCommitR(zkpcp, big.NewInt(0), uc)

		// CM is considered the "base" of CMTok since it would be only uaH and not ua sk H
		// C - G is done regardless of the c = 0 or 1 because in the case c = 0 it does matter what that random number is
		disjuncAC, e = NewDisjunctiveProof(zkpcp, CM, CMTok, zkpcp.H, zkpcp.Sub(C, zkpcp.G), sk, Left)
	} else if option == Right && value.Cmp(BigZero) != 0 {
		// MUST: c = 1! ; side = right

		B = PedCommitR(zkpcp, new(big.Int).ModInverse(value, zkpcp.C.Params().N), ub)

		// C = G + ucH
		C = PedCommitR(zkpcp, big.NewInt(1), uc)

		// Look at notes a couple lines above on what the input is like this
		disjuncAC, e = NewDisjunctiveProof(zkpcp, CM, CMTok, zkpcp.H, zkpcp.Sub(C, zkpcp.G), uc, Right)
	} else {
		return &ABCProof{}, &errorProof{"ABCProof", "invalid side-value pair passed"}
	}

	if e != nil {
		return &ABCProof{}, &errorProof{"ABCProof", "disjunctiveProve within ABCProve failed to generate"}
	}

	// CMTok is Ta for the rest of the proof
	// T1 = u1G + u2Ta
	// u1G
	u1G := zkpcp.Mult(zkpcp.G, u1)
	// u2Ta
	u2Ta := zkpcp.Mult(CMTok, u2)
	// Sum the above two
	T1 := zkpcp.Add(u1G, u2Ta)

	// T2 = u1B + u3H
	// u1B
	u1B := zkpcp.Mult(B, u1)
	// u3H
	u3H := zkpcp.Mult(zkpcp.H, u3)
	// Sum of the above two
	T2 := zkpcp.Add(u1B, u3H)

	// chal = HASH(G,H,CM,CMTok,B,C,T1,T2)
	Challenge := GenerateChallenge(zkpcp, zkpcp.G.Bytes(), zkpcp.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		B.Bytes(), C.Bytes(),
		T1.Bytes(), T2.Bytes())

	// j = u1 + v * chal
	j := new(big.Int).Add(u1, new(big.Int).Mul(value, Challenge))
	j = new(big.Int).Mod(j, zkpcp.C.Params().N)

	// k = u2 + inv(sk) * chal
	// inv(sk)
	isk := new(big.Int).ModInverse(sk, zkpcp.C.Params().N)
	k := new(big.Int).Add(u2, new(big.Int).Mul(isk, Challenge))
	k = new(big.Int).Mod(k, zkpcp.C.Params().N)

	// l = u3 + (uc - v * ub) * chal
	temp1 := new(big.Int).Sub(uc, new(big.Int).Mul(value, ub))
	l := new(big.Int).Add(u3, new(big.Int).Mul(temp1, Challenge))

	return &ABCProof{
		B,
		C,
		T1,
		T2,
		Challenge,
		j, k, l, CToken,
		disjuncAC}, nil

}

// Verify checks if ABCProof aProof with appropriate commits CM and CMTok is correct
func (aProof *ABCProof) Verify(zkpcp ZKPCurveParams, CM, CMTok ECPoint) (bool, error) {

	// Notes in ABCProof talk about why the Disjunc takes in this specific input even though it looks non-intuitive
	// Here it is important that you subtract exactly 1 G from the aProof.C because that only allows for you to prove c = 1!
	_, status := aProof.disjuncAC.Verify(zkpcp, CM, CMTok, zkpcp.H, zkpcp.Sub(aProof.C, zkpcp.G))

	if status != nil {
		return false, &errorProof{"ABCVerify", "ABCProof for disjuncAC is false or not generated properly"}
	}

	Challenge := GenerateChallenge(zkpcp, zkpcp.G.Bytes(), zkpcp.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		aProof.B.Bytes(), aProof.C.Bytes(),
		aProof.T1.Bytes(), aProof.T2.Bytes())

	// chal = HASH(G,H,CM,CMTok,B,C,T1,T2)
	if Challenge.Cmp(aProof.Challenge) != 0 {
		return false, &errorProof{"ABCVerify", "proof contains incorrect challenge"}
	}

	// chalCM + T1 ?= jG + kCMTok
	// chalCM
	chalA := zkpcp.Mult(CM, Challenge)
	// + T1
	lhs1 := zkpcp.Add(chalA, aProof.T1)
	//jG
	jG := zkpcp.Mult(zkpcp.G, aProof.j)
	// kCMTok
	kCMTok := zkpcp.Mult(CMTok, aProof.k)
	// jG + kCMTok
	rhs1 := zkpcp.Add(jG, kCMTok)

	if !lhs1.Equal(rhs1) {
		return false, &errorProof{"ABCProof", "cCM + T1 != jG + kCMTok"}
	}

	// cC + T2 ?= jB + lH
	chalC := zkpcp.Mult(aProof.C, Challenge)
	lhs2 := zkpcp.Add(chalC, aProof.T2)

	jB := zkpcp.Mult(aProof.B, aProof.j)
	lH := zkpcp.Mult(zkpcp.H, aProof.l)
	rhs2 := zkpcp.Add(jB, lH)

	if !lhs2.Equal(rhs2) {
		return false, &errorProof{"ABCVerify", "cC + T2 != jB + lH"}
	}

	return true, nil
}

// Bytes returns a byte slice with a serialized representation of ABCProof proof
func (proof *ABCProof) Bytes() []byte {
	var buf bytes.Buffer

	WriteECPoint(&buf, proof.B)
	WriteECPoint(&buf, proof.C)
	WriteECPoint(&buf, proof.T1)
	WriteECPoint(&buf, proof.T2)
	WriteBigInt(&buf, proof.Challenge)
	WriteBigInt(&buf, proof.j)
	WriteBigInt(&buf, proof.k)
	WriteBigInt(&buf, proof.l)
	WriteECPoint(&buf, proof.CToken)
	wire.WriteVarBytes(&buf, proof.disjuncAC.Bytes())

	return buf.Bytes()
}

// NewABCProofFromBytes returns an ABCProof generated from the deserialization of
// byte slice b
func NewABCProofFromBytes(b []byte) (*ABCProof, error) {
	proof := new(ABCProof)
	buf := bytes.NewBuffer(b)
	var err error
	proof.B, err = ReadECPoint(buf)
	if err != nil {
		return nil, err
	}
	proof.C, err = ReadECPoint(buf)
	if err != nil {
		return nil, err
	}
	proof.T1, err = ReadECPoint(buf)
	if err != nil {
		return nil, err
	}
	proof.T2, err = ReadECPoint(buf)
	if err != nil {
		return nil, err
	}
	proof.Challenge, err = ReadBigInt(buf)
	if err != nil {
		return nil, err
	}
	proof.j, err = ReadBigInt(buf)
	if err != nil {
		return nil, err
	}
	proof.k, err = ReadBigInt(buf)
	if err != nil {
		return nil, err
	}
	proof.l, err = ReadBigInt(buf)
	if err != nil {
		return nil, err
	}
	proof.CToken, err = ReadECPoint(buf)
	if err != nil {
		return nil, err
	}
	disjuncBytes, err := wire.ReadVarBytes(buf, 100000, "disjunctProof")
	if err != nil {
		return nil, err
	}
	proof.disjuncAC, err = NewDisjunctiveProofFromBytes(disjuncBytes)
	if err != nil {
		return nil, err
	}
	return proof, nil
}
