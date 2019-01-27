package zksigma

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
)

// ConsistencyProof is similar to EquivalenceProof except that we
// make some assumptions about the public info. Here we want to prove
// that the r used in CM and Y are the same.
//
//	Public:
//  - generator points G and H,
//  - PK (pubkey) = skH, // sk is secret key
//  - CM (commitment) = vG + rH
//  - CMTok = rPK
//
//  Prover									Verifier
//  ======                                  ========
//  selects v and r for commitment          knows CM = vG + rH; CMTok = rPK
//  selects random u1, u2
//  T1 = u1G + u2H
//  T2 = u2PK
//  c = HASH(G, H, T1, T2, PK, CM, CMTok)
//  s1 = u1 + c * v
//  s2 = u2 + c * r
//
//  T1, T2, c, s1, s2 ----------------->
//                                          c ?= HASH(G, H, T1, T2, PK, CM, CMTok)
//                                          s1G + s2H ?= T1 + cCM
//                                          s2PK ?= T2 + cCMTok
type ConsistencyProof struct {
	T1        ECPoint
	T2        ECPoint
	Challenge *big.Int
	s1        *big.Int
	s2        *big.Int
}

// NewConsistencyProof generates a proof that the r used in CM(=xG+rH)
// and CMTok(=r(sk*H)) are the same.
func NewConsistencyProof(
	CM, CMTok, PubKey ECPoint, value, randomness *big.Int) (*ConsistencyProof, error) {
	// Base1and Base2 will most likely be G and H, Result1 and Result2 will be xG and xH
	// x trying to be proved that both G and H are raised with x

	modValue := new(big.Int).Mod(value, ZKCurve.C.Params().N)
	//modRandom := new(big.Int).Mod(randomness, ZKCurve.C.Params().N)

	// do a quick correctness check to ensure the value we are testing and the
	// randomness are correct
	if !CM.Equal(PedCommitR(value, randomness)) {
		return &ConsistencyProof{}, &errorProof{"ConsistencyProve", "value and randomVal does not produce CM"}
	}

	if !CMTok.Equal(PubKey.Mult(randomness)) {
		return &ConsistencyProof{}, &errorProof{"ConsistencyProve", "Pubkey and randomVal does not produce CMTok"}
	}

	u1, err := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	if err != nil {
		return nil, err
	}
	u2, err := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	if err != nil {
		return nil, err
	}

	T1 := PedCommitR(u1, u2)
	T2 := PubKey.Mult(u2)

	Challenge := GenerateChallenge(ZKCurve.G.Bytes(), ZKCurve.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		PubKey.Bytes(),
		T1.Bytes(), T2.Bytes())

	s1 := new(big.Int).Add(u1, new(big.Int).Mul(modValue, Challenge))
	s2 := new(big.Int).Add(u2, new(big.Int).Mul(randomness, Challenge))
	s1.Mod(s1, ZKCurve.C.Params().N)
	s2.Mod(s2, ZKCurve.C.Params().N) // this was s1 instead of s2, took me an hour to find...

	return &ConsistencyProof{T1, T2, Challenge, s1, s2}, nil

}

// Verify checks if a ConsistencyProof conProof is valid
func (conProof *ConsistencyProof) Verify(
	CM, CMTok, PubKey ECPoint) (bool, error) {

	if conProof == nil {
		return false, &errorProof{"ConsistencyProof.Verify", fmt.Sprintf("passed proof is nil")}
	}

	// CM should be point1, Y should be point2

	// Regenerate challenge string
	Challenge := GenerateChallenge(ZKCurve.G.Bytes(), ZKCurve.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		PubKey.Bytes(),
		conProof.T1.Bytes(), conProof.T2.Bytes())

	// c ?= HASH(G, H, T1, T2, PK, CM, Y)
	if Challenge.Cmp(conProof.Challenge) != 0 {
		return false, &errorProof{"ConsistencyVerify", fmt.Sprintf("c comparison failed. proof: %v calculated: %v",
			conProof.Challenge, Challenge)}
	}
	// lhs = left hand side, rhs = right hand side
	// s1G + s2H ?= T1 + cCM, CM should be point1
	// s1G + s2H from how PedCommitR works
	lhs := PedCommitR(conProof.s1, conProof.s2)
	// cCM
	temp1 := CM.Mult(Challenge)
	// T1 + cCM
	rhs := conProof.T1.Add(temp1)

	if !lhs.Equal(rhs) {
		return false, &errorProof{"ConsistencyVerify", "CM check is failing"}
	}

	// s2PK ?= T2 + cY
	lhs = PubKey.Mult(conProof.s2)
	temp1 = CMTok.Mult(Challenge)
	rhs = conProof.T2.Add(temp1)

	if !lhs.Equal(rhs) {
		return false, &errorProof{"ConsistencyVerify", "CMTok check is failing"}
	}

	// All three checks passed, proof must be correct
	return true, nil
}

func (proof *ConsistencyProof) Bytes() []byte {
	var buf bytes.Buffer

	WriteECPoint(&buf, proof.T1)
	WriteECPoint(&buf, proof.T2)
	WriteBigInt(&buf, proof.Challenge)
	WriteBigInt(&buf, proof.s1)
	WriteBigInt(&buf, proof.s2)

	return buf.Bytes()
}

func NewConsistencyProofFromBytes(b []byte) (*ConsistencyProof, error) {
	proof := new(ConsistencyProof)
	buf := bytes.NewBuffer(b)
	proof.T1, _ = ReadECPoint(buf)
	proof.T2, _ = ReadECPoint(buf)
	proof.Challenge, _ = ReadBigInt(buf)
	proof.s1, _ = ReadBigInt(buf)
	proof.s2, _ = ReadBigInt(buf)
	return proof, nil
}
