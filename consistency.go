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
//  - PK (pubkey) = skH // sk = secret key
//  - CM (commitment) = vG + rH
//  - CMTok = rPK
//
//  Prover									Verifier
//  ======                                  ========
//  selects v and r for commitments
//  CM = vG + rH; CMTok = rPK				learns CM, CMTok
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
	S1        *big.Int // s1 - but capitalized to allow access from outside of zksigma
	S2        *big.Int // s2 - but capitalized to allow access from outside of zksigma
}

// NewConsistencyProof generates a proof that the r used in CM(=xG+rH)
// and CMTok(=r(sk*H)) are the same.
func NewConsistencyProof(zkpcp ZKPCurveParams,
	CM, CMTok, PubKey ECPoint, value, randomness *big.Int) (*ConsistencyProof, error) {

	modValue := new(big.Int).Mod(value, zkpcp.C.Params().N)
	//modRandom := new(big.Int).Mod(randomness, zkpcp.C.Params().N)

	// do a quick correctness check to ensure the value we are testing and the
	// randomness are correct
	if !CM.Equal(PedCommitR(zkpcp, value, randomness)) {
		return &ConsistencyProof{}, &errorProof{"ConsistencyProve", "value and randomVal does not produce CM"}
	}

	if !CMTok.Equal(zkpcp.Mult(PubKey, randomness)) {
		return &ConsistencyProof{}, &errorProof{"ConsistencyProve", "Pubkey and randomVal does not produce CMTok"}
	}

	u1, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}
	u2, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}

	T1 := PedCommitR(zkpcp, u1, u2)
	T2 := zkpcp.Mult(PubKey, u2)

	Challenge := GenerateChallenge(zkpcp, zkpcp.G.Bytes(), zkpcp.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		PubKey.Bytes(),
		T1.Bytes(), T2.Bytes())

	s1 := new(big.Int).Add(u1, new(big.Int).Mul(modValue, Challenge))
	s2 := new(big.Int).Add(u2, new(big.Int).Mul(randomness, Challenge))

	s1.Mod(s1, zkpcp.C.Params().N)
	s2.Mod(s2, zkpcp.C.Params().N)

	conProof := &ConsistencyProof{T1, T2, Challenge, s1, s2}

	return conProof, nil

}

// Verify checks if a ConsistencyProof conProof is valid
func (conProof *ConsistencyProof) Verify(
	zkpcp ZKPCurveParams, CM, CMTok, PubKey ECPoint) (bool, error) {

	if conProof == nil {
		return false, &errorProof{"ConsistencyProof.Verify", fmt.Sprintf("passed proof is nil")}
	}

	// Regenerate challenge string
	Challenge := GenerateChallenge(zkpcp, zkpcp.G.Bytes(), zkpcp.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		PubKey.Bytes(),
		conProof.T1.Bytes(), conProof.T2.Bytes())

	// c ?= HASH(G, H, T1, T2, PK, CM, Y)
	if Challenge.Cmp(conProof.Challenge) != 0 {
		return false, &errorProof{"ConsistencyVerify", fmt.Sprintf("c comparison failed. proof: %v calculated: %v",
			conProof.Challenge, Challenge)}
	}
	// lhs :: left hand side, rhs :: right hand side
	// s1G + s2H ?= T1 + cCM, CM should be point1
	// s1G + s2H from how PedCommitR works
	lhs := PedCommitR(zkpcp, conProof.S1, conProof.S2)
	// cCM
	temp1 := zkpcp.Mult(CM, Challenge)
	// T1 + cCM
	rhs := zkpcp.Add(conProof.T1, temp1)

	if !lhs.Equal(rhs) {
		return false, &errorProof{"ConsistencyVerify", "CM check is failing"}
	}

	// s2PK ?= T2 + cY
	lhs = zkpcp.Mult(PubKey, conProof.S2)
	temp1 = zkpcp.Mult(CMTok, Challenge)
	rhs = zkpcp.Add(conProof.T2, temp1)

	if !lhs.Equal(rhs) {
		return false, &errorProof{"ConsistencyVerify", "CMTok check is failing"}
	}

	// All three checks passed, proof must be correct
	return true, nil
}

// Bytes returns a byte slice with a serialized representation of ConsistencyProof proof
func (proof *ConsistencyProof) Bytes() []byte {
	var buf bytes.Buffer

	WriteECPoint(&buf, proof.T1)
	WriteECPoint(&buf, proof.T2)
	WriteBigInt(&buf, proof.Challenge)
	WriteBigInt(&buf, proof.S1)
	WriteBigInt(&buf, proof.S2)

	return buf.Bytes()
}

// NewConsistencyProofFromBytes returns a ConsistencyProof generated from the
// deserialization of byte slice b
func NewConsistencyProofFromBytes(b []byte) (*ConsistencyProof, error) {
	proof := new(ConsistencyProof)
	buf := bytes.NewBuffer(b)
	proof.T1, _ = ReadECPoint(buf)
	proof.T2, _ = ReadECPoint(buf)
	proof.Challenge, _ = ReadBigInt(buf)
	proof.S1, _ = ReadBigInt(buf)
	proof.S2, _ = ReadBigInt(buf)
	return proof, nil
}
