package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// type newGSP struct {
// 	A         ECPoint
// 	B         ECPoint
// 	Val1      *big.Int
// 	Val2      *big.Int
// 	Challenge *big.Int
// }

// func newProve(CM, CMTok ECPoint, txValue *big.Int) {
// 	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
// 	PK := ZKCurve.H.Mult(sk)
// 	u1, _ := rand.Int(rand.Reader, ZKCurve.N)
// 	u2, _ := rand.Int(rand.Reader, ZKCurve.N)

// 	B1X, B1Y := ZKCurve.C.ScalarBaseMult(u1.Bytes())
// 	B2X, B2Y := ZKCurve.C.ScalarMult(PK.X, PK.Y, sk.Bytes())
// 	B := ECPoint{B1X, B1Y}.Add(ECPoint{B2X, B2Y}.Mult(u2))

// 	temp := [][]byte{ZKCurve.G.Bytes(), ZKCurve.H.Bytes(), CM.Bytes(), CMTok.Bytes(), B.Bytes(), PK.Bytes()}

// 	var bytesToHash []byte
// 	for _, v := range temp {
// 		bytesToHash = append(bytesToHash, v...)
// 	}

// 	hasher := sha256.New()
// 	hasher.Write(bytesToHash)
// 	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
// 	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

// 	// TODO: finish this proof, add in return type and stateemnt
// 	// TODO: generate the values, then figure out how to get uH from P and R
// }

/*
	ABCProof1: generate a proof that commitment C is either 0 or 1
			  depending on if we are involved in a tx. This will later
			  be used to generate a sum to preform an average calculation

	Public: G, H, CM, B, C, CMTok where
	- CM = vG + uaH // we do not know ua, only v
	- B = inv(v)G + ubH //inv is multiplicative inverse, in the case of v = 0, inv(v) = 0
	- C = (v * inv(v))G + ucH
	- CMTok = rPK = r(skH) // same r from A

	P 										V
	generate in order:
	- commitment of inv(v), B
	- commitment of v * inv(v), C // either 0 or 1 ONLY
	- Disjunctive proof of a = 0 or c = 1
	select u1, u2, u3 at random
	select ub, uc at random
	Compute:
	- T1 = u1G + u2CMTok
	- T2 = u1B + u3H
	- c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	Compute:
	- j = u1 + v * c				// can be though of as s1
	- k = u2 + inv(sk) * c			// s2
	- l = u3 + (uc - v * ub) * c 	// s3

	disjuncAC, B, C, T1, T2, c, j, k, l
								   	------->
											 disjuncAC ?= true
											 c ?= HASH(G,H,CM,CMTok,B,C,T1,T2)
											 cCM + T1 ?= jG + kCMTok
											 cC + T2 ?= jB + lH
*/

type ABCProof1 struct {
	// A         ECPoint  // fresh commit of vG without any blinding
	B         ECPoint  // commitment for b = 0 OR inv(v)
	C         ECPoint  // commitment for c = 0 OR 1 ONLY
	T1        ECPoint  // T1 = u1G + u2MTok
	T2        ECPoint  // T2 = u1B + u3H
	Challenge *big.Int //c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	j         *big.Int // j = u1 + v * c
	k         *big.Int // k = u2 + inv(sk) * c
	l         *big.Int // l = u3 + (uc - v * ub) * c
	CToken    ECPoint
	disjuncAC *DisjunctiveProof
}

// option left is proving that A and C commit to zero and simulates that A, B and C commit to v, inv(v) and 1 respectively
// option right is proving that A, B and C commit to v, inv(v) and 1 respectively and sumulating that A and C commit to 0
func ABCProve1(CM, CMTok ECPoint, value, sk *big.Int, option side) (*ABCProof1, bool) {

	// modValue := new(big.Int).Mod(value, ZKCurve.N)

	u1, err := rand.Int(rand.Reader, ZKCurve.N)
	u2, err := rand.Int(rand.Reader, ZKCurve.N)
	u3, err := rand.Int(rand.Reader, ZKCurve.N)
	ub, err := rand.Int(rand.Reader, ZKCurve.N)
	uc, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	// // v = 0
	// if modValue.Cmp(big.NewInt(0)) != 0 {
	// 	Dprintf("We are lying about value of tx and trying to generate inccorect proof")
	// 	return &ABCProof1{}, false
	// }

	B := ECPoint{}
	C := ECPoint{}
	CToken := ZKCurve.H.Mult(uc)

	disjuncAC := new(DisjunctiveProof)
	status := false
	// Disjunctive Proof of a = 0 or c = 1
	if option == left && value.Cmp(big.NewInt(0)) == 0 {
		// MUST:a = 0! ; side = left
		// B = 0 + ubH, here since we want to prove v = 0, we later accomidate for the lack of inverses
		B = PedCommitR(new(big.Int).ModInverse(big.NewInt(0), ZKCurve.N), ub)

		// C = 0 + ucH
		C = PedCommitR(big.NewInt(0), uc)

		disjuncAC, status = DisjunctiveProve(CMTok, CM, ZKCurve.H, C, sk, left) //C - G?
	} else if option == right && value.Cmp(big.NewInt(0)) != 0 {
		// MUST:c = 1! ; side = right

		B = PedCommitR(new(big.Int).ModInverse(value, ZKCurve.N), ub)

		// C = G + ucH
		C = PedCommitR(big.NewInt(1), uc)

		disjuncAC, status = DisjunctiveProve(CMTok, CM, ZKCurve.H, C.Sub(ZKCurve.G), uc, right)
	} else {
		Dprintf("ABCProof1: Side/value combination not correct\n")
		return &ABCProof1{}, false
	}

	if !status {
		Dprintf("Disjunctive Proof in ABCProof1 failed to generated!\n")
		return &ABCProof1{}, false
	}

	// CMTok is Ta for the rest of the proof
	// T1 = u1G + u2Ta
	// u1G
	u1G := ZKCurve.G.Mult(u1)
	// u2Ta
	u2Ta := CMTok.Mult(u2)
	// Sum the above two
	T1X, T1Y := ZKCurve.C.Add(u1G.X, u1G.Y, u2Ta.X, u2Ta.Y)

	// T2 = u1B + u3H
	// u1B
	u1B := B.Mult(u1)
	// u3H
	u3H := ZKCurve.H.Mult(u3)
	// Sum of the above two
	T2X, T2Y := ZKCurve.C.Add(u1B.X, u1B.Y, u3H.X, u3H.Y)

	// c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	temp := [][]byte{ZKCurve.G.Bytes(), ZKCurve.H.Bytes(), CM.Bytes(), CMTok.Bytes(), B.Bytes(), C.Bytes(), T1X.Bytes(), T1Y.Bytes(), T2X.Bytes(), T2Y.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	// j = u1 + v * c , can be though of as s1
	j := new(big.Int).Add(u1, new(big.Int).Mul(value, Challenge))
	j = new(big.Int).Mod(j, ZKCurve.N)

	// k = u2 + inv(sk) * c
	// inv(sk)
	isk := new(big.Int).ModInverse(sk, ZKCurve.N)
	k := new(big.Int).Add(u2, new(big.Int).Mul(isk, Challenge))
	k = new(big.Int).Mod(k, ZKCurve.N)

	// l = u3 + (uc - v * ub) * c
	temp1 := new(big.Int).Sub(uc, new(big.Int).Mul(value, ub))
	l := new(big.Int).Add(u3, new(big.Int).Mul(temp1, Challenge))

	return &ABCProof1{
		B,
		C,
		ECPoint{T1X, T1Y},
		ECPoint{T2X, T2Y},
		Challenge,
		j, k, l, CToken,
		disjuncAC}, true

}

/*
	proofA ?= true
	proofC ?= true
	c ?= HASH(G,H,CM,CMTok,B,C,T1,T2)
	cCM + T1 ?= jG + kCMTok
	cC + T2 ?= jB + lH
*/

func ABCVerify1(CM, CMTok ECPoint, aProof *ABCProof1) bool {

	if !DisjunctiveVerify(CMTok, CM, ZKCurve.H, aProof.C.Sub(ZKCurve.G), aProof.disjuncAC) {
		Dprintf("ABCProof1 for disjuncAC is false or not generated properly\n")
		return false
	}

	temp := [][]byte{ZKCurve.G.Bytes(), ZKCurve.H.Bytes(), CM.Bytes(), CMTok.Bytes(), aProof.B.Bytes(), aProof.C.Bytes(), aProof.T1.Bytes(), aProof.T2.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	// c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	if Challenge.Cmp(aProof.Challenge) != 0 {
		Dprintf("ABCVerify: proof contains incorrect challenge\n")
		return false
	}

	// cCM + T1 ?= jG + kCMTok
	// cCM
	chalA := CM.Mult(Challenge)
	// + T1
	lhs1 := chalA.Add(aProof.T1)
	//jG
	jG := ZKCurve.G.Mult(aProof.j)
	// kCMTok
	kCMTok := CMTok.Mult(aProof.k)
	// jG + kCMTok
	rhs1 := jG.Add(kCMTok)

	if !lhs1.Equal(rhs1) {
		Dprintf("ABCVerify: cCM + T1 != jG + kCMTok\n")
		return false
	}

	// cC + T2 ?= jB + lH
	chalC := aProof.C.Mult(Challenge)
	lhs2 := chalC.Add(aProof.T2)

	jB := aProof.B.Mult(aProof.j)
	lH := ZKCurve.H.Mult(aProof.l)
	rhs2 := jB.Add(lH)

	if !lhs2.Equal(rhs2) {
		Dprintf("ABCVerify: cC + T2 != jB + lH\n")
		return false
	}

	return true
}
