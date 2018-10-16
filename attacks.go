package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// Here the side is which one to lie about, chosing 0 means that c != 0 and chosing 1 means that c = 1
func BreakABCProve(CM, CMTok ECPoint, value, sk *big.Int, option side) (*ABCProof, error) {

	u1, _ := rand.Int(rand.Reader, ZKCurve.N)
	u2, _ := rand.Int(rand.Reader, ZKCurve.N)
	u3, _ := rand.Int(rand.Reader, ZKCurve.N)
	ub, _ := rand.Int(rand.Reader, ZKCurve.N)
	uc, _ := rand.Int(rand.Reader, ZKCurve.N)

	B := ECPoint{}
	C := ECPoint{}
	CToken := ZKCurve.H.Mult(uc)

	// B = 2/v
	B = PedCommitR(new(big.Int).ModInverse(new(big.Int).Quo(big.NewInt(2), value), ZKCurve.N), ub)

	// C = 2G + ucH, the 2 here is the big deal
	C = PedCommitR(big.NewInt(2), uc)

	disjuncAC, status := DisjunctiveProve(CMTok, CM, ZKCurve.H, C.Sub(ZKCurve.G.Mult(big.NewInt(2))), uc, right)

	if status != nil {
		proofStatus(status.(*errorProof))
		Dprintf("BreakABCProve: disjuncAC proof did not generate!\n")
		return &ABCProof{}, &errorProof{"BreakABCProve", "disjuncAC did not generate (good!)"}
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

	return &ABCProof{
		B,
		C,
		ECPoint{T1X, T1Y},
		ECPoint{T2X, T2Y},
		Challenge,
		j, k, l, CToken,
		disjuncAC}, nil

}
