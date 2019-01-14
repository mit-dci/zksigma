package zksigma

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestABCProof(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestABCProof")
		t.Skip("Skipped TestABCProof")
	}

	sk, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	value, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	ua, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)

	PK := ZKCurve.H.Mult(sk)
	A := ZKCurve.H.Mult(ua)       // uaH
	temp := ZKCurve.G.Mult(value) // value(G)

	// A = vG + uaH
	A = A.Add(temp)
	AToken := PK.Mult(ua)

	aProof, status := NewABCProof(A, AToken, value, sk, Right)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof RIGHT failed to generate!\n")
		t.Fatalf("ABCProof RIGHT failed\n")
	}

	check, err := aProof.Verify(A, AToken)
	if !check || err != nil {
		t.Logf("ABCProof RIGHT Failed to verify!\n")
		t.Fatalf("ABCVerify RIGHT failed\n")
	}

	A = ZKCurve.H.Mult(ua)
	aProof, status = NewABCProof(A, AToken, big.NewInt(0), sk, Left)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof LEFT failed to generate!\n")
		t.Fatalf("ABCProof LEFT failed\n")
	}

	check, err = aProof.Verify(A, AToken)
	if !check || err != nil {
		t.Logf("ABCProof LEFT Failed to verify!\n")
		t.Fatalf("ABCVerify LEFT failed\n")
	}

	A, ua, err = PedCommit(big.NewInt(1000))
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	AToken = PK.Mult(ua)

	aProof, status = NewABCProof(A, AToken, big.NewInt(1001), sk, Right)

	if status != nil {
		t.Logf("False proof genereation succeeded! (bad)\n")
		t.Fatalf("ABCProve generated for false proof\n")
	}

	t.Logf("Next ABCVerify should catch false proof\n")

	check, err = aProof.Verify(A, AToken)
	if check || err == nil {
		t.Logf("ABCVerify: should have failed on false proof check!\n")
		t.Fatalf("ABCVerify: not working...\n")
	}

	fmt.Println("Passed TestABCProof")

}

func TestBreakABCProve(t *testing.T) {

	if *EVILPROOF {
		fmt.Println("Skipped TestBreakABCProve")
		t.Skip("Skipped TestBreakABCProve")
	}

	sk, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	value, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	ua, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)

	PK := ZKCurve.H.Mult(sk)
	CM := ZKCurve.H.Mult(ua)      // uaH
	temp := ZKCurve.G.Mult(value) // value(G)

	// A = vG + uaH
	CM = CM.Add(temp)
	CMTok := PK.Mult(ua)

	u1, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	u2, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	u3, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	ub, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	uc, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)

	B := ECPoint{}
	C := ECPoint{}
	CToken := ZKCurve.H.Mult(uc)

	// B = 2/v
	B = PedCommitR(new(big.Int).ModInverse(new(big.Int).Quo(big.NewInt(2), value), ZKCurve.C.Params().N), ub)

	// C = 2G + ucH, the 2 here is the big deal
	C = PedCommitR(big.NewInt(2), uc)

	disjuncAC, _ := NewDisjunctiveProof(CMTok, CM, ZKCurve.H, C.Sub(ZKCurve.G.Mult(big.NewInt(2))), uc, Right)

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
	Challenge := GenerateChallenge(ZKCurve.G.Bytes(), ZKCurve.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		B.Bytes(), C.Bytes(),
		T1X.Bytes(), T1Y.Bytes(),
		T2X.Bytes(), T2Y.Bytes())

	// j = u1 + v * c , can be though of as s1
	j := new(big.Int).Add(u1, new(big.Int).Mul(value, Challenge))
	j = new(big.Int).Mod(j, ZKCurve.C.Params().N)

	// k = u2 + inv(sk) * c
	// inv(sk)
	isk := new(big.Int).ModInverse(sk, ZKCurve.C.Params().N)
	k := new(big.Int).Add(u2, new(big.Int).Mul(isk, Challenge))
	k = new(big.Int).Mod(k, ZKCurve.C.Params().N)

	// l = u3 + (uc - v * ub) * c
	temp1 := new(big.Int).Sub(uc, new(big.Int).Mul(value, ub))
	l := new(big.Int).Add(u3, new(big.Int).Mul(temp1, Challenge))

	evilProof := &ABCProof{
		B,
		C,
		ECPoint{T1X, T1Y},
		ECPoint{T2X, T2Y},
		Challenge,
		j, k, l, CToken,
		disjuncAC}

	t.Logf("Attemping to pass malicious true proof into verification function\n")
	t.Logf("This test should throw a couple error messages in debug\n")

	check, err := evilProof.Verify(CM, CMTok)
	if check || err == nil {
		t.Logf("ABCVerify - EVIL: accepted attack input! c = 2, should fail...\n")
		t.Fatalf("ABCVerify - EVIL: failed to catch attack!\n")
	}

}

func BenchmarkABCProve_0(b *testing.B) {
	value := big.NewInt(0)

	sk, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal, err := PedCommit(value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewABCProof(CM, CMTok, value, sk, Left)
	}
}

func BenchmarkABCProve_1(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)

	sk, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal, err := PedCommit(value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewABCProof(CM, CMTok, value, sk, Right)
	}
}

func BenchmarkABCVerify_0(b *testing.B) {
	value := big.NewInt(0)

	sk, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal, err := PedCommit(value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal)
	proof, _ := NewABCProof(CM, CMTok, value, sk, Left)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		proof.Verify(CM, CMTok)
	}
}

func BenchmarkABCVerify_1(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)

	sk, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal, err := PedCommit(value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal)
	proof, _ := NewABCProof(CM, CMTok, value, sk, Right)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		proof.Verify(CM, CMTok)
	}
}
