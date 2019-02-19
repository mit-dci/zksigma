package zksigma

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// TestABCProof tests if the ABC Proof can generate and verify.
func TestABCProof(t *testing.T) {
	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	value, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	ua, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)

	PK := TestCurve.H.Mult(sk, TestCurve)
	A := TestCurve.H.Mult(ua, TestCurve)       // uaH
	temp := TestCurve.G.Mult(value, TestCurve) // value(G)

	// A = vG + uaH
	A = A.Add(temp, TestCurve)
	AToken := PK.Mult(ua, TestCurve)

	aProof, status := NewABCProof(TestCurve, A, AToken, value, sk, Right)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof RIGHT failed to generate!\n")
		t.Fatalf("ABCProof RIGHT failed\n")
	}

	check, err := aProof.Verify(TestCurve, A, AToken)
	if !check || err != nil {
		t.Logf("ABCProof RIGHT Failed to verify!\n")
		t.Fatalf("ABCVerify RIGHT failed\n")
	}

	A = TestCurve.H.Mult(ua, TestCurve)
	aProof, status = NewABCProof(TestCurve, A, AToken, big.NewInt(0), sk, Left)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof LEFT failed to generate!\n")
		t.Fatalf("ABCProof LEFT failed\n")
	}

	check, err = aProof.Verify(TestCurve, A, AToken)
	if !check || err != nil {
		t.Logf("ABCProof LEFT Failed to verify!\n")
		t.Fatalf("ABCVerify LEFT failed\n")
	}

	A, ua, err = PedCommit(TestCurve, big.NewInt(1000))
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	AToken = PK.Mult(ua, TestCurve)

	aProof, status = NewABCProof(TestCurve, A, AToken, big.NewInt(1001), sk, Right)

	if status != nil {
		t.Logf("False proof generation succeeded! (bad)\n")
		t.Fatalf("ABCProve generated for false proof\n")
	}

	t.Logf("Next ABCVerify should catch false proof\n")

	check, err = aProof.Verify(TestCurve, A, AToken)
	if check || err == nil {
		t.Logf("ABCVerify: should have failed on false proof check!\n")
		t.Fatalf("ABCVerify: not working...\n")
	}
}

// TestABCProofSerialization tests if the ABC Proof can generate, serialize, deserialize, and then verify.
func TestABCProofSerialization(t *testing.T) {

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	value, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	ua, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)

	PK := TestCurve.H.Mult(sk, TestCurve)
	A := TestCurve.H.Mult(ua, TestCurve)       // uaH
	temp := TestCurve.G.Mult(value, TestCurve) // value(G)

	// A = vG + uaH
	A = A.Add(temp, TestCurve)
	AToken := PK.Mult(ua, TestCurve)

	aProof, status := NewABCProof(TestCurve, A, AToken, value, sk, Right)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof RIGHT failed to generate!\n")
		t.Fatalf("ABCProof RIGHT failed\n")
	}
	aProof, status = NewABCProofFromBytes(aProof.Bytes())

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Fatalf("ABCProof failed to deserialize!\n")
	}

	check, err := aProof.Verify(TestCurve, A, AToken)
	if !check || err != nil {
		t.Fatalf("ABCVerify failed: %s\n", err.Error())
	}
}

// TestBreakABCProve tests if the ABC Proof can will catch invalid proofs.
func TestBreakABCProve(t *testing.T) {
	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	value, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	ua, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)

	PK := TestCurve.H.Mult(sk, TestCurve)
	CM := TestCurve.H.Mult(ua, TestCurve)      // uaH
	temp := TestCurve.G.Mult(value, TestCurve) // value(G)

	// A = vG + uaH
	CM = CM.Add(temp, TestCurve)
	CMTok := PK.Mult(ua, TestCurve)

	u1, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	u2, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	u3, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	ub, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	uc, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)

	B := ECPoint{}
	C := ECPoint{}
	CToken := TestCurve.H.Mult(uc, TestCurve)

	// B = 2/v
	x := new(big.Int).ModInverse(value, TestCurve.C.Params().N)
	B = PedCommitR(TestCurve, new(big.Int).Mul(big.NewInt(2), x), ub)

	// C = 2G + ucH, the 2 here is the big deal
	C = PedCommitR(TestCurve, big.NewInt(2), uc)

	disjuncAC, _ := NewDisjunctiveProof(TestCurve, CMTok, CM, TestCurve.H, C.Sub(TestCurve.G.Mult(big.NewInt(2), TestCurve), TestCurve), uc, Right)

	// CMTok is Ta for the rest of the proof
	// T1 = u1G + u2Ta
	// u1G
	u1G := TestCurve.G.Mult(u1, TestCurve)
	// u2Ta
	u2Ta := CMTok.Mult(u2, TestCurve)
	// Sum the above two
	T1X, T1Y := TestCurve.C.Add(u1G.X, u1G.Y, u2Ta.X, u2Ta.Y)

	// T2 = u1B + u3H
	// u1B
	u1B := B.Mult(u1, TestCurve)
	// u3H
	u3H := TestCurve.H.Mult(u3, TestCurve)
	// Sum of the above two
	T2X, T2Y := TestCurve.C.Add(u1B.X, u1B.Y, u3H.X, u3H.Y)

	// c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	Challenge := GenerateChallenge(TestCurve, TestCurve.G.Bytes(), TestCurve.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		B.Bytes(), C.Bytes(),
		T1X.Bytes(), T1Y.Bytes(),
		T2X.Bytes(), T2Y.Bytes())

	// j = u1 + v * c , can be though of as s1
	j := new(big.Int).Add(u1, new(big.Int).Mul(value, Challenge))
	j = new(big.Int).Mod(j, TestCurve.C.Params().N)

	// k = u2 + inv(sk) * c
	// inv(sk)
	isk := new(big.Int).ModInverse(sk, TestCurve.C.Params().N)
	k := new(big.Int).Add(u2, new(big.Int).Mul(isk, Challenge))
	k = new(big.Int).Mod(k, TestCurve.C.Params().N)

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

	t.Logf("Attempting to pass malicious true proof into verification function\n")
	t.Logf("This test should throw a couple error messages in debug\n")

	check, err := evilProof.Verify(TestCurve, CM, CMTok)
	if check || err == nil {
		t.Logf("ABCVerify - EVIL: accepted attack input! c = 2, should fail...\n")
		t.Fatalf("ABCVerify - EVIL: failed to catch attack!\n")
	}
}

func BenchmarkABCProve_0(b *testing.B) {
	value := big.NewInt(0)

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	PK := TestCurve.H.Mult(sk, TestCurve)

	CM, randVal, err := PedCommit(TestCurve, value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal, TestCurve)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewABCProof(TestCurve, CM, CMTok, value, sk, Left)
	}
}

func BenchmarkABCProve_1(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	PK := TestCurve.H.Mult(sk, TestCurve)

	CM, randVal, err := PedCommit(TestCurve, value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal, TestCurve)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewABCProof(TestCurve, CM, CMTok, value, sk, Right)
	}
}

func BenchmarkABCVerify_0(b *testing.B) {
	value := big.NewInt(0)

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	PK := TestCurve.H.Mult(sk, TestCurve)

	CM, randVal, err := PedCommit(TestCurve, value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal, TestCurve)
	proof, _ := NewABCProof(TestCurve, CM, CMTok, value, sk, Left)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		proof.Verify(TestCurve, CM, CMTok)
	}
}

func BenchmarkABCVerify_1(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	PK := TestCurve.H.Mult(sk, TestCurve)

	CM, randVal, err := PedCommit(TestCurve, value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal, TestCurve)
	proof, _ := NewABCProof(TestCurve, CM, CMTok, value, sk, Right)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		proof.Verify(TestCurve, CM, CMTok)
	}
}
