package zksigma

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestInequalityProve(t *testing.T) {

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	a, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	b, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	A, ua, err := PedCommit(TestCurve, a)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	B, ub, err := PedCommit(TestCurve, b)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	PK := TestCurve.H.Mult(sk, TestCurve)

	// Even though we generated the values for ua and ub in this test case, we do not
	// need to know ua or ub, only the commitment tokens are needed, which is already
	// used in many other proofs
	CMTokA := PK.Mult(ua, TestCurve)
	CMTokB := PK.Mult(ub, TestCurve)

	aProof, status := NewInequalityProof(TestCurve, A, B, CMTokA, CMTokB, a, b, sk)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof for InequalityProve failed to generate!\n")
		t.Fatalf("ABCProof for InequalityProve failed\n")
	}

	check, err := aProof.Verify(TestCurve, A.Sub(B, TestCurve), CMTokA.Sub(CMTokB, TestCurve))
	if !check || err != nil {
		t.Logf("ABCProof for InequalityProve failed to verify!\n")
		t.Fatalf("ABCVerify for InequalityProve failed\n")
	}

	// Swapped positions of commitments, tokens and values, will work just fine
	aProof, status = NewInequalityProof(TestCurve, B, A, CMTokB, CMTokA, b, a, sk)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof for InequalityProve failed to generate!\n")
		t.Fatalf("ABCProof for InequalityProve failed\n")
	}

	check, err = aProof.Verify(TestCurve, B.Sub(A, TestCurve), CMTokB.Sub(CMTokA, TestCurve))
	if !check || err != nil {
		t.Logf("ABCProof for InequalityProve failed to verify!\n")
		t.Fatalf("ABCVerify for InequalityProve failed\n")
	}

	// Mismatched commitments and values, a proof does generate but the
	// verification step will catch the false proof.
	// Use the -debug1 flag to see this in action
	aProof, status = NewInequalityProof(TestCurve, A, B, CMTokA, CMTokB, b, a, sk)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof for InequalityProve failed to generate!\n")
		t.Fatalf("ABCProof for InequalityProve failed\n")
	}

	check, err = aProof.Verify(TestCurve, A.Sub(B, TestCurve), CMTokA.Sub(CMTokB, TestCurve))
	if check || err == nil {
		t.Logf("ABCProof for InequalityProve failed to verify!\n")
		t.Fatalf("ABCVerify for InequalityProve failed\n")
	}

}

func BenchmarkInequalityProve(b *testing.B) {

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	a, _ := rand.Int(rand.Reader, big.NewInt(10000000000))      // "realistic rarnge"
	bValue, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	A, ua, err := PedCommit(TestCurve, a)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	B, ub, err := PedCommit(TestCurve, bValue)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	PK := TestCurve.H.Mult(sk, TestCurve)

	// even though we generated the values for ua and ub in this test case, we do not
	// need to know ua or ub, only the commitment tokens, which is already used in many other proofs
	CMTokA := PK.Mult(ua, TestCurve)
	CMTokB := PK.Mult(ub, TestCurve)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewInequalityProof(TestCurve, A, B, CMTokA, CMTokB, a, bValue, sk)
	}
}
