package zksigma

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestInequalityProve(t *testing.T) {

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	a, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic range"
	b, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic range"
	A, ua, err := PedCommit(TestCurve, a)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	B, ub, err := PedCommit(TestCurve, b)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	PK := TestCurve.Mult(TestCurve.H, sk)

	// Even though we generated the values for ua and ub in this test case, we do not
	// need to know ua or ub, only the commitment tokens are needed
	CMTokA := TestCurve.Mult(PK, ua)
	CMTokB := TestCurve.Mult(PK, ub)

	aProof, status := NewInequalityProof(TestCurve, A, B, CMTokA, CMTokB, a, b, sk)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof for InequalityProve failed to generate!\n")
		t.Fatalf("ABCProof for InequalityProve failed\n")
	}

	check, err := aProof.Verify(TestCurve, TestCurve.Sub(A, B), TestCurve.Sub(CMTokA, CMTokB))
	if !check || err != nil {
		t.Logf("ABCProof for InequalityProve failed to verify!\n")
		t.Fatalf("ABCVerify for InequalityProve failed\n")
	}

	// Swapped positions of commitments, tokens and values, should work just fine
	aProof, status = NewInequalityProof(TestCurve, B, A, CMTokB, CMTokA, b, a, sk)

	if status != nil {
		proofStatus(status.(*errorProof))
		t.Logf("ABCProof for InequalityProve failed to generate!\n")
		t.Fatalf("ABCProof for InequalityProve failed\n")
	}

	check, err = aProof.Verify(TestCurve, TestCurve.Sub(B, A), TestCurve.Sub(CMTokB, CMTokA))
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

	check, err = aProof.Verify(TestCurve, TestCurve.Sub(A, B), TestCurve.Sub(CMTokA, CMTokB))
	if check || err == nil {
		t.Logf("ABCProof for InequalityProve failed to verify!\n")
		t.Fatalf("ABCVerify for InequalityProve failed\n")
	}

}

func BenchmarkInequalityProve(b *testing.B) {

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	a, _ := rand.Int(rand.Reader, big.NewInt(10000000000))      // "realistic range"
	bValue, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic range"
	A, ua, err := PedCommit(TestCurve, a)

	if err != nil {
		b.Fatalf("%v\n", err)
	}

	B, ub, err := PedCommit(TestCurve, bValue)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	PK := TestCurve.Mult(TestCurve.H, sk)

	// even though we generated the values for ua and ub in this test case, we do not
	// need to know ua or ub, only the commitment tokens, which is already used in many other proofs
	CMTokA := TestCurve.Mult(PK, ua)
	CMTokB := TestCurve.Mult(PK, ub)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewInequalityProof(TestCurve, A, B, CMTokA, CMTokB, a, bValue, sk)
	}
}
