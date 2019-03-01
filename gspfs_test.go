package zksigma

import (
	"crypto/rand"
	"testing"
)

func TestGSPFS(t *testing.T) {

	x, err := rand.Int(rand.Reader, TestCurve.C.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	// MUST use G here because of GSPFSProve implementation
	result := TestCurve.Mult(TestCurve.G, x)

	testProof, err := NewGSPFSProof(TestCurve, result, x)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	status, err := testProof.Verify(TestCurve, result)
	if !status && err == nil {
		t.Logf("x : %v\n", x)
		t.Logf("randPoint : %v\n", result)
		t.Logf("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof didn't generate properly - 1\n")
	}

	// Using H here should break the proof
	result = TestCurve.Mult(TestCurve.H, x)

	t.Logf("Next GSPFSVerify should fail\n")
	status, err = testProof.Verify(TestCurve, result)
	if status && err != nil {
		t.Logf("x : %v\n", x)
		t.Logf("randPoint : %v\n", result)
		t.Logf("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof should not have worked - 2\n")
	}

}

func TestGSPFSSerialization(t *testing.T) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base := TestCurve.G
	CM := TestCurve.Mult(TestCurve.G, value)
	proof, err := NewGSPFSProofBase(TestCurve, Base, CM, value)
	proof, err = NewGSPFSProofFromBytes(proof.Bytes())
	if err != nil {
		t.Fatalf("TestGSPFSSerialization failed to deserialize\n")
	}
	ok, err := proof.Verify(TestCurve, CM)
	if !ok || err != nil {
		t.Fatalf("TestGSPFSSerialization failed to verify\n")
	}

}

func BenchmarkGSPFS_AnyBase(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base := TestCurve.G
	CM := TestCurve.Mult(TestCurve.G, value)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewGSPFSProofBase(TestCurve, Base, CM, value)
	}
}

func BenchmarkGSPFS_Verify(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base := TestCurve.G
	CM := TestCurve.Mult(TestCurve.G, value)
	proof, err := NewGSPFSProofBase(TestCurve, Base, CM, value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	for ii := 0; ii < b.N; ii++ {
		proof.Verify(TestCurve, CM)
	}
}
