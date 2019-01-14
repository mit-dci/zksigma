package zksigma

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestGSPFS(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestGSPFS")
		t.Skip("Skipped TestGSPFS")
	}

	x, err := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	// MUST use G here becuase of GSPFSProve implementation
	result := ZKCurve.G.Mult(x)

	testProof, err := NewGSPFSProof(result, x)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	status, err := testProof.Verify(result)
	if !status && err == nil {
		t.Logf("x : %v\n", x)
		t.Logf("randPoint : %v\n", result)
		t.Logf("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof didnt generate properly - 1\n")
	}

	// Using H here should break the proof
	result = ZKCurve.H.Mult(x)

	t.Logf("Next GSPFSVerify should fail\n")
	status, err = testProof.Verify(result)
	if status && err != nil {
		t.Logf("x : %v\n", x)
		t.Logf("randPoint : %v\n", result)
		t.Logf("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof should not have worked - 2\n")
	}

	fmt.Println("Passed TestGSPFS")

}

func BenchmarkGSPFS_AnyBase(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	Base := ZKCurve.G
	CM := ZKCurve.G.Mult(value)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewGSPFSProofBase(Base, CM, value)
	}
}

func BenchmarkGSPFS_Verify(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	Base := ZKCurve.G
	CM := ZKCurve.G.Mult(value)
	proof, err := NewGSPFSProofBase(Base, CM, value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	for ii := 0; ii < b.N; ii++ {
		proof.Verify(CM)
	}
}
