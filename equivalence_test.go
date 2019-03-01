package zksigma

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestEquivalence(t *testing.T) {

	x, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(Base1, x)

	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(Base2, x)

	eqProof, status1 := NewEquivalenceProof(TestCurve, Base1, Result1, Base2, Result2, x)

	if status1 != nil {
		proofStatus(status1.(*errorProof))
		t.Fatalf("error code should have indicated successful proof")
	}

	check, err := eqProof.Verify(TestCurve, Base1, Result1, Base2, Result2)
	if !check || err != nil {
		t.Logf("Base1 : %v\n", Base1)
		t.Logf("Result1 : %v\n", Result1)
		t.Logf("Base2 : %v\n", Base2)
		t.Logf("Result2 : %v\n", Result2)
		t.Logf("Proof : %v \n", eqProof)
		t.Fatalf("Equivalence Proof verification failed")
	}

	t.Logf("Next comparison should fail\n")

	// Bases swapped shouldn't work
	check, err = eqProof.Verify(TestCurve, Base2, Result1, Base1, Result2)

	if check || err == nil {
		t.Logf("Base1 : %v\n", Base1)
		t.Logf("Result1 : %v\n", Result1)
		t.Logf("Base2 : %v\n", Base2)
		t.Logf("Result2 : %v\n", Result2)
		t.Logf("Proof : %v \n", eqProof)
		t.Fatalf("Equivalence Proof verification doesn't work")
	}

	t.Logf("Next comparison should fail\n")
	// Bad proof
	eqProof.HiddenValue = big.NewInt(-1)
	check, err = eqProof.Verify(TestCurve, Base2, Result1, Base1, Result2)
	if check || err == nil {
		t.Logf("Base1 : %v\n", Base1)
		t.Logf("Result1 : %v\n", Result1)
		t.Logf("Base2 : %v\n", Base2)
		t.Logf("Result2 : %v\n", Result2)
		t.Logf("Proof : %v \n", eqProof)
		t.Fatalf("Equivalence Proof verification doesn't work")
	}

	x, _ = rand.Int(rand.Reader, TestCurve.C.Params().N)
	_, status2 := NewEquivalenceProof(TestCurve, Base1, Result1, Base2, Result2, x)

	// here I check proofStatus in the else statement because I want to make sure
	// the failed case will raise an error
	if status2 == nil {
		t.Fatalf("error code should have indicated failed proof")
	} else {
		proofStatus(status2.(*errorProof))
	}

}

func TestEquivSerialization(t *testing.T) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(Base1, value)

	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(Base2, value)

	proof, _ := NewEquivalenceProof(TestCurve, Base1, Result1, Base2, Result2, value)
	proof, err := NewEquivalenceProofFromBytes(proof.Bytes())
	if err != nil {
		t.Fatalf("TestEquivSerialization failed to deserialize\n")
	}
	ok, err := proof.Verify(TestCurve, Base1, Result1, Base2, Result2)
	if !ok || err != nil {
		t.Fatalf("TestEquivSerialization failed to verify\n")
	}

}

func BenchmarkEquivProve(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(Base1, value)

	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(Base2, value)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewEquivalenceProof(TestCurve, Base1, Result1, Base2, Result2, value)
	}
}

func BenchmarkEquivVerify(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(Base1, value)

	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(Base2, value)
	proof, _ := NewEquivalenceProof(TestCurve, Base1, Result1, Base2, Result2, value)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		proof.Verify(TestCurve, Base1, Result1, Base2, Result2)
	}
}
