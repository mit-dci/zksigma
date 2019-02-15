package zksigma

import (
	"crypto/rand"
	"testing"
)

func TestConsistency(t *testing.T) {
	x, err := rand.Int(rand.Reader, TestCurve.C.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	sk, err := rand.Int(rand.Reader, TestCurve.C.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	pk := TestCurve.H.Mult(sk, TestCurve)

	comm, u, err := PedCommit(TestCurve, x)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	y := pk.Mult(u, TestCurve)

	conProof, status1 := NewConsistencyProof(TestCurve, comm, y, pk, x, u)

	if status1 != nil {
		t.Fatalf("TestConsistency - incorrect error message for correct proof, case 1\n")
	}

	t.Logf(" [testing] Testing correct consistency proof\n")
	check, err := conProof.Verify(TestCurve, comm, y, pk)
	if !check || err != nil {
		t.Fatalf("Error -- Proof should be correct\n")
	}

	t.Logf(" [testing] Next proof should fail\n")

	_, status2 := NewConsistencyProof(TestCurve, y, comm, pk, x, u)

	if status2 == nil {
		t.Fatalf("TestConsistency - incorrect error message for correct proof, case 2\n")
	}
}

func TestConsistencySerialization(t *testing.T) {
	x, err := rand.Int(rand.Reader, TestCurve.C.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	sk, err := rand.Int(rand.Reader, TestCurve.C.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	pk := TestCurve.H.Mult(sk, TestCurve)

	comm, u, err := PedCommit(TestCurve, x)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	y := pk.Mult(u, TestCurve)

	conProof, status1 := NewConsistencyProof(TestCurve, comm, y, pk, x, u)

	if status1 != nil {
		t.Fatalf("TestConsistency - incorrect error message for correct proof, case 1\n")
	}

	conProof, status1 = NewConsistencyProofFromBytes(conProof.Bytes())
	if status1 != nil {
		t.Fatalf("TestConsistency - failed to deserialize \n")
	}
	t.Logf(" [testing] Testing correct consistency proof\n")
	check, err := conProof.Verify(TestCurve, comm, y, pk)
	if !check || err != nil {
		t.Fatalf("Error -- Proof should be correct\n")
	}
}

func BenchmarkConsistencyProve(b *testing.B) {
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
		NewConsistencyProof(TestCurve, CM, CMTok, PK, value, randVal)
	}
}

func BenchmarkConsistencyVerify(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)

	sk, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	PK := TestCurve.H.Mult(sk, TestCurve)

	CM, randVal, err := PedCommit(TestCurve, value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal, TestCurve)
	proof, _ := NewConsistencyProof(TestCurve, CM, CMTok, PK, value, randVal)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		proof.Verify(TestCurve, CM, CMTok, PK)
	}
}
