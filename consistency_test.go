package zksigma

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestConsistency(t *testing.T) {
	x, err := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	sk, err := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	pk := ZKCurve.H.Mult(sk)

	comm, u, err := PedCommit(x)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	y := pk.Mult(u)

	conProof, status1 := NewConsistencyProof(comm, y, pk, x, u)

	if status1 != nil {
		t.Fatalf("TestConsistency - incorrect error message for correct proof, case 1\n")
	}

	t.Logf(" [testing] Testing correct consistency proof\n")
	check, err := conProof.Verify(comm, y, pk)
	if !check || err != nil {
		t.Fatalf("Error -- Proof should be correct\n")
	}

	t.Logf(" [testing] Next proof should fail\n")

	_, status2 := NewConsistencyProof(y, comm, pk, x, u)

	if status2 == nil {
		t.Fatalf("TestConsistency - incorrect error message for correct proof, case 2\n")
	}

	fmt.Println("Passed TestConsistency")
}

func BenchmarkConsistencyProve(b *testing.B) {
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
		NewConsistencyProof(CM, CMTok, PK, value, randVal)
	}
}

func BenchmarkConsistencyVerify(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)

	sk, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal, err := PedCommit(value)
	if err != nil {
		b.Fatalf("%v\n", err)
	}

	CMTok := PK.Mult(randVal)
	proof, _ := NewConsistencyProof(CM, CMTok, PK, value, randVal)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		proof.Verify(CM, CMTok, PK)
	}
}
