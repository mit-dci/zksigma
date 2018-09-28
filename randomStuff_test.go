package zkSigma

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestABCProof1(t *testing.T) {

	if ZKCurve.C == nil {
		Init()
	}

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	value, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	ua, _ := rand.Int(rand.Reader, ZKCurve.N)

	PK := ZKCurve.H.Mult(sk)
	A := PK.Mult(ua)              // ua * (sk * H)
	temp := ZKCurve.G.Mult(value) // value(G); ZKCurve.C.ScalarBaseMult(value.Bytes())

	// A = vG + ua (sk * H)
	A.X, A.Y = ZKCurve.C.Add(A.X, A.Y, temp.X, temp.Y)
	AToken := PK.Mult(ua) //ZKCurve.H.Mult(ua), where can I get uaH?

	// // C = G + uc * H
	// C, uc := PedCommit(big.NewInt(1))
	// CToken := ZKCurve.H.Mult(uc)

	aProof, status := ABCProve1(A, AToken, value, sk, right)

	if !status {
		Dprintf("ABCProof1 failed to generate!\n")
		fmt.Printf("aProof: \n\n %v \n\n", aProof)
		t.Fatalf("ABCProof1 failed\n")
	}

	if !ABCVerify1(A, AToken, aProof) {
		Dprintf("Proof Failed to verify!\n")
		Dprintf("aProof: \n\n %v \n\n", aProof)
		t.Fatalf("ABCVerify1 failed\n")
	}

	fmt.Println("TestABCProof1 Passed")

}
