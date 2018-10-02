package zkSigma

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

// Copy-pasted from origianl apl implementation by Willy (github.com/wrv)
func TestRangeProver_Verify(t *testing.T) {
	value, err := rand.Int(rand.Reader, new(big.Int).SetInt64(1099511627775))
	//	value, err := rand.Int(rand.Reader, new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(64), ec.N)) // 2^64 should be big enough for any value
	if err != nil {
		t.Error(err)
	}
	proof, rp := RangeProverProve(value)
	comm := PedCommitR(value, rp)
	if !comm.Equal(proof.ProofAggregate) {
		t.Error("Error computing the randomnesses used -- commitments did not check out when supposed to")
	} else if !RangeProverVerify(comm, proof) {
		t.Error("** Range proof failed")
	} else {
		fmt.Println("Passed TestRangeProver_Verify")
	}
}

func TestOutOfRangeRangeProver_Verify(t *testing.T) {

	min := new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(64), nil)

	value, err := rand.Int(rand.Reader, new(big.Int).Add(new(big.Int).Sub(ZKCurve.N, min), min)) // want to make sure it's out of range
	if err != nil {
		t.Error(err)
	}

	proof, rp := RangeProverProve(value)
	if proof != nil || rp != nil {
		t.Error("Error computing the range proof; shouldn't work")
	} else {
		fmt.Println("Passed TestOutOfRangeProver_Verify")
	}
}
