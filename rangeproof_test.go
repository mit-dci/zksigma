package zksigma

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// Copy-pasted from original apl implementation by Willy (github.com/wrv)
func TestRangeProver_Verify(t *testing.T) {
	value, _ := rand.Int(rand.Reader, big.NewInt(1099511627775))
	proof, rp, err := NewRangeProof(value)
	if err != nil {
		t.Fatalf("TestRangeProver_Verify failed to generate proof\n")
	}
	comm := PedCommitR(value, rp)
	if !comm.Equal(proof.ProofAggregate) {
		t.Error("Error computing the randomnesses used -- commitments did not check out when supposed to")
	} else {
		ok, err := proof.Verify(comm)
		if !ok {
			t.Errorf("** Range proof failed: %s", err)
		} else {

		}
	}
}

func TestRangeProverSerialization(t *testing.T) {
	value, _ := rand.Int(rand.Reader, big.NewInt(1099511627775))
	proof, rp, err := NewRangeProof(value)
	if err != nil {
		t.Fatalf("TestRangeProverSerialization failed to generate proof\n")
	}
	proof, err = NewRangeProofFromBytes(proof.Bytes())
	if err != nil {
		t.Fatalf("TestRangeProverSerialization failed to deserialize\n")
	}
	comm := PedCommitR(value, rp)
	if !comm.Equal(proof.ProofAggregate) {
		t.Error("Error computing the randomnesses used -- commitments did not check out when supposed to")
	} else {
		ok, err := proof.Verify(comm)
		if !ok {
			t.Errorf("** Range proof failed: %s", err)
		} else {

		}
	}
}

func TestOutOfRangeRangeProver_Verify(t *testing.T) {
	min := new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(64), nil)

	value, err := rand.Int(rand.Reader, new(big.Int).Add(new(big.Int).Sub(ZKCurve.C.Params().N, min), min)) // want to make sure it's out of range
	if err != nil {
		t.Error(err)
	}

	_, _, err = NewRangeProof(value)
	if err == nil {
		t.Error("Computing the range proof shouldn't work but it did")
	}
}
