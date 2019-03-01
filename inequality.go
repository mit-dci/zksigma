package zksigma

import (
	"fmt"
	"math/big"
)

type InequalityProof ABCProof

// InequalityProve generates a proof to show that two commitments, A and B, are not equal
// Given two commitments A and B that we know the values for - a and b respectively - we
// can prove that a != b without needed any new commitments, just generate a proof
// There is no Inequality verify since this generates an ABCProof, so just use ABCVerify
func NewInequalityProof(zkpcp ZKPCurveParams, A, B, CMTokA, CMTokB ECPoint, a, b, sk *big.Int) (*InequalityProof, error) {

	if a.Cmp(b) == 0 {
		return nil, &errorProof{"InequalityProve", "a and b should not be equal..."}
	}

	// should I check if a > b? I think that shouldn't be a problem
	// generate a-b for ABCProof, D will be created  commitment
	value := new(big.Int).Sub(a, b)
	CM := zkpcp.Sub(A, B)

	CMTok := zkpcp.Sub(CMTokA, CMTokB)

	proof, proofStatus := NewABCProof(zkpcp, CM, CMTok, value, sk, Right)

	if proofStatus != nil {
		return nil, proofStatus
	}

	return ((*InequalityProof)(proof)), proofStatus
}

// Verify checks if InequalityProof ieProof with appropriate commits CM and CMTok is correct
func (ieProof *InequalityProof) Verify(zkpcp ZKPCurveParams, CM, CMTok ECPoint) (bool, error) {
	if ieProof == nil {
		return false, &errorProof{"InequalityProof.Verify", fmt.Sprintf("passed proof is nil")}
	}

	return ((*ABCProof)(ieProof)).Verify(zkpcp, CM, CMTok)
}
