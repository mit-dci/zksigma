package zksigma

import "math/big"

type InequalityProof ABCProof

// InequalityProve generates a proof to show that two commitments, A and B, are not equal
// Given two commitments A and B that we know the values for - a and b respectively - we
// can prove that a != b without needed any new commitments, just generate a proof
// There is no Inequality verify since this generates an ABCProof, so just use ABCVerify
func NewInequalityProof(A, B, CMTokA, CMTokB ECPoint, a, b, sk *big.Int) (*InequalityProof, error) {

	if a.Cmp(b) == 0 {
		return nil, &errorProof{"InequalityProve", "a and b should not be equal..."}
	}

	// should I check if a > b? I think that shouldn't be a problem
	// generate a-b for ABCProof, D will be created  commitment
	value := new(big.Int).Sub(a, b)
	CM := A.Sub(B)

	CMTok := CMTokA.Sub(CMTokB)

	proof, proofStatus := NewABCProof(CM, CMTok, value, sk, Right)

	if proofStatus != nil {
		return nil, proofStatus
	}

	return ((*InequalityProof)(proof)), proofStatus
}

// Verify checks if InequalityProof ieProof with appropriate commits CM and CMTok is correct
func (ieProof *InequalityProof) Verify(CM, CMTok ECPoint) (bool, error) {
	return ((*ABCProof)(ieProof)).Verify(CM, CMTok)
}
