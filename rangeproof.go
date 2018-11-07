package zksigma

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"math/big"
	"sync"
)

var RANGE = flag.Bool("range", false, "Run rangeproof test cases")

// The following was copy-pasted from zkLedger's original implementation by Willy (github.com/wrv)
// TODO: replace rangeproofs of zkLedger with bulletproofs, eventually

///////////////////////
// RANGE PROOFS

type RangeProofTuple struct {
	C ECPoint
	S *big.Int
}

type RangeProof struct {
	ProofAggregate ECPoint
	ProofE         *big.Int
	ProofTuples    []RangeProofTuple
}

type ProverInternalData struct {
	Rpoints  []ECPoint
	Bpoints  []ECPoint
	kScalars []*big.Int
	vScalars []*big.Int
}

// ProofGenA takes in a waitgroup, index and bit
// returns an Rpoint and Cpoint, and the k value bigint
func ProofGenA(
	wg *sync.WaitGroup, idx int, bit bool, s *ProverInternalData) error {

	defer wg.Done()
	var err error

	//	R := s.Rpoints[idx]
	//	B := s.Bpoints[idx]
	//	k := stuff.kScalars[index]
	//	v := stuff.vScalars[index]

	if !bit { // If bit is 0, just make a random R = k*H
		s.kScalars[idx], err = rand.Int(rand.Reader, ZKCurve.C.Params().N) // random k
		if err != nil {
			return err
		}
		s.Rpoints[idx] = ZKCurve.H.Mult(s.kScalars[idx]) // R is k * H
	} else { // if bit is 1, actually do stuff

		// get a random ri
		s.vScalars[idx], err = rand.Int(rand.Reader, ZKCurve.C.Params().N)
		if err != nil {
			return err
		}
		// get R as H*ri... what is KC..?
		s.Rpoints[idx] = ZKCurve.H.Mult(s.vScalars[idx])

		// B is htothe[index] plus partial R
		s.Bpoints[idx].X, s.Bpoints[idx].Y =
			ZKCurve.C.Add(HPoints[idx].X, HPoints[idx].Y,
				s.Rpoints[idx].X, s.Rpoints[idx].Y)

			// random k
		s.kScalars[idx], err = rand.Int(rand.Reader, ZKCurve.C.Params().N)
		if err != nil {
			return err
		}

		// make k*H for hashing
		temp := ZKCurve.H.Mult(s.kScalars[idx])

		// Hash of temp point (why the whole thing..?
		hash := sha256.Sum256(append(temp.X.Bytes(), temp.Y.Bytes()...))
		ei := new(big.Int).SetBytes(hash[:])
		ei.Mod(ei, ZKCurve.C.Params().N)
		s.Rpoints[idx].X, s.Rpoints[idx].Y =
			ZKCurve.C.ScalarMult(s.Bpoints[idx].X, s.Bpoints[idx].Y, ei.Bytes())
	}
	//	fmt.Printf("loop %d\n", idx)

	return nil
}

// ProofGenB takes waitgroup, index, bit, along with the data to operate on
func ProofGenB(
	wg *sync.WaitGroup, idx int, bit bool, e0 *big.Int, data *ProverInternalData) error {

	defer wg.Done()

	if !bit {
		// choose a random value from the integers mod prime
		j, err := rand.Int(rand.Reader, ZKCurve.C.Params().N)
		if err != nil {
			return err
		}

		m2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(idx)), ZKCurve.C.Params().N)
		//		m2 := big.NewInt(1 << uint(idx))
		em2 := new(big.Int).Mul(e0, m2)
		em2.Mod(em2, ZKCurve.C.Params().N)

		rhsX, rhsY := ZKCurve.C.ScalarBaseMult(em2.Bytes())

		lhs := ZKCurve.H.Mult(j)

		totX, totY := ZKCurve.C.Add(lhs.X, lhs.Y, rhsX, rhsY)

		hash := sha256.Sum256(append(totX.Bytes(), totY.Bytes()...))
		ei := new(big.Int).SetBytes(hash[:]) // get ei
		ei.Mod(ei, ZKCurve.C.Params().N)

		inverseEI := new(big.Int).ModInverse(ei, ZKCurve.C.Params().N)

		data.vScalars[idx] = new(big.Int).Mul(inverseEI, data.kScalars[idx])

		// set the C point for this index to R* inv ei
		data.Bpoints[idx] = data.Rpoints[idx].Mult(inverseEI)

		// s = k + (kValues[i] * e0) * inverse ei
		data.kScalars[idx] = j.Add(
			j, new(big.Int).Mul(data.kScalars[idx], new(big.Int).Mul(e0, inverseEI)))

	} else { // bit is 1, don't do anything
		// s is k + e0*v

		data.kScalars[idx] = new(big.Int).Add(
			data.kScalars[idx], new(big.Int).Mul(e0, data.vScalars[idx]))
	}

	return nil
}

/// RangeProof
// Implementation details from:
// https://blockstream.com/bitcoin17-final41.pdf
// NOTE: To be consistent with our use of Pedersen commitments, we switch the G and H values
// from the above description
//
// Takes in a value and randomness used in a commitment, and produces a proof that
// our value is in range 2^64.
// Range proofs uses ring signatures from Chameleon hashes and Pedersen Commitments
// to do commitments on the bitwise decomposition of our value.
//
func RangeProverProve(value *big.Int) (*RangeProof, *big.Int) {
	proof := RangeProof{}

	// extend or truncate our value to 64 bits, which is the range we are proving
	// If our value is in range, then sum of commitments would equal original commitment
	// else, because of truncation, it will be deemed out of range not be equal

	if value.Cmp(big.NewInt(1099511627776)) == 1 {
		fmt.Printf("val %s too big, can only prove up to 1099511627776\n", value.String())
		return nil, nil
	}

	proofSize := 40
	// check to see if our value is out of range
	if proofSize > 40 || value.Cmp(big.NewInt(0)) == -1 {
		//if so, then we can't play
		fmt.Printf("** Trying to get a value that is out of range! Range Proof will not work!\n")
		return nil, nil
	}

	stuff := new(ProverInternalData)

	stuff.kScalars = make([]*big.Int, proofSize)
	stuff.Rpoints = make([]ECPoint, proofSize)
	stuff.Bpoints = make([]ECPoint, proofSize)
	stuff.vScalars = make([]*big.Int, proofSize)

	vTotal := big.NewInt(0)
	proof.ProofTuples = make([]RangeProofTuple, proofSize)

	//	 do the loop bValue times
	var wg sync.WaitGroup
	wg.Add(proofSize)
	for i := 0; i < proofSize; i++ {
		// TODO: Check errors
		go ProofGenA(&wg, i, value.Bit(i) == 1, stuff)
	}
	wg.Wait()

	// hash concat of all R values
	rHash := sha256.New()
	for _, rvalue := range stuff.Rpoints {
		rHash.Write(rvalue.X.Bytes())
		rHash.Write(rvalue.Y.Bytes())
	}
	hashed := rHash.Sum(nil)

	e0 := new(big.Int).SetBytes(hashed[:])
	e0.Mod(e0, ZKCurve.C.Params().N)

	var AggregatePoint ECPoint
	AggregatePoint.X = new(big.Int)
	AggregatePoint.Y = new(big.Int)

	// go through all 64 part B
	wg.Add(proofSize)
	for i := 0; i < proofSize; i++ {
		// TODO: Check errors
		go ProofGenB(
			&wg, i, value.Bit(i) == 1, e0, stuff)
	}
	wg.Wait()

	for i := 0; i < proofSize; i++ {
		//		add up to get vTotal scalar
		vTotal.Add(vTotal, stuff.vScalars[i])

		// add points to get AggregatePoint
		AggregatePoint = AggregatePoint.Add(stuff.Bpoints[i])

		// copy data to ProofTuples
		proof.ProofTuples[i].C = stuff.Bpoints[i]
		proof.ProofTuples[i].S = stuff.kScalars[i]
	}

	proof.ProofE = e0
	proof.ProofAggregate = AggregatePoint

	return &proof, vTotal
}

type VerifyTuple struct {
	index  int
	Rpoint ECPoint
}

// give it a proof tuple, proofE.  Get back an Rpoint, and a Cpoint
func VerifyGen(
	idx int, proofE *big.Int, rpt RangeProofTuple, retbox chan VerifyTuple) {

	lhs := ZKCurve.H.Mult(rpt.S)

	rhs2 := rpt.C.Add(HPoints[idx].Neg())

	rhsXYNeg := rhs2.Mult(proofE).Neg()

	//s_i * G - e_0 * (C_i - 2^i * H)
	tot := lhs.Add(rhsXYNeg)

	hash := sha256.Sum256(append(tot.X.Bytes(), tot.Y.Bytes()...))

	e1 := new(big.Int).SetBytes(hash[:])

	var result VerifyTuple
	result.index = idx
	result.Rpoint = rpt.C.Mult(e1)

	retbox <- result

	return
}

func RangeProverVerify(comm ECPoint, proof *RangeProof) bool {
	proofs := proof.ProofTuples

	proofLength := len(proofs)

	Rpoints := make([]ECPoint, len(proofs))

	totalPoint := ECPoint{big.NewInt(0), big.NewInt(0)}

	resultBox := make(chan VerifyTuple, 10) // doubt we'll use even 1

	for i := 0; i < proofLength; i++ {
		// check that proofs are non-nil
		if proof.ProofTuples[i].C.X == nil {
			fmt.Println(proofs)
			panic(fmt.Sprintf("entry %d has nil point", i))
		}
		if proof.ProofTuples[i].S == nil {
			fmt.Println(proofs)
			panic(fmt.Sprintf("entry %d has nil scalar", i))

		}

		// give proof to the verify gorouting
		go VerifyGen(i, proof.ProofE, proof.ProofTuples[i], resultBox)
	}

	for i := 0; i < proofLength; i++ {
		result := <-resultBox

		// only reason we do this is for the hash of the point.
		// could do something commutative here too?
		Rpoints[result.index] = result.Rpoint

		// add to totalpoint here (commutative)
		totalPoint = totalPoint.Add(proof.ProofTuples[i].C)
	}

	rHash := sha256.New()
	for _, rpoint := range Rpoints {
		rHash.Write(rpoint.X.Bytes())
		rHash.Write(rpoint.Y.Bytes())
	}
	calculatedE0 := rHash.Sum(nil)

	if proof.ProofE.Cmp(new(big.Int).SetBytes(calculatedE0[:])) != 0 {
		//fmt.Println("check 1")
		return false
	}

	if !totalPoint.Equal(proof.ProofAggregate) {
		return false
	}

	// TODO
	// This checks that comm and proof Aggregate are equal.  seems "pointless".

	if !comm.Equal(totalPoint) {
		return false
	}

	return true
}
