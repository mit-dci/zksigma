package zksigma

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"

	"github.com/mit-dci/zksigma/wire"
)

// The following was copy-pasted from zkLedger's original implementation by Willy (github.com/wrv)
// TODO: replace rangeproofs of zkLedger with bulletproofs, eventually

///////////////////////
// RANGE PROOFS

type rangeProofTuple struct {
	C ECPoint
	S *big.Int
}

// RangeProof
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
type RangeProof struct {
	ProofAggregate ECPoint
	ProofE         *big.Int
	ProofTuples    []rangeProofTuple
}

type proverInternalData struct {
	Rpoints  []ECPoint
	Bpoints  []ECPoint
	kScalars []*big.Int
	vScalars []*big.Int
}

// proofGenA takes in a waitgroup, index and bit
// returns an Rpoint and Cpoint, and the k value bigint
func proofGenA(zkpcp ZKPCurveParams,
	wg *sync.WaitGroup, idx int, bit bool, s *proverInternalData) error {

	defer wg.Done()
	var err error

	//	R := s.Rpoints[idx]
	//	B := s.Bpoints[idx]
	//	k := stuff.kScalars[index]
	//	v := stuff.vScalars[index]

	if !bit { // If bit is 0, just make a random R = k*H
		s.kScalars[idx], err = rand.Int(rand.Reader, zkpcp.C.Params().N) // random k
		if err != nil {
			return err
		}
		s.Rpoints[idx] = zkpcp.Mult(zkpcp.H, s.kScalars[idx]) // R is k * H
	} else { // if bit is 1, actually do stuff

		// get a random ri
		s.vScalars[idx], err = rand.Int(rand.Reader, zkpcp.C.Params().N)
		if err != nil {
			return err
		}
		// get R as H*ri... what is KC..?
		s.Rpoints[idx] = zkpcp.Mult(zkpcp.H, s.vScalars[idx])

		// B is htothe[index] plus partial R
		s.Bpoints[idx].X, s.Bpoints[idx].Y =
			zkpcp.C.Add(zkpcp.HPoints[idx].X, zkpcp.HPoints[idx].Y,
				s.Rpoints[idx].X, s.Rpoints[idx].Y)

			// random k
		s.kScalars[idx], err = rand.Int(rand.Reader, zkpcp.C.Params().N)
		if err != nil {
			return err
		}

		// make k*H for hashing
		temp := zkpcp.Mult(zkpcp.H, s.kScalars[idx])

		// Hash of temp point (why the whole thing..?
		hash := sha256.Sum256(append(temp.X.Bytes(), temp.Y.Bytes()...))
		ei := new(big.Int).SetBytes(hash[:])
		ei.Mod(ei, zkpcp.C.Params().N)
		s.Rpoints[idx].X, s.Rpoints[idx].Y =
			zkpcp.C.ScalarMult(s.Bpoints[idx].X, s.Bpoints[idx].Y, ei.Bytes())
	}
	//	fmt.Printf("loop %d\n", idx)

	return nil
}

// proofGenB takes waitgroup, index, bit, along with the data to operate on
func proofGenB(zkpcp ZKPCurveParams,
	wg *sync.WaitGroup, idx int, bit bool, e0 *big.Int, data *proverInternalData) error {

	defer wg.Done()

	if !bit {
		// choose a random value from the integers mod prime
		j, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
		if err != nil {
			return err
		}

		m2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(idx)), zkpcp.C.Params().N)
		//		m2 := big.NewInt(1 << uint(idx))
		em2 := new(big.Int).Mul(e0, m2)
		em2.Mod(em2, zkpcp.C.Params().N)

		rhsX, rhsY := zkpcp.C.ScalarBaseMult(em2.Bytes())

		lhs := zkpcp.Mult(zkpcp.H, j)

		totX, totY := zkpcp.C.Add(lhs.X, lhs.Y, rhsX, rhsY)

		hash := sha256.Sum256(append(totX.Bytes(), totY.Bytes()...))
		ei := new(big.Int).SetBytes(hash[:]) // get ei
		ei.Mod(ei, zkpcp.C.Params().N)

		inverseEI := new(big.Int).ModInverse(ei, zkpcp.C.Params().N)

		data.vScalars[idx] = new(big.Int).Mul(inverseEI, data.kScalars[idx])

		// set the C point for this index to R* inv ei
		data.Bpoints[idx] = zkpcp.Mult(data.Rpoints[idx], inverseEI)

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

// NewRangeProof generates a range proof for the given value
func NewRangeProof(zkpcp ZKPCurveParams, value *big.Int) (*RangeProof, *big.Int, error) {
	proof := RangeProof{}

	// extend or truncate our value to 64 bits, which is the range we are proving
	// If our value is in range, then sum of commitments would equal original commitment
	// else, because of truncation, it will be deemed out of range not be equal

	if value.Cmp(big.NewInt(1099511627776)) == 1 {
		return nil, nil, fmt.Errorf("val %s too big, can only prove up to 1099511627776\n", value.String())
	}

	proofSize := 40
	// check to see if our value is out of range
	if proofSize > 40 || value.Cmp(BigZero) == -1 {
		//if so, then we can't play
		return nil, nil, fmt.Errorf("** Trying to get a value that is out of range! Range Proof will not work!\n")
	}

	stuff := new(proverInternalData)

	stuff.kScalars = make([]*big.Int, proofSize)
	stuff.Rpoints = make([]ECPoint, proofSize)
	stuff.Bpoints = make([]ECPoint, proofSize)
	stuff.vScalars = make([]*big.Int, proofSize)

	vTotal := big.NewInt(0)
	proof.ProofTuples = make([]rangeProofTuple, proofSize)

	//	 do the loop bValue times
	var wg sync.WaitGroup
	wg.Add(proofSize)
	for i := 0; i < proofSize; i++ {
		// TODO: Check errors
		go proofGenA(zkpcp, &wg, i, value.Bit(i) == 1, stuff)
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
	e0.Mod(e0, zkpcp.C.Params().N)

	var AggregatePoint ECPoint
	AggregatePoint.X = new(big.Int)
	AggregatePoint.Y = new(big.Int)

	// go through all 64 part B
	wg.Add(proofSize)
	for i := 0; i < proofSize; i++ {
		// TODO: Check errors
		go proofGenB(zkpcp,
			&wg, i, value.Bit(i) == 1, e0, stuff)
	}
	wg.Wait()

	for i := 0; i < proofSize; i++ {
		//		add up to get vTotal scalar
		vTotal.Add(vTotal, stuff.vScalars[i])

		// add points to get AggregatePoint
		AggregatePoint = zkpcp.Add(AggregatePoint, stuff.Bpoints[i])

		// copy data to ProofTuples
		proof.ProofTuples[i].C = stuff.Bpoints[i]
		proof.ProofTuples[i].S = stuff.kScalars[i]
	}

	proof.ProofE = e0
	proof.ProofAggregate = AggregatePoint

	return &proof, vTotal, nil
}

type verifyTuple struct {
	index  int
	Rpoint ECPoint
}

// give it a proof tuple, proofE.  Get back an Rpoint, and a Cpoint
func verifyGen(zkpcp ZKPCurveParams,
	idx int, proofE *big.Int, rpt rangeProofTuple, retbox chan verifyTuple) {

	lhs := zkpcp.Mult(zkpcp.H, rpt.S)

	rhs2 := zkpcp.Add(rpt.C, zkpcp.Neg(zkpcp.HPoints[idx]))

	rhsXYNeg := zkpcp.Neg(zkpcp.Mult(rhs2, proofE))

	//s_i * G - e_0 * (C_i - 2^i * H)
	tot := zkpcp.Add(lhs, rhsXYNeg)

	hash := sha256.Sum256(append(tot.X.Bytes(), tot.Y.Bytes()...))

	e1 := new(big.Int).SetBytes(hash[:])

	var result verifyTuple
	result.index = idx
	result.Rpoint = zkpcp.Mult(rpt.C, e1)

	retbox <- result
}

func (proof *RangeProof) Verify(zkpcp ZKPCurveParams, comm ECPoint) (bool, error) {
	if proof == nil {
		return false, &errorProof{"RangeProof.Verify", fmt.Sprintf("passed proof is nil")}
	}

	proofs := proof.ProofTuples

	proofLength := len(proofs)

	Rpoints := make([]ECPoint, len(proofs))

	totalPoint := ECPoint{big.NewInt(0), big.NewInt(0)}

	resultBox := make(chan verifyTuple, 10) // doubt we'll use even 1

	for i := 0; i < proofLength; i++ {
		// check that proofs are non-nil
		if proof.ProofTuples[i].C.X == nil {
			return false, &errorProof{"RangeProof.Verify", fmt.Sprintf("entry %d has nil point", i)}
		}
		if proof.ProofTuples[i].S == nil {
			return false, &errorProof{"RangeProof.Verify", fmt.Sprintf("entry %d has nil scalar", i)}

		}

		// give proof to the verify gorouting
		go verifyGen(zkpcp, i, proof.ProofE, proof.ProofTuples[i], resultBox)
	}

	for i := 0; i < proofLength; i++ {
		result := <-resultBox

		// only reason we do this is for the hash of the point.
		// could do something commutative here too?
		Rpoints[result.index] = result.Rpoint

		// add to totalpoint here (commutative)
		totalPoint = zkpcp.Add(totalPoint, proof.ProofTuples[i].C)
	}

	rHash := sha256.New()
	for _, rpoint := range Rpoints {
		rHash.Write(rpoint.X.Bytes())
		rHash.Write(rpoint.Y.Bytes())
	}
	calculatedE0 := rHash.Sum(nil)

	if proof.ProofE.Cmp(new(big.Int).SetBytes(calculatedE0[:])) != 0 {
		return false, &errorProof{"RangeProof.Verify", fmt.Sprintf("calculatedE0 does not match")}
	}

	if !totalPoint.Equal(proof.ProofAggregate) {
		return false, &errorProof{"RangeProof.Verify", fmt.Sprintf("ProofAggregate does not match totalPoint")}
	}

	if !comm.Equal(totalPoint) {
		return false, &errorProof{"RangeProof.Verify", fmt.Sprintf("ProofAggregate does not match commitment")}
	}

	return true, nil
}

// Bytes returns a byte slice with a serialized representation of RangeProof proof
func (proof *RangeProof) Bytes() []byte {
	var buf bytes.Buffer

	WriteECPoint(&buf, proof.ProofAggregate)
	WriteBigInt(&buf, proof.ProofE)
	wire.WriteVarInt(&buf, uint64(len(proof.ProofTuples)))
	for _, t := range proof.ProofTuples {
		WriteECPoint(&buf, t.C)
		WriteBigInt(&buf, t.S)
	}

	return buf.Bytes()
}

// NewRangeProofFromBytes returns a RangeProof generated from the
// deserialization of byte slice b
func NewRangeProofFromBytes(b []byte) (*RangeProof, error) {
	proof := new(RangeProof)
	buf := bytes.NewBuffer(b)

	proof.ProofAggregate, _ = ReadECPoint(buf)
	proof.ProofE, _ = ReadBigInt(buf)
	numTuples, _ := wire.ReadVarInt(buf)
	proof.ProofTuples = make([]rangeProofTuple, numTuples)
	for i := uint64(0); i < numTuples; i++ {
		proof.ProofTuples[i] = rangeProofTuple{}
		proof.ProofTuples[i].C, _ = ReadECPoint(buf)
		proof.ProofTuples[i].S, _ = ReadBigInt(buf)
	}

	return proof, nil
}
