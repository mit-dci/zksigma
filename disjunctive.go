package zksigma

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
)

// DisjunctiveProof is a proof that you know either x or y but does not reveal
// which one you know
//
//  Public: generator points G and H, A, B
//
//  Prover                              Verifier
//  ======                              ========
//  (proving x)
//  knows x AND/OR y
// 	A = xG; B = yH or yG				learns A, B
//  selects random u1, u2, u3
//  T1 = u1G
//  T2 = u2H + (-u3)yH
//  c = HASH(T1, T2, G, A, B)
//  deltaC = c - u3
//  s = u1 + deltaC * x
//  T1, T2, c, deltaC, u3, s, u2 -MAP-> T1, T2, c, c1, c2, s1, s2
//                                      c ?= HASH(T1, T2, G, A, B)
//                                      c ?= c1 + c2 // mod zkpcp.C.Params().N
//                                      s1G ?= T1 + c1A
//                                      s2G ?= T2 + c2A
//  To prove y instead:
//
//  Prover		 						Verifier
//  ======                              ========
//  T2, T1, c, u3, deltaC, u2, s -MAP-> T1, T2, c, c1, c2, s1, s2
//										Same checks as above
//
// Note:
// It should be indistinguishable for Verifier with T1, T2, c, c1, c2, s1, s2
// to tell if we are proving x or y. The above arrows show how the variables
// used in the proof translate to T1, T2, etc.
//
// More info: https://drive.google.com/file/d/0B_ndzgLH0bcvMjg3M1ROUWQwWTBCN0loQ055T212eV9JRU1v/view
// see section 4.2
type DisjunctiveProof struct {
	T1 ECPoint
	T2 ECPoint
	C  *big.Int
	C1 *big.Int
	C2 *big.Int
	S1 *big.Int
	S2 *big.Int
}

// NewDisjunctiveProof generates a disjunctive proof. Base1 and Base2 are our chosen base points.
// Result1 is Base1 multiplied by x or y, and Result2 is Base2 multiplied by x or y. x is the value to
// prove, if option is Left, we use Base1 and Result1 - if option is Right we use Base2 and Result2. The
// verifier will not learn what side is being proved and should not be able to tell.
func NewDisjunctiveProof(
	zkpcp ZKPCurveParams, Base1, Result1, Base2, Result2 ECPoint, x *big.Int, option Side) (*DisjunctiveProof, error) {

	modValue := new(big.Int).Mod(x, zkpcp.C.Params().N)

	// Declaring them like this because Golang crys otherwise
	var ProveBase, ProveResult, OtherBase, OtherResult ECPoint

	// Generate a proof for A
	if option == Left {
		ProveBase = Base1
		ProveResult = Result1
		OtherBase = Base2
		OtherResult = Result2
	} else if option == Right { // Generate a proof for B
		ProveBase = Base2
		ProveResult = Result2
		OtherBase = Base1
		OtherResult = Result1
	} else { // number for option is not correct
		return &DisjunctiveProof{}, &errorProof{"DisjunctiveProve", "invalid side provided"}
	}

	if !zkpcp.Mult(ProveBase, x).Equal(ProveResult) {
		return &DisjunctiveProof{}, &errorProof{"DisjunctiveProve", "Base and Result to be proved not related by x"}
	}
	u1, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}
	u2, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}
	u3, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return nil, err
	}

	// for (-u3)yH
	u3Neg := new(big.Int).Neg(u3)
	u3Neg.Mod(u3Neg, zkpcp.C.Params().N)

	// T1 = u1G
	T1 := zkpcp.Mult(ProveBase, u1)

	// u2H
	temp := zkpcp.Mult(OtherBase, u2)
	// (-u3)yH
	temp2 := zkpcp.Mult(OtherResult, u3Neg)
	// T2 = u2H + (-u3)yH (yH is OtherResult)
	T2 := zkpcp.Add(temp, temp2)

	var Challenge *big.Int
	if option == 0 {
		// String for proving Base1 and Result1
		Challenge = GenerateChallenge(zkpcp, Base1.Bytes(), Result1.Bytes(),
			Base2.Bytes(), Result2.Bytes(),
			T1.Bytes(), T2.Bytes())
	} else {

		// If we are proving Base2 and Result2 then we must switch T1 and
		// T2 in this string, look at mapping in proof for clarification
		Challenge = GenerateChallenge(zkpcp, Base1.Bytes(), Result1.Bytes(),
			Base2.Bytes(), Result2.Bytes(),
			T2.Bytes(), T1.Bytes()) //T2 and T1 SWAPPED!
	}

	deltaC := new(big.Int).Sub(Challenge, u3)
	deltaC.Mod(deltaC, zkpcp.C.Params().N)

	s := new(big.Int).Add(u1, new(big.Int).Mul(deltaC, modValue))

	// Look at mapping given in block comment above
	if option == Left {
		return &DisjunctiveProof{
			T1,
			T2,
			Challenge,
			deltaC,
			u3,
			s,
			u2}, nil
	}

	return &DisjunctiveProof{
		T2,
		T1,
		Challenge,
		u3,
		deltaC,
		u2,
		s}, nil
}

// Verify checks if DisjunctiveProof djProof is valid for the given bases and results
func (djProof *DisjunctiveProof) Verify(
	zkpcp ZKPCurveParams, Base1, Result1, Base2, Result2 ECPoint) (bool, error) {

	if djProof == nil {
		return false, &errorProof{"DisjunctiveProof.Verify", fmt.Sprintf("passed proof is nil")}
	}

	T1 := djProof.T1
	T2 := djProof.T2
	C := djProof.C
	C1 := djProof.C1
	C2 := djProof.C2
	S1 := djProof.S1
	S2 := djProof.S2

	checkC := GenerateChallenge(zkpcp, Base1.Bytes(), Result1.Bytes(),
		Base2.Bytes(), Result2.Bytes(),
		T1.Bytes(), T2.Bytes())

	if checkC.Cmp(C) != 0 {
		return false, &errorProof{"DisjunctiveVerify", "checkC does not agree with proofC"}
	}

	// C1 + C2
	totalC := new(big.Int).Add(C1, C2)
	totalC.Mod(totalC, zkpcp.C.Params().N)
	if totalC.Cmp(C) != 0 {
		return false, &errorProof{"DisjunctiveVerify", "totalC does not agree with proofC"}
	}

	// T1 + c1A
	c1A := zkpcp.Mult(Result1, C1)
	checks1G := zkpcp.Add(T1, c1A)
	s1G := zkpcp.Mult(Base1, S1)

	if !checks1G.Equal(s1G) {
		return false, &errorProof{"DisjunctiveVerify", "s1G not equal to T1 + c1A"}
	}

	// T2 + c2B
	c2A := zkpcp.Mult(Result2, C2)
	checks2G := zkpcp.Add(c2A, T2)
	s2G := zkpcp.Mult(Base2, S2)

	if !checks2G.Equal(s2G) {
		return false, &errorProof{"DisjunctiveVerify", "s2G not equal to T2 + c2B"}
	}

	return true, nil
}

// Bytes returns a byte slice with a serialized representation of DisjunctiveProof proof
func (djProof *DisjunctiveProof) Bytes() []byte {
	var buf bytes.Buffer

	WriteECPoint(&buf, djProof.T1)
	WriteECPoint(&buf, djProof.T2)
	WriteBigInt(&buf, djProof.C)
	WriteBigInt(&buf, djProof.C1)
	WriteBigInt(&buf, djProof.C2)
	WriteBigInt(&buf, djProof.S1)
	WriteBigInt(&buf, djProof.S2)

	return buf.Bytes()
}

// NewDisjunctiveProofFromBytes returns a DisjunctiveProof generated from the
// deserialization of byte slice b
func NewDisjunctiveProofFromBytes(b []byte) (*DisjunctiveProof, error) {
	proof := new(DisjunctiveProof)
	buf := bytes.NewBuffer(b)
	proof.T1, _ = ReadECPoint(buf)
	proof.T2, _ = ReadECPoint(buf)
	proof.C, _ = ReadBigInt(buf)
	proof.C1, _ = ReadBigInt(buf)
	proof.C2, _ = ReadBigInt(buf)
	proof.S1, _ = ReadBigInt(buf)
	proof.S2, _ = ReadBigInt(buf)
	return proof, nil
}
