package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"math"
	"math/big"
)

// FLAGS
var BULLET = flag.Bool("bullet", false, "Run bulletproof test cases")

type Generator struct {
	N      uint64
	M      uint64
	MaxVal *big.Int
	VecG   []ECPoint
	VecH   []ECPoint
}

type GeneratorView struct {
	G *ECPoint
	H *ECPoint
}

const (
	numBits     uint64 = 64
	numVals     uint64 = 1
	rootNumBits uint64 = 7
)

var ZKGen Generator
var ZKView GeneratorView

func BPInit() {
	ZKGen = NewGen(numBits, numVals)
	fillVecs()
}

// NewGen generates a new chain of ECPoints that are linked by consecutive hashes
func NewGen(n, m uint64) Generator {
	BPGen := Generator{}

	maxVal := big.NewInt(9223372036854775808 - 1)

	BPGen.N = n
	BPGen.M = m
	BPGen.MaxVal = maxVal

	u1, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	u2, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	VecG := genChain(n, m, u1.Bytes())
	VecH := genChain(n, m, u2.Bytes())

	BPGen.VecG = VecG
	BPGen.VecH = VecH

	return BPGen
}

func genChain(n, m uint64, initBytes []byte) []ECPoint {
	vec := make([]ECPoint, n*m)

	hasher := sha256.New()
	hasher.Write(initBytes)
	temp := new(big.Int).SetBytes(hasher.Sum(nil))
	temp.Mod(temp, ZKCurve.C.Params().N)
	vec[0].X, vec[0].Y = ZKCurve.C.ScalarBaseMult(temp.Bytes())

	for ii := uint64(1); ii < n*m; ii++ {
		hasher.Write(vec[ii-1].Bytes())
		temp = new(big.Int).SetBytes(hasher.Sum(nil))
		temp.Mod(temp, ZKCurve.C.Params().N)
		vec[ii].X, vec[ii].Y = ZKCurve.C.ScalarBaseMult(temp.Bytes())

		if !ZKCurve.C.IsOnCurve(vec[ii].X, vec[ii].Y) {
			logStuff("Some is really wrong... \n")
		}
	}

	return vec
}

func (g Generator) Share(j uint64) GeneratorView {
	return GeneratorView{&g.VecG[j], &g.VecH[j]}
}

//======== Perliminary stuff

var PowsOf2 []*big.Int
var ZeroVec []*big.Int
var OnesVec []*big.Int
var RandVec []*big.Int

func fillVecs() {
	ZeroVec, OnesVec, PowsOf2, RandVec = make([]*big.Int, numBits), make([]*big.Int, numBits),
		make([]*big.Int, numBits), make([]*big.Int, numBits)
	for ii := int64(0); ii < int64(numBits); ii++ {

		// Probably can save space here
		ZeroVec[ii] = big.NewInt(0)
		OnesVec[ii] = big.NewInt(1)
		PowsOf2[ii] = new(big.Int).Exp(big.NewInt(2), big.NewInt(ii), ZKCurve.C.Params().N)
	}
}

// binaryDecomp takes in a value and generates an binary composition array that
// summed up will equal value
// could probably optimize this somehow since its only 0/1
func binaryDecomp(value *big.Int) []*big.Int {

	result := make([]*big.Int, numBits)

	// GENERATES BIG ENDIAN
	for ii := 0; ii < int(numBits); ii++ {
		result[ii] = big.NewInt(0)
		value.QuoRem(value, big.NewInt(2), result[ii])
	}

	return result
}

func dotProd(x, y []*big.Int) *big.Int {

	if len(x) != len(y) {
		logStuff("dorProd: anrray sizes do not match! Zero *big.Int returned\n")
		return big.NewInt(0)
	}

	acc := big.NewInt(0)

	for ii := 0; ii < len(x); ii++ {
		acc.Add(new(big.Int).Mul(x[ii], y[ii]), acc)
	}
	return acc
}

// x[] cannot contain 0 or 1 in any entry?
func ecDotProd(x []*big.Int, y []ECPoint) ECPoint {
	if len(x) != len(y) {
		logStuff("ecDotProd: array sizes do not match! Zero ECPoint returned\n")
		return Zero
	}

	if len(y) == 1 {
		return y[0].Mult(x[0])
	}

	temp := y[0].Mult(x[0])
	acc := Zero

	for ii := 0; ii < len(x); ii++ {
		temp = y[ii].Mult(x[ii])
		acc = acc.Add(temp)
	}
	return acc
}

// COM(vec1, vec2, u) -> <vec1, G> + <vec2, H> + uB', where B' is the ped commit blinder, G and H are chain vecots
func vecPedComm(a []*big.Int, G []ECPoint, H []ECPoint) (ECPoint, *big.Int) {
	if len(a) != len(G) || len(a) != len(H) {
		return Zero, big.NewInt(0)
	}

	randomness, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	res := ecDotProd(a, G).Add(ecDotProd(a, H))
	temp := Zero
	temp.X, temp.Y = ZKCurve.C.ScalarBaseMult(randomness.Bytes())
	res = res.Add(temp)

	return res, randomness

}

func vecMult(x, y []*big.Int) []*big.Int {

	if len(x) != len(y) {
		return []*big.Int{}
	}

	res := make([]*big.Int, len(x))

	for ii := 0; ii < len(x); ii++ {
		res[ii] = new(big.Int).Mul(x[ii], y[ii]) // res is not declared yet so we need assignment statement
	}
	return res
}

func vecAdd(x, y []*big.Int) []*big.Int {
	if len(x) != len(y) {
		return []*big.Int{}
	}

	res := make([]*big.Int, len(x))

	for ii := 0; ii < len(x); ii++ {
		res[ii] = new(big.Int).Add(x[ii], y[ii]) // res is not declared yet so we need assignment statement
	}
	return res
}

func vecAddEC(G []ECPoint, H []ECPoint) []ECPoint {
	if len(G) != len(H) {
		return []ECPoint{}
	}

	res := make([]ECPoint, len(G))

	for ii := 0; ii < len(G); ii++ {
		res[ii].X, res[ii].Y = ZKCurve.C.Add(G[ii].X, G[ii].Y, H[ii].X, H[ii].Y) // res is not declared yet so we need assignment statement
	}
	return res

}

func vecSub(x, y []*big.Int) []*big.Int {
	if len(x) != len(y) {
		return []*big.Int{}
	}

	res := make([]*big.Int, len(x))
	for ii := 0; ii < len(x); ii++ {
		res[ii] = new(big.Int).Sub(x[ii], y[ii]) // res is not declared yet so we need assignment statement
	}
	return res
}

func splitVec(x []*big.Int) ([]*big.Int, []*big.Int) {

	if len(x) == 1 {
		logStuff("splitVec:\n - input array is of size 1, returning {x, x}\n")
		return x, x
	}

	if len(x)%2 != 0 {
		logStuff("splitVec:\n - input arrays are not multiple of 2\n")
		return []*big.Int{}, []*big.Int{}
	}

	return x[0 : len(x)/2], x[len(x)/2 : len(x)]
}

func splitVecEC(x []ECPoint) ([]ECPoint, []ECPoint) {

	if len(x) == 1 {
		logStuff("splitVecEC:\n - input array is of size 1, returning {x, x}\n")
		return x, x
	}

	if len(x)%2 != 0 {
		logStuff("splitVecEC:\n - input arrays are not multiple of 2\n")
		return []ECPoint{}, []ECPoint{}
	}

	return x[0 : len(x)/2], x[len(x)/2 : len(x)]
}

func genVec(x *big.Int) []*big.Int {
	res := make([]*big.Int, numBits)

	for ii := int64(0); ii < int64(numBits); ii++ {
		res[ii] = new(big.Int).Exp(x, big.NewInt(ii), ZKCurve.C.Params().N)
	}
	return res
}

func scalar(x *big.Int, y []*big.Int) []*big.Int {
	if len(y) != 0 {
		return []*big.Int{}
	}

	res := make([]*big.Int, len(y))
	for ii := 0; ii < len(y); ii++ {
		res[ii] = new(big.Int).Mul(y[ii], x)
	}
	return res

}

func scalarEC(x *big.Int, G []ECPoint) []ECPoint {
	if len(G) != 0 {
		return []ECPoint{}
	}

	res := make([]ECPoint, len(G))
	for ii := 0; ii < len(G); ii++ {
		res[ii].X, res[ii].Y = ZKCurve.C.ScalarMult(G[ii].X, G[ii].Y, x.Bytes())
	}
	return res

}

func ecVecBytes(x []ECPoint) []byte {
	var byteArr []byte
	for _, vv := range x {
		byteArr = append(byteArr, vv.Bytes()...)
	}
	return byteArr
}

//========== INNER PRODUCT PROOF =========

type InProdProof struct {
	A        *big.Int
	B        *big.Int
	U        []*big.Int
	UInv     []*big.Int
	P        ECPoint
	Q        ECPoint
	LeftVec  []ECPoint
	RightVec []ECPoint
}

/*
	Inner Product Proof:

	REFERANCE : https://doc-internal.dalek.rs/ristretto_bulletproofs/inner_product_proof/index.html

	We want to prove that c is the inner product (dot product) of a and b
	without sending 2n bits but insteading sending log(n) bits

	Public: G, H, P', Q, a, b, where:
	 - a and b are scalar vectors
	 - G and H are ECPoint vectors
	 - P' and Q are ECPoints

	c = <a, b>
	P = <a,G> + <b,H>
	w is random num

	P' = cwB + P where B is the G of the ped commitment
	Q = wB



*/

// InProdProve will generate a proof that shows the final commitment provided
// is generated from two scalar vectors reduced into one commtiment
func InProdProve(a, b []*big.Int, G, H []ECPoint) (InProdProof, bool) {

	if len(a)%2 != 0 && (len(a) != len(b) || len(a) != len(G) || len(a) != len(H)) {
		logStuff("InProdProof:\n - lengths of arrays do not agree/not multiple of 2\n")
		return InProdProof{}, false
	}

	k := rootNumBits

	proof := InProdProof{big.NewInt(0),
		big.NewInt(0),
		make([]*big.Int, k-1),
		make([]*big.Int, k-1),
		Zero,
		Zero,
		make([]ECPoint, k-1),
		make([]ECPoint, k-1)}

	// Commitments we want to prove
	// P = <a, G> + <b, H>
	temp1 := ecDotProd(a, G)
	temp2 := ecDotProd(b, H)
	P := temp1.Add(temp2)
	c := new(big.Int).Mod(dotProd(a, b), ZKCurve.C.Params().N)

	// Blinding factor for c
	w, _ := rand.Int(rand.Reader, ZKCurve.C.Params().N)

	// wG where G is from the ped commit:
	Q := ZKCurve.G.Mult(w)
	proof.Q = Q

	// c * wG
	temp1 = Q.Mult(c)
	// P' = P + cwG, public commitment used for inner product proof
	P2 := P.Add(temp1)
	proof.P = P2

	// s := make([]*big.Int, k)
	hasher := sha256.New()

	for ii := rootNumBits - 2; ii >= uint64(0); ii-- {
		// split the vectors for reduction later
		aL, aR := splitVec(a)
		bL, bR := splitVec(b)
		GL, GR := splitVecEC(G)
		HL, HR := splitVecEC(H)

		// Prover calcualtes L and R
		// The two statements below work just fine, don't mess with the brackets...
		// Something fucky going on here...
		thing1 := ecDotProd(aL, GR)
		thing2 := ecDotProd(bR, HL)
		thing3 := Q.Mult(dotProd(aL, bR))

		proof.LeftVec[ii] = thing1.Add(thing2.Add(thing3))
		proof.RightVec[ii] = ecDotProd(aR, GL).Add(ecDotProd(bL, HR).Add(Q.Mult(dotProd(aR, bL))))
		// logStuff(" LeftV[%v]: %v \nRightV[%v]: %v\n", ii, proof.LeftVec[ii], ii, proof.RightVec[ii])

		// FS-Transform to make this non interactive is to write in each L and R into the buffer
		// stringing these consecutive hashes locks in each value of L and R to the previous ones
		hasher.Write(proof.LeftVec[ii].Bytes())
		hasher.Write(proof.RightVec[ii].Bytes())
		u := new(big.Int).SetBytes(hasher.Sum(nil))
		u.Mod(u, ZKCurve.C.Params().N)
		uinv := new(big.Int).ModInverse(u, ZKCurve.C.Params().N)
		// s[ii] = uinv
		proof.U[ii] = new(big.Int).Mod(new(big.Int).Mul(u, u), ZKCurve.C.Params().N)          // we need it squared for verification
		proof.UInv[ii] = new(big.Int).Mod(new(big.Int).Mul(uinv, uinv), ZKCurve.C.Params().N) //need squared for verification

		// reduce vectors by half
		// a, b are computed by verifier only
		a = vecAdd(scalar(u, aL), scalar(uinv, aR))
		b = vecAdd(scalar(u, bR), scalar(uinv, bL))
		// G, H are computed by both parites
		G = vecAddEC(scalarEC(u, GR), scalarEC(uinv, GL))
		H = vecAddEC(scalarEC(u, HL), scalarEC(uinv, HR))

		// Without this you will get overflow on uint64(-1) and stuff breaks...
		if ii == 0 {
			break
		}

	}

	if (len(a) != 1 || len(a) != len(b)) && (len(G) != 1 || len(G) != len(H)) {
		logStuff("InProdProof:\n - len(a) is not 1 and/or len(a) != len(b) OR for G and H the same\n")
		logStuff(" - Proof failed to generate\n")
		logStuff(" - a: %v\n - b: %v\n", a, b)
		return InProdProof{}, false
	}

	// Internal verficiation, this is where the proof is failing
	// If this does not pass then I do not expect the InnerProdVerify to pass
	proof.A = a[0]
	proof.B = b[0]

	tempAB := new(big.Int).Mul(proof.A, proof.B)

	// a_0 * G_0 + b_0 + H_0 + a_0 * b_0 * Q; Q is wG, where G is the basepoint and not compress ECvec
	test1 := G[0].Mult(a[0])
	test2 := H[0].Mult(b[0])
	test3 := Q.Mult(tempAB)

	sumTemp := Zero
	for ii := 0; ii < 6; ii++ { // k - 1 = 6
		// logStuff("LeftVec[%v]: %v\n", ii, proof.LeftVec[ii])
		whatBroke1 := proof.LeftVec[ii].Mult(proof.U[ii])
		whatBroke2 := proof.RightVec[ii].Mult(proof.UInv[ii])
		whatBroke3 := sumTemp
		sumTemp = whatBroke1.Add(whatBroke2.Add(whatBroke3))
	}

	total := test1.Add(test2.Add(test3.Sub(sumTemp)))

	if !proof.P.Equal(total) {
		logStuff("Internal check did not pass!\n")
		return InProdProof{}, false
	}

	return proof, true
}

// InProdVerify will check if an InProdProof is correct
func InProdVerify(G, H []ECPoint, proof InProdProof) bool {

	// generate vector s
	s := make([]*big.Int, numBits)
	sRev := make([]*big.Int, numBits)

	for ii := uint64(0); ii < numBits; ii++ {
		acc := big.NewInt(1)
		for jj := uint64(0); jj < rootNumBits-1; jj++ {
			if math.Mod(float64(ii), math.Pow(2, float64(jj))) < math.Pow(2, float64(jj-1)) {
				acc.Mul(acc, new(big.Int).ModInverse(proof.U[jj], ZKCurve.C.Params().N)) // mod inverse might not be the correct thing...
			} else {
				acc.Mul(acc, proof.U[jj])
			}

		}
		s[ii] = new(big.Int).Mul(acc, proof.A)
		sRev[numBits-1-ii] = new(big.Int).Mul(acc, proof.B)
	}

	thing1 := ecDotProd(s, G)
	thing2 := ecDotProd(sRev, H)
	thing3 := proof.Q.Mult(new(big.Int).Mul(proof.A, proof.B))

	sumTemp := Zero
	for ii := 0; ii < 6; ii++ {
		whatBroke1 := proof.LeftVec[ii].Mult(proof.U[ii])
		whatBroke2 := proof.RightVec[ii].Mult(proof.UInv[ii])
		whatBroke3 := sumTemp
		sumTemp = whatBroke1.Add(whatBroke2.Add(whatBroke3))
	}

	total := thing1.Add(thing2.Add(thing3.Sub(sumTemp)))

	if !proof.P.Equal(total) {
		logStuff("Internal check did not pass!\n")
		return false
	}

	return true
}

type newInProdProof struct {
	a        *big.Int
	b        *big.Int
	LeftVec  []ECPoint
	RightVec []ECPoint
}

func InProdProveRecursive(a, b []*big.Int, prevChallenge *big.Int, G, H, LeftVec, RightVec []ECPoint) (*newInProdProof, error) {
	n := len(a)
	// safety
	if n == int(numBits) {
		prevChallenge = big.NewInt(0)
	}
	if len(a)%2 != 0 && (len(a) != len(b) || len(a) != len(G) || len(a) != len(H)) {
		return nil, &errorProof{"InProdProveRecursive:", "lengths of arrays do not agree/not multiple of 2"}
	} else if n%2 != 0 && n != 1 {
		return nil, &errorProof{"InProdProveRecursive", "length of vectors not power of 2"}
	} else if n == 1 {
		return &newInProdProof{a[0], b[0], LeftVec, RightVec}, nil
	}

	aL, aR := splitVec(a)
	bL, bR := splitVec(b)
	GL, GR := splitVecEC(G)
	HL, HR := splitVecEC(H)

	cL := dotProd(aL, bR)
	cR := dotProd(aR, bL)

	LeftTemp := ecDotProd(aL, GR).Add(ecDotProd(bR, HL).Add(ZKCurve.H.Mult(cL)))
	RightTemp := ecDotProd(aR, GL).Add(ecDotProd(bL, HR).Add(ZKCurve.H.Mult(cR)))

	LeftVec = append(LeftVec, LeftTemp)
	RightVec = append(RightVec, RightTemp)

	U := GenerateChallenge(prevChallenge.Bytes(), LeftTemp.Bytes(), RightTemp.Bytes())
	UInv := new(big.Int).ModInverse(U, ZKCurve.C.Params().N)

	// U2 := new(big.Int).Mul(U, U)
	// U2Inv := new(big.Int).Mul(UInv, UInv)

	NewG := vecAddEC(scalarEC(UInv, GL), scalarEC(U, GR))
	NewH := vecAddEC(scalarEC(U, HL), scalarEC(UInv, HR))

	NewA := vecAdd(scalar(U, aL), scalar(UInv, aR))
	NewB := vecAdd(scalar(UInv, bL), scalar(U, bR))

	//NewP := vecAddEC(scalarEC(U2, LeftVec), scalarEC(U2Inv, RightVec))

	return InProdProveRecursive(NewA, NewB, prevChallenge, NewG, NewH, LeftVec, RightVec)

}

func InProdVerify1(G, H []ECPoint, proof *newInProdProof) bool {
	n := len(G)

	if n != int(numBits) || n != len(H) {
		// errorProof{"InProdVerify1", "Length of vectors is not power of 2 or equal to each other"}
		return false
	}

	prevChallenge := big.NewInt(0)

	var FinalG, FinalH ECPoint
	checkC := Zero

	for ii, _ := range proof.LeftVec {
		L := proof.LeftVec[ii]
		R := proof.RightVec[ii]

		GL, GR := splitVecEC(G)
		HL, HR := splitVecEC(H)

		U := GenerateChallenge(prevChallenge.Bytes(), proof.LeftVec[ii].Bytes(), proof.RightVec[ii].Bytes())
		UInv := new(big.Int).ModInverse(U, ZKCurve.C.Params().N)

		U2 := new(big.Int).Mul(U, U)
		U2Inv := new(big.Int).Mul(UInv, UInv)

		NewG := vecAddEC(scalarEC(UInv, GL), scalarEC(U, GR))
		NewH := vecAddEC(scalarEC(U, HL), scalarEC(UInv, HR))

		// if this is true then n = 1, should only happen once
		if n%2 == 1 && len(G) == 1 {
			FinalG = NewG[0].Add(G[n-1])
			FinalH = NewH[0].Add(H[n-1])
		}
		// setting variables for next iteration of loop
		n = n / 2
		G = NewG
		H = NewH
		prevChallenge = U

		// verification value accumulator
		checkC = L.Mult(U2).Add(R.Mult(U2Inv).Add(checkC))
	}

	if len(G) != 1 {
		return false
	}

	prodAB := new(big.Int).Mul(proof.a, proof.b)
	proofC := FinalG.Mult(proof.a).Add(FinalH.Mult(proof.b).Add(ZKCurve.G.Mult(prodAB)))

	if proofC.Equal(checkC) {
		return true
	}
	return false
}
