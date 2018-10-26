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

	u1, _ := rand.Int(rand.Reader, ZKCurve.N)
	u2, _ := rand.Int(rand.Reader, ZKCurve.N)
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
	temp.Mod(temp, ZKCurve.N)
	vec[0].X, vec[0].Y = ZKCurve.C.ScalarBaseMult(temp.Bytes())

	for ii := uint64(1); ii < n*m; ii++ {
		hasher.Write(vec[ii-1].Bytes())
		temp = new(big.Int).SetBytes(hasher.Sum(nil))
		temp.Mod(temp, ZKCurve.N)
		vec[ii].X, vec[ii].Y = ZKCurve.C.ScalarBaseMult(temp.Bytes())

		if !ZKCurve.C.IsOnCurve(vec[ii].X, vec[ii].Y) {
			Dprintf("Some is really wrong... \n")
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
		PowsOf2[ii] = new(big.Int).Exp(big.NewInt(2), big.NewInt(ii), ZKCurve.N)
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
		Dprintf("dorProd: anrray sizes do not match! Zero bigInt returned\n")
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
		Dprintf("ecDotProd: array sizes do not match! Zero ECP returned\n")
		return ZKCurve.Zero()
	}

	acc := y[0].Mult(x[0])
	temp := ZKCurve.Zero()

	for ii := 1; ii < len(x); ii++ {
		temp = y[ii].Mult(x[ii])
		acc = acc.Add(temp)
	}
	return acc
}

// COM(vec1, vec2, u) -> <vec1, G> + <vec2, H> + uB', where B' is the ped commit blinder, G and H are chain vecots
func vecPedComm(a []*big.Int, G []ECPoint, H []ECPoint) (ECPoint, *big.Int) {
	if len(a) != len(G) || len(a) != len(H) {
		return ZKCurve.Zero(), big.NewInt(0)
	}

	randomness, _ := rand.Int(rand.Reader, ZKCurve.N)
	res := ecDotProd(a, G).Add(ecDotProd(a, H))
	temp := ZKCurve.Zero()
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
		Dprintf("splitVec:\n - input array is of size 1, returning {x, x}\n")
		return x, x
	}

	if len(x)%2 != 0 {
		Dprintf("splitVec:\n - input arrays are not multiple of 2\n")
		return []*big.Int{}, []*big.Int{}
	}

	return x[0 : len(x)/2], x[len(x)/2 : len(x)]
}

func splitVecEC(x []ECPoint) ([]ECPoint, []ECPoint) {

	if len(x) == 1 {
		Dprintf("splitVecEC:\n - input array is of size 1, returning {x, x}\n")
		return x, x
	}

	if len(x)%2 != 0 {
		Dprintf("splitVecEC:\n - input arrays are not multiple of 2\n")
		return []ECPoint{}, []ECPoint{}
	}

	return x[0 : len(x)/2], x[len(x)/2 : len(x)]
}

func genVec(x *big.Int) []*big.Int {
	res := make([]*big.Int, numBits)

	for ii := int64(0); ii < int64(numBits); ii++ {
		res[ii] = new(big.Int).Exp(x, big.NewInt(ii), ZKCurve.N)
	}
	return res
}

func scalar(x []*big.Int, y *big.Int) []*big.Int {
	if len(x)%2 != 0 && len(x) != 1 {
		return []*big.Int{}
	}

	res := make([]*big.Int, len(x))
	for ii := 0; ii < len(x); ii++ {
		res[ii] = new(big.Int).Mul(x[ii], y)
	}
	return res

}

func scalarEC(x *big.Int, G []ECPoint) []ECPoint {
	if len(G)%2 != 0 && len(G) != 1 {
		return []ECPoint{}
	}

	res := make([]ECPoint, len(G))
	for ii := 0; ii < len(G); ii++ {
		res[ii].X, res[ii].Y = ZKCurve.C.ScalarMult(G[ii].X, G[ii].Y, x.Bytes())
	}
	return res

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

func InProdProve(a, b []*big.Int, G, H []ECPoint) (InProdProof, bool) {

	if len(a)%2 != 0 && (len(a) != len(b) || len(a) != len(G) || len(a) != len(H)) {
		Dprintf("InProdProof:\n - lengths of arrays do not agree/not multiple of 2\n")
		return InProdProof{}, false
	}

	k := rootNumBits

	proof := InProdProof{big.NewInt(0),
		big.NewInt(0),
		make([]*big.Int, k-1),
		make([]*big.Int, k-1),
		ZKCurve.Zero(),
		ZKCurve.Zero(),
		make([]ECPoint, k-1),
		make([]ECPoint, k-1)}

	// Commitments we want to prove
	// P = <a, G> + <b, H>
	temp1 := ecDotProd(a, G)
	temp2 := ecDotProd(b, H)
	P := temp1.Add(temp2)
	c := new(big.Int).Mod(dotProd(a, b), ZKCurve.N)

	// Blinding factor for c
	w, _ := rand.Int(rand.Reader, ZKCurve.N)

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
		// Dprintf(" LeftV[%v]: %v \nRightV[%v]: %v\n", ii, proof.LeftVec[ii], ii, proof.RightVec[ii])

		// FS-Transform to make this non interactive is to write in each L and R into the buffer
		// stringing these consecutive hashes locks in each value of L and R to the previous ones
		hasher.Write(proof.LeftVec[ii].Bytes())
		hasher.Write(proof.RightVec[ii].Bytes())
		u := new(big.Int).SetBytes(hasher.Sum(nil))
		u.Mod(u, ZKCurve.N)
		uinv := new(big.Int).ModInverse(u, ZKCurve.N)
		// s[ii] = uinv
		proof.U[ii] = new(big.Int).Mod(new(big.Int).Mul(u, u), ZKCurve.N)          // we need it squared for verification
		proof.UInv[ii] = new(big.Int).Mod(new(big.Int).Mul(uinv, uinv), ZKCurve.N) //need squared for verification

		// reduce vectors by half
		// a, b are computed by verifier only
		a = vecAdd(scalar(aL, u), scalar(aR, uinv))
		b = vecAdd(scalar(bR, u), scalar(bL, uinv))
		// G, H are computed by both parites
		G = vecAddEC(scalarEC(u, GR), scalarEC(uinv, GL))
		H = vecAddEC(scalarEC(u, HL), scalarEC(uinv, HR))

		// Without this you will get overflow on uint64(-1) and stuff breaks...
		if ii == 0 {
			break
		}

	}

	if len(a) != 1 || len(a) != len(b) {
		Dprintf("InProdProof:\n - len(a) is not 1 and/or len(a) != len(b)\n")
		Dprintf(" - Proof failed to generate\n")
		Dprintf(" - a: %v\n - b: %v\n", a, b)
		return InProdProof{}, false
	}

	proof.A = a[0]
	proof.B = b[0]

	tempAB := new(big.Int).Mul(proof.A, proof.B)

	// a_0 * G_0 + b_0 + H_0 + a_0 * b_0 * Q; Q is wG, where G is the basepoint and not compress ECvec
	test1 := G[0].Mult(a[0])
	test2 := H[0].Mult(b[0])
	test3 := Q.Mult(tempAB)

	sumTemp := ZKCurve.Zero()
	for ii := 0; ii < 6; ii++ { // k - 1 = 6
		// Dprintf("LeftVec[%v]: %v\n", ii, proof.LeftVec[ii])
		whatBroke1 := proof.LeftVec[ii].Mult(proof.U[ii])
		whatBroke2 := proof.RightVec[ii].Mult(proof.UInv[ii])
		whatBroke3 := sumTemp
		sumTemp = whatBroke1.Add(whatBroke2.Add(whatBroke3))
	}

	total := test1.Add(test2.Add(test3.Sub(sumTemp)))

	if !proof.P.Equal(total) {
		Dprintf("Internal check did not pass!\n")
		return InProdProof{}, false
	}

	return proof, true
}

func InProdVerify(G, H []ECPoint, proof InProdProof) bool {

	// generate vector s
	s := make([]*big.Int, numBits)
	sRev := make([]*big.Int, numBits)

	for ii := uint64(0); ii < numBits; ii++ {
		acc := big.NewInt(1)
		for jj := uint64(0); jj < rootNumBits-1; jj++ {
			if math.Mod(float64(ii), math.Pow(2, float64(jj))) < math.Pow(2, float64(jj-1)) {
				acc.Mul(acc, new(big.Int).ModInverse(proof.U[jj], ZKCurve.N)) // mod inverse might not be the correct thing...
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

	sumTemp := ZKCurve.Zero()
	for ii := 0; ii < 6; ii++ {
		whatBroke1 := proof.LeftVec[ii].Mult(proof.U[ii])
		whatBroke2 := proof.RightVec[ii].Mult(proof.UInv[ii])
		whatBroke3 := sumTemp
		sumTemp = whatBroke1.Add(whatBroke2.Add(whatBroke3))
	}

	total := thing1.Add(thing2.Add(thing3.Sub(sumTemp)))

	if !proof.P.Equal(total) {
		Dprintf("Internal check did not pass!\n")
		return false
	}

	return true
}

/*

// Read at your own risk, this was really messed up before trying the version above....
func InProdVerify1(G, H []ECPoint, proof InProdProof) bool {

	s := make([]*big.Int, numBits)
	sInv := make([]*big.Int, numBits)
	s[0] = proof.UInv[0]
	sInv[numBits-1] = s[0]
	for ii := 1; ii < int(numBits); ii++ {
		lgI := uint64(math.Log2(float64(ii)))
		k := 1 << lgI
		s[ii] = new(big.Int).Mod(new(big.Int).Mul(s[ii-k], proof.U[rootNumBits-1-lgI]), ZKCurve.N)
		sInv[int(numBits-1)-ii] = s[ii] // reverse order of s provides multiplicative inverse of s
	}

	// temp1 = <a * s, G>
	// temp2 = <b / s, H>
	// temp3 = abQ

	temp1 := ecDotProd(scalar(s, proof.A), G)
	temp2 := ecDotProd(scalar(sInv, proof.B), H)
	temp3 := proof.Q.Mult(new(big.Int).Mod(new(big.Int).Mul(proof.A, proof.B), ZKCurve.N))

	temps := temp1.Add(temp2.Add(temp3))

	// sumTemp = SUM(uL + uinvR) for j = 0 -> k-1
	sumTemp := ZKCurve.Zero()
	for ii := range proof.LeftVec {
		sumTemp = sumTemp.Add(proof.LeftVec[ii].Mult(proof.U[ii]).Add(proof.RightVec[ii].Mult(proof.UInv[ii])))
	}

	Dprintf("\n\nP: %v\nP': %v\n", proof.P, temps.Sub(sumTemp))

	// P ?= temps - sumTemp
	if !proof.P.Equal(temps.Sub(sumTemp)) {
		return false
	}

	return true
}
*/
