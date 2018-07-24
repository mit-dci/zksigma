package zkCrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type Generator struct {
	N    uint64
	M    uint64
	VecG []ECPoint
	VecH []ECPoint
}

type GeneratorView struct {
	G *ECPoint
	H *ECPoint
}

const (
	numBits uint64 = 64
	numVals uint64 = 2
)

var ZKGen *Generator
var ZKView *GeneratorView

func BPInit() {
	ZKGen = NewGen(numBits, numVals)
}

// NewGen generates a new chain of ECPoints that are linked by consecutive hashes
func NewGen(n, m uint64) *Generator {
	BPGen := Generator{}

	BPGen.N = n
	BPGen.M = m

	u1, _ := rand.Int(rand.Reader, ZKCurve.N)
	u2, _ := rand.Int(rand.Reader, ZKCurve.N)
	VecG := genChain(n, m, u1.Bytes())
	VecH := genChain(n, m, u2.Bytes())

	BPGen.VecG = VecG
	BPGen.VecH = VecH

	return &BPGen
}

func genChain(n, m uint64, initBytes []byte) []ECPoint {
	vec := make([]ECPoint, n*m)

	hasher := sha256.New()
	hasher.Write(initBytes)
	pointX, pointY := ZKCurve.C.ScalarBaseMult(hasher.Sum(nil))
	vec[0] = ECPoint{pointX, pointY}

	for ii := uint64(1); ii < n*m; ii++ {
		hasher.Write(vec[ii-1].Bytes())
		pointX, pointY = ZKCurve.C.ScalarBaseMult(hasher.Sum(nil))
		vec[ii] = ECPoint{pointX, pointY}
	}

	return vec
}

func (g *Generator) Share(j uint64) *GeneratorView {
	return &GeneratorView{&g.VecG[j], &g.VecH[j]}
}

//======== Perliminary stuff

var PowsOf2 []*big.Int
var ZeroVec []*big.Int
var OnesVec []*big.Int

func fillVecs() {
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
		if new(big.Int).Rem(value, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
			result[ii] = big.NewInt(1)
			value.Quo(value, big.NewInt(2))
			continue
		}
		result[ii] = big.NewInt(0)
		value.Quo(value, big.NewInt(2))
	}

	return result
}

func dotProd(x, y []*big.Int) *big.Int {

	if len(x) != len(y) || len(x) != int(numBits) {
		return big.NewInt(0)
	}

	acc := big.NewInt(0)
	for ii := uint64(0); ii < numBits; ii++ {
		acc.Add(new(big.Int).Mul(x[ii], y[ii]), big.NewInt(0))
	}
	return acc
}

func ecDotProd(x []*big.Int, y []ECPoint) []ECPoint {
	if len(x) != len(y) || len(x) != int(numBits) || len(y) != int(numBits) {
		return []ECPoint{}
	}

	res := make([]ECPoint, numBits)
	for ii := uint64(0); ii < numBits; ii++ {
		res[ii].X, res[ii].Y = ZKCurve.C.ScalarMult(y[ii].X, y[ii].Y, x[ii].Bytes())
	}
	return res

}

// COM(vec1, vec2, uH) -> <vec1, G> + <vec2, H> + uB', where B' is the ped commit blinder, G and H are chain vecots
func vecPedComm(a []*big.Int, G []ECPoint, H []ECPoint) ([]ECPoint, *big.Int) {
	if len(a) != len(G) || len(a) != len(H) || len(a) != int(numBits) {
		return []ECPoint{}, nil
	}

	randomness, _ := rand.Int(rand.Reader, ZKCurve.N)

	res := make([]ECPoint, len(a))
	for ii, vv := range a {
		temp1 := G[ii].Mult(vv)
		temp2 := H[ii].Mult(new(big.Int).Mod(new(big.Int).Sub(vv, OnesVec[0]), ZKCurve.N))
		temp3 := ZKCurve.H.Mult(randomness)
		res[ii] = temp1.Add(temp2).Add(temp3)
	}

	return res, randomness

}

func vecMult(x, y []*big.Int) []*big.Int {

	if len(x) != len(y) || len(x) != int(numBits) {
		return []*big.Int{}
	}

	res := make([]*big.Int, numBits)
	for ii := uint64(0); ii < numBits; ii++ {
		res[ii] = new(big.Int).Mul(x[ii], y[ii])
	}
	return res
}

func splitVec(x []*big.Int) ([]*big.Int, []*big.Int) {

	if len(x)%2 != 0 {
		return []*big.Int{}, []*big.Int{}
	}

	return x[0 : len(x)/2-1], x[len(x)/2 : len(x)]
}

func genVec(x *big.Int) []*big.Int {
	res := make([]*big.Int, numBits)

	for ii := int64(0); ii < int64(numBits); ii++ {
		res[ii] = new(big.Int).Exp(x, big.NewInt(ii), ZKCurve.N)
	}
	return res
}

func scalarMult(x []*big.Int, y *big.Int) []*big.Int {
	if len(x)%2 != 0 {
		return []*big.Int{}
	}

	res := make([]*big.Int, numBits)
	for ii := uint64(0); ii < numBits; ii++ {
		res[ii] = new(big.Int).Mul(x[ii], y)
	}
	return res

}

// t(x) = ax^2 bx + c
type TwoDegPoly struct {
	a []*big.Int
	b []*big.Int
	c []*big.Int
}

// evalualte t(x)
func (p *TwoDegPoly) EvalAt(x *big.Int) []*big.Int {
	res := make([]*big.Int, numBits)
	// I know this looks nasty
	for ii := uint64(0); ii < numBits; ii++ {
		res[ii] = new(big.Int).Add(new(big.Int).Add(new(big.Int).Mul(p.b[ii], x), p.c[ii]), new(big.Int).Mul(p.a[ii], x).Mul(x, big.NewInt(1)))
	}

	return res
}

//========== INNER PRODUCT PROOF =========

type InProdProof struct {
	a        *big.Int
	b        *big.Int
	LeftVec  []ECPoint
	RightVec []ECPoint
}
