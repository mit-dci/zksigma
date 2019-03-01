package zksigma

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/mit-dci/zksigma/btcec"
	"github.com/mit-dci/zksigma/wire"
)

// ZKPCurveParams is zero knowledge proof curve and params struct, only one instance should be used
type ZKPCurveParams struct {
	C       elliptic.Curve // Curve
	G       ECPoint        // generator 1
	H       ECPoint        // generator 2
	HPoints []ECPoint      // HPoints should be initialized with a pre-populated array of the ZKCurve's generator point H multiplied by 2^x where x = [0...63]
}

// DEBUG Indicates whether we output debug information while running the tests. Default off.
var DEBUG = flag.Bool("debug1", false, "Debug output")

type errorProof struct {
	t string // proof type that failed
	s string // error message
}

func (e *errorProof) Error() string {
	return fmt.Sprintf("%v - %v\n", e.t, e.s)
}

func proofStatus(e *errorProof) int {
	if *DEBUG && e != nil {
		fmt.Printf("ERROR: %v \n", e.Error())
		return -1
	}
	return 0
}

func logStuff(format string, args ...interface{}) {
	if *DEBUG {
		log.SetFlags(log.Lshortfile)
		log.Printf(format, args...)
	}
}

// == Keygen ==

func KeyGen(curve elliptic.Curve, base ECPoint) (ECPoint, *big.Int) {

	sk, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	pkX, pkY := curve.ScalarMult(base.X, base.Y, sk.Bytes())

	return ECPoint{pkX, pkY}, sk
}

// BigZero contains a cached instance of big.Int with value 0
var BigZero *big.Int

// ============ ECPoint OPERATIONS ==================

type ECPoint struct {
	X, Y *big.Int
}

// Zero is a cached variable containing ECPoint{big.NewInt(0), big.NewInt(0)}
var Zero ECPoint // initialized in init()

// Equal returns true if points p (self) and p2 (arg) are the same.
func (p ECPoint) Equal(p2 ECPoint) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

// Mult multiplies point p by scalar s and returns the resulting point
func (zkpcp ZKPCurveParams) Mult(p ECPoint, s *big.Int) ECPoint {

	if p.X == nil && p.Y == nil { // Multiplying a nil point is "pointless". ha.
		return ECPoint{nil, nil}
	}

	modS := new(big.Int).Mod(s, zkpcp.C.Params().N)

	// if p.Equal(Zero) {
	// 	logStuff("Mult: Trying to multiple with zero-point!\n")
	// 	return p
	// } else
	if p.Equal(zkpcp.G) {
		X, Y := zkpcp.C.ScalarBaseMult(modS.Bytes())
		return ECPoint{X, Y}
	}

	if p.Equal(zkpcp.H) {
		X, Y := zkpcp.C.(*btcec.KoblitzCurve).ScalarBaseMultH(modS.Bytes())
		return ECPoint{X, Y}
	}

	X, Y := zkpcp.C.ScalarMult(p.X, p.Y, modS.Bytes())
	return ECPoint{X, Y}
}

// Add adds points p and p2 and returns the resulting point
func (zkpcp ZKPCurveParams) Add(p, p2 ECPoint) ECPoint {
	// if p.Equal(Zero) && p2.Equal(Zero) {
	// 	return Zero
	// } else
	if p.Equal(Zero) && zkpcp.C.IsOnCurve(p2.X, p2.Y) {
		return p2
	} else if p2.Equal(Zero) && zkpcp.C.IsOnCurve(p.X, p.Y) {
		return p
	}

	X, Y := zkpcp.C.Add(p.X, p.Y, p2.X, p2.Y)

	return ECPoint{X, Y}
}

func (zkpcp ZKPCurveParams) Sub(p, p2 ECPoint) ECPoint {
	// if p.Equal(Zero) && p2.Equal(Zero) {
	// 	return Zero
	// } else
	if p.Equal(Zero) && zkpcp.C.IsOnCurve(p2.X, p2.Y) {
		return zkpcp.Neg(p2)
	} else if p2.Equal(Zero) && zkpcp.C.IsOnCurve(p.X, p.Y) {
		return p
	}

	temp := zkpcp.Neg(p2)
	X, Y := zkpcp.C.Add(p.X, p.Y, temp.X, temp.Y)

	return ECPoint{X, Y}
}

// Neg returns the additive inverse of point p
func (zkpcp ZKPCurveParams) Neg(p ECPoint) ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := new(big.Int).Mod(negY, zkpcp.C.Params().P)
	return ECPoint{p.X, modValue}
}

func (p ECPoint) Bytes() []byte {
	return append(p.X.Bytes(), p.Y.Bytes()...)
}

// WriteECPoint write an ECPoint to io.Writer w
func WriteECPoint(w io.Writer, p ECPoint) error {
	err := wire.WriteVarBytes(w, p.X.Bytes())
	if err != nil {
		return err
	}
	err = wire.WriteVarBytes(w, p.Y.Bytes())
	return err
}

// ReadECPoint reads an ECPoint from io.Reader r
func ReadECPoint(r io.Reader) (ECPoint, error) {
	xBytes, err := wire.ReadVarBytes(r, 32, "x")
	if err != nil {
		return Zero, err
	}
	yBytes, err := wire.ReadVarBytes(r, 32, "y")
	if err != nil {
		return Zero, err
	}
	return ECPoint{X: big.NewInt(0).SetBytes(xBytes), Y: big.NewInt(0).SetBytes(yBytes)}, nil
}

// WriteBigInt write a big.Int to io.Writer w
func WriteBigInt(w io.Writer, b *big.Int) error {
	neg := []byte{0x00}
	if b.Sign() < 0 {
		neg = []byte{0x01}
	}
	err := wire.WriteVarBytes(w, append(neg, b.Bytes()...))
	return err
}

// ReadBigInt reads a big.Int from io.Reader r
func ReadBigInt(r io.Reader) (*big.Int, error) {
	bBytes, err := wire.ReadVarBytes(r, 32, "")
	if err != nil {
		return nil, err
	}
	newInt := big.NewInt(0).SetBytes(bBytes[1:])
	if bBytes[0] == 0x01 {
		newInt.Neg(newInt)
	}
	return newInt, nil
}

// CommitR uses the Public Key (pk) and a random number (r) to
// generate a commitment of r as an ECPoint
func CommitR(zkpcp ZKPCurveParams, pk ECPoint, r *big.Int) ECPoint {
	newR := new(big.Int).Mod(r, zkpcp.C.Params().N)
	X, Y := zkpcp.C.ScalarMult(pk.X, pk.Y, newR.Bytes()) // {commitR.X,commitR.Y} = newR * {pk.X, pk.Y}
	return ECPoint{X, Y}
}

// VerifyR checks if the point in question is a valid commitment of r
// by generating a new point and comparing the two
func VerifyR(zkpcp ZKPCurveParams, rt ECPoint, pk ECPoint, r *big.Int) bool {
	p := CommitR(zkpcp, pk, r) // Generate test point (P) using pk and r
	return p.Equal(rt)
}

// =============== PEDERSEN COMMITMENTS ================
// PedCommit generates a pedersen commitment of value using the
// generators of zkpcp.  It returns the randomness generated for the
// commitment.
func PedCommit(zkpcp ZKPCurveParams, value *big.Int) (ECPoint, *big.Int, error) {
	// randomValue = rand() mod N
	randomValue, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return Zero, nil, err
	}
	return PedCommitR(zkpcp, value, randomValue), randomValue, nil
}

// PedCommitR generates a Pedersen commitment with a given random value
func PedCommitR(zkpcp ZKPCurveParams, value, randomValue *big.Int) ECPoint {

	// modValue = value mod N
	modValue := new(big.Int).Mod(value, zkpcp.C.Params().N)
	modRandom := new(big.Int).Mod(randomValue, zkpcp.C.Params().N)

	// mG, rH :: lhs, rhs
	lhs := zkpcp.Mult(zkpcp.G, modValue)
	rhs := zkpcp.Mult(zkpcp.H, modRandom)

	//mG + rH
	return zkpcp.Add(lhs, rhs)
}

// Open checks if the values given result in the given Pedersen commitment
func Open(zkpcp ZKPCurveParams, value, randomValue *big.Int, pcomm ECPoint) bool {
	return PedCommitR(zkpcp, value, randomValue).Equal(pcomm)

}

// ====== Generalized Hash Function =========

// GenerateChallenge hashes the passed byte arrays using SHA-256, and then returns
// the resulting hash as a big.Int modulo the order of the curve base point
func GenerateChallenge(zkpcp ZKPCurveParams, arr ...[]byte) *big.Int {
	hasher := sha256.New()
	for _, v := range arr {
		hasher.Write(v)
	}
	c := new(big.Int).SetBytes(hasher.Sum(nil))
	c = new(big.Int).Mod(c, zkpcp.C.Params().N)
	return c
}

// ====== init =========

func init() {

	BigZero = big.NewInt(0)
	Zero = ECPoint{BigZero, BigZero}

}
