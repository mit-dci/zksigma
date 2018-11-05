package zkSigma

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"math/big"

	"github.com/narula/btcd/btcec"
)

var DEBUG = flag.Bool("debug1", false, "Debug output")
var NOBASIC = flag.Bool("nobasic", false, "Skips basic tests")
var EVILPROOF = flag.Bool("testevil", false, "Tries to generate a false proof and make it pass verification")

// Global variables used to maintain all the crypto constants
var ZKCurve zkpCrypto // initialized in init()
var HPoints []ECPoint // initialized in init()
var Zero ECPoint      // initialized in init()

type ECPoint struct {
	X, Y *big.Int
}

// zkpCrypto is zero knowledge proof curve and params struct, only one instance should be used
type zkpCrypto struct {
	C elliptic.Curve // Curve
	G ECPoint        // generator 1
	H ECPoint        // generator 2
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type errorProof struct {
	t string // proof type that failed
	s string // error message
}

func (e *errorProof) Error() string {
	return fmt.Sprintf("%v - %v", e.t, e.s)
}

func proofStatus(e *errorProof) int {
	if e != nil {
		logStuff("ERROR: %v \n", e.Error())
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

// ============ BASIC ECPoint OPERATIONS ==================

// Equal returns true if points p (self) and p2 (arg) are the same.
func (p ECPoint) Equal(p2 ECPoint) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

// Mult multiplies point p by scalar s and returns the resulting point
func (p ECPoint) Mult(s *big.Int) ECPoint {
	modS := new(big.Int).Mod(s, ZKCurve.C.Params().N)

	if p.Equal(Zero) {
		logStuff("Mult: Trying to multiple with zero-point!\n")
		return p
	} else if ZKCurve.C.IsOnCurve(p.X, p.Y) {
		X, Y := ZKCurve.C.ScalarMult(p.X, p.Y, modS.Bytes())
		return ECPoint{X, Y}
	} else if !ZKCurve.C.IsOnCurve(p.X, p.Y) {
		logStuff("ECPoint.Add():\n - p and p2 is not on the curve\n")
		logStuff(" -  POINT: %v\n - SCALAR: %v\n", p, s)
		return ECPoint{nil, nil}
	}

	logStuff("Mult: we should not get here...")
	return ECPoint{nil, nil}
}

func SBaseMult(s *big.Int) ECPoint {
	modS := new(big.Int).Mod(s, ZKCurve.C.Params().N)
	X, Y := ZKCurve.C.ScalarBaseMult(modS.Bytes())
	return ECPoint{X, Y}
}

// Add adds points p and p2 and returns the resulting point
func (p ECPoint) Add(p2 ECPoint) ECPoint {
	if p.Equal(Zero) && ZKCurve.C.IsOnCurve(p2.X, p2.Y) {
		return p2
	} else if p2.Equal(Zero) && ZKCurve.C.IsOnCurve(p.X, p.Y) {
		return p
	} else if !ZKCurve.C.IsOnCurve(p.X, p.Y) || !ZKCurve.C.IsOnCurve(p2.X, p2.Y) {
		logStuff("ECPoint.Add():\n - p and p2 is not on the curve\n")
		logStuff(" -  POINT: %v\n - POINT2: %v\n", p, p2)
		return ECPoint{nil, nil}
	}

	X, Y := ZKCurve.C.Add(p.X, p.Y, p2.X, p2.Y)

	return ECPoint{X, Y}
}

func (p ECPoint) Sub(p2 ECPoint) ECPoint {
	if p.Equal(Zero) && ZKCurve.C.IsOnCurve(p2.X, p2.Y) {
		return p2.Neg()
	} else if p2.Equal(Zero) && ZKCurve.C.IsOnCurve(p.X, p.Y) {
		return p
	} else if !ZKCurve.C.IsOnCurve(p.X, p.Y) || !ZKCurve.C.IsOnCurve(p2.X, p2.Y) {
		logStuff("ECPoint.Add():\n - p and p2 is not on the curve\n")
		logStuff(" -  POINT: %v\n - POINT2: %v\n", p, p2)
		return ECPoint{nil, nil}
	}

	temp := p2.Neg()
	X, Y := ZKCurve.C.Add(p.X, p.Y, temp.X, temp.Y)

	return ECPoint{X, Y}
}

// Neg returns the additive inverse of point p
func (p ECPoint) Neg() ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := new(big.Int).Mod(negY, ZKCurve.C.Params().P)
	return ECPoint{p.X, modValue}
}

func (p ECPoint) Bytes() []byte {
	return append(p.X.Bytes(), p.Y.Bytes()...)
}

// ============= BASIC zkCrypto OPERATIONS ==================

// *****************************************
// * USED PedCommit and PedCommitR INSTEAD *
// *****************************************

// CommitR uses the Public Key (pk) and a random number (r mod e.N) to generate a commitment of r as an ECPoint
// A commitment is the locking of a value with a public key that can be posted publically and verifed by everyone
func (e zkpCrypto) CommitR(pk ECPoint, r *big.Int) ECPoint {
	newR := new(big.Int).Mod(r, ZKCurve.C.Params().N)
	X, Y := e.C.ScalarMult(pk.X, pk.Y, newR.Bytes()) // {commitR.X,commitR.Y} = newR * {pk.X, pk.Y}
	return ECPoint{X, Y}
}

// VerifyR checks if the point in question is a valid commitment of R by generating a new point and comparing it
func (e zkpCrypto) VerifyR(rt ECPoint, pk ECPoint, r *big.Int) bool {
	p := e.CommitR(pk, r) // Generate test point (P) using pk and r
	if p.Equal(rt) {
		return true
	}
	return false
}

// =============== KEYGEN OPERATIONS ==============

// The following code was just copy-past'ed into this codebase,
// I trust that the keygen stuff works, if it doesnt ask Willy

func NewECPrimeGroupKey() zkpCrypto {
	curValue := ECPoint{btcec.S256().Gx, btcec.S256().Gy}
	s256 := sha256.New()
	hashedString := s256.Sum([]byte("This is the new Random point and stuff"))

	HX, HY := btcec.S256().ScalarMult(curValue.X, curValue.Y, hashedString)

	return zkpCrypto{btcec.S256(), ECPoint{btcec.S256().Gx,
		btcec.S256().Gy}, ECPoint{HX, HY}}
}

func KeyGen() (ECPoint, *big.Int) {

	sk, err := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	check(err)
	pkX, pkY := ZKCurve.C.ScalarMult(ZKCurve.H.X, ZKCurve.H.Y, sk.Bytes())

	return ECPoint{pkX, pkY}, sk
}

func GenerateH2tothe() []ECPoint {
	Hslice := make([]ECPoint, 64)
	for i := range Hslice {
		m := big.NewInt(1 << uint(i))
		Hslice[i].X, Hslice[i].Y = ZKCurve.C.ScalarMult(ZKCurve.H.X, ZKCurve.H.Y, m.Bytes())
	}
	return Hslice
}

func init() {
	ZKCurve = NewECPrimeGroupKey()
	HPoints = GenerateH2tothe()
	Zero = ECPoint{big.NewInt(0), big.NewInt(0)}
}

// =============== PEDERSEN COMMITMENTS ================

// PedCommit generates a pedersen commitment of (value) using agreeded upon generators of (ZKCurve),
// also returns the random value generated for the commitment
func PedCommit(value *big.Int) (ECPoint, *big.Int) {

	// modValue = value mod N
	modValue := new(big.Int).Mod(value, ZKCurve.C.Params().N)

	// randomValue = rand() mod N
	randomValue, err := rand.Int(rand.Reader, ZKCurve.C.Params().N)
	check(err)

	// mG, rH :: lhs, rhs
	// mG, rH :: lhs, rhs
	lhs := SBaseMult(modValue)
	rhs := ZKCurve.H.Mult(randomValue)

	//mG + rH
	return lhs.Add(rhs), randomValue
}

// CommitWithR generates a pedersen commitment with a given random value
func PedCommitR(value, randomValue *big.Int) ECPoint {

	// modValue = value mod N
	modValue := new(big.Int).Mod(value, ZKCurve.C.Params().N)
	modRandom := new(big.Int).Mod(randomValue, ZKCurve.C.Params().N)

	// mG, rH :: lhs, rhs
	lhs := SBaseMult(modValue)
	rhs := ZKCurve.H.Mult(modRandom)

	//mG + rH
	return lhs.Add(rhs)
}

// Open checks if the values given result in the PedComm being varifed
func Open(value, randomValue *big.Int, PedComm ECPoint) bool {

	// Generate commit using given values
	testCommit := PedCommitR(value, randomValue)
	return testCommit.Equal(PedComm)
}

// ====== Generalized Hash Function =========

func GenerateChallenge(arr ...[]byte) *big.Int {

	hasher := sha256.New()

	for _, v := range arr {
		hasher.Write(v)
	}

	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.C.Params().N)

	return Challenge
}
