package zkCrypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"math/big"

	"github.com/narula/btcd/btcec"
)

// MAKE SURE TO CALL init() BEFORE DOING ANYTHING
// Global vars used to maintain all the crypto constants
var zkCurve zkpCrypto // look for init()
var H2tothe []ECPoint // look for init()

type ECPoint struct {
	X, Y *big.Int
}

// zkpCrypto is zero knowledge proof curve and params struct, only one instance should be used
type zkpCrypto struct {
	C  elliptic.Curve      // Curve, this is primarily used for it's operations, the Curve itself is not used
	KC *btcec.KoblitzCurve // Curve, this is the Curve used for
	G  ECPoint             // generator 1
	H  ECPoint             // generator 2
	N  *big.Int            // exponent prime
}

// Geeric stuff
func check(e error) {
	if e != nil {
		panic(e)
	}
}

var DEBUG = flag.Bool("debug", false, "Debug output")

// Dprintf is a generic debug statement generator
func Dprintf(format string, args ...interface{}) {
	if *DEBUG {
		fmt.Printf(format, args...)
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
	modS := new(big.Int).Mod(s, zkCurve.N)
	X, Y := zkCurve.C.ScalarMult(p.X, p.Y, modS.Bytes())
	return ECPoint{X, Y}
}

// Add adds points p and p2 and returns the resulting point
func (p ECPoint) Add(p2 ECPoint) ECPoint {
	X, Y := zkCurve.C.Add(p.X, p.Y, p2.X, p2.Y)
	return ECPoint{X, Y}
}

// Neg returns the addadtive inverse of point p
func (p ECPoint) Neg() ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := negY.Mod(negY, zkCurve.C.Params().P)
	return ECPoint{p.X, modValue}
}

// ============= BASIC zklCrypto OPERATIONS ==================
// These functions are not directly used in the code base much
// TODO: Remove the following functions and just use PedCommits

// CommitR uses the Public Key (pk) and a random number (r mod e.N) to generate a commitment of r as an ECPoint
// A commitment is the locking of a value with a public key that can be posted publically and verifed by everyone
func (e zkpCrypto) CommitR(pk ECPoint, r *big.Int) ECPoint {
	newR := new(big.Int).Mod(r, e.N)                 // newR = r mod e.N to generate a *bigInt
	X, Y := e.C.ScalarMult(pk.X, pk.Y, newR.Bytes()) // {commitR.X,commitR.Y} = newR * {pk.X, pk.Y}
	return ECPoint{X, Y}                             // ECPoint of commited Value
}

// VerifyR checks if the point in question is a valid commitment of R by generating a new point and comparing it
func (e zkpCrypto) VerifyR(rt ECPoint, pk ECPoint, r *big.Int) bool {
	p := e.CommitR(pk, r) // Generate test point (P) using pk and r
	if p.Equal(rt) {
		return true
	}
	return false
}

// Zero generates an ECPoint with the coordinates (0,0) typically to represent inifinty
func (e zkpCrypto) Zero() ECPoint {
	return ECPoint{big.NewInt(0), big.NewInt(0)}
}

// =============== KEYGEN OPERATIONS ==============

// The following code was just copy-pasta'ed into this codebase,
// I trust that the keygen stuff works, if it doesnt ask Willy

func NewECPrimeGroupKey() zkpCrypto {
	curValue := btcec.S256().Gx
	s256 := sha256.New()
	s256.Write(new(big.Int).Add(curValue, big.NewInt(2)).Bytes()) // hash G_x + 2 which

	potentialXValue := make([]byte, 33)
	binary.LittleEndian.PutUint32(potentialXValue, 2)
	for i, elem := range s256.Sum(nil) {
		potentialXValue[i+1] = elem
	}

	gen2, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
	check(err)

	return zkpCrypto{btcec.S256(), btcec.S256(), ECPoint{btcec.S256().Gx,
		btcec.S256().Gy}, ECPoint{gen2.X, gen2.Y}, btcec.S256().N}
}

func KeyGen() (ECPoint, *big.Int) {

	sk, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)
	pkX, pkY := zkCurve.C.ScalarMult(zkCurve.H.X, zkCurve.H.Y, sk.Bytes())

	return ECPoint{pkX, pkY}, sk
}

func DeterministicKeyGen(id int) (ECPoint, *big.Int) {
	idb := big.NewInt(int64(id + 1))
	pkX, pkY := zkCurve.C.ScalarMult(zkCurve.H.X, zkCurve.H.Y, idb.Bytes())
	return ECPoint{pkX, pkY}, idb
}

func GenerateH2tothe() []ECPoint {
	Hslice := make([]ECPoint, 64)
	for i, _ := range Hslice {
		// mv := new(big.Int).Exp(new(big.Int).SetInt64(2), big.NewInt(int64(len(bValue)-i-1)), EC.C.Params().N)
		// This does the same thing.
		m := big.NewInt(1 << uint(i))
		Hslice[i].X, Hslice[i].Y = zkCurve.C.ScalarBaseMult(m.Bytes())
	}
	return Hslice
}

func init() {
	zkCurve = NewECPrimeGroupKey()
	H2tothe = GenerateH2tothe()
}

// =============== PEDERSEN COMMITMENTS ================

// TODO: figure out if CommitR and PedCommit/R are redundant

// Commit generates a pedersen commitment of (value) using agreeded upon generators of (zkCurve),
// also returns the random value generated for the commitment
func PedCommit(value *big.Int) (ECPoint, *big.Int) {

	// modValue = value mod N
	modValue := new(big.Int).Mod(value, zkCurve.N)

	// randomValue = rand() mod N
	randomValue, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)

	// mG, rH :: lhs, rhs
	lhsX, lhsY := zkCurve.C.ScalarMult(zkCurve.G.X, zkCurve.G.Y, modValue.Bytes())
	rhsX, rhsY := zkCurve.C.ScalarMult(zkCurve.H.X, zkCurve.H.Y, randomValue.Bytes())

	//mG + rH
	commX, commY := zkCurve.C.Add(lhsX, lhsY, rhsX, rhsY)

	return ECPoint{commX, commY}, randomValue
}

// CommitWithR generates a pedersen commitment with a given random value
func PedCommitR(value, randomValue *big.Int) ECPoint {

	// modValue = value mod N
	modValue := new(big.Int).Mod(value, zkCurve.N)

	// randomValue = rand() mod N
	modRandom := new(big.Int).Mod(randomValue, zkCurve.N)

	// mG, rH :: lhs, rhs
	lhsX, lhsY := zkCurve.C.ScalarMult(zkCurve.G.X, zkCurve.G.Y, modValue.Bytes())
	rhsX, rhsY := zkCurve.C.ScalarMult(zkCurve.H.X, zkCurve.H.Y, modRandom.Bytes())

	//mG + rH
	commX, commY := zkCurve.C.Add(lhsX, lhsY, rhsX, rhsY)

	return ECPoint{commX, commY}
}

// Open checks if the values given result in the PedComm being varifed
func Open(value, randomValue *big.Int, PedComm ECPoint) bool {

	// Generate commit using given values
	testCommit := PedCommitR(value, randomValue)
	return testCommit.Equal(PedComm)
}

// =========== GENERALIZED SCHNORR PROOFS ===============

// GSPFS is Generalized Schnorr Proofs with Fiat-Shamir transform
// TODO: change the json stuff

// GSPFSProof is proof of knowledge of x
type GSPFSProof struct {
	RandCommit  ECPoint  `json:"T"` // this is H = uG, where u is random value and G is a generator point
	HiddenValue *big.Int `json:"R"` // s = x * c + u, here c is the challenge and x is what we want to prove knowledge of
	Challenge   *big.Int `json:"C"` // challenge string hash sum, only use for sanity checks
}

/*
	Schnorr Proof: prove that we know x withot revealing x

	Public: generator points G and H

	V									P
	know x								knows A = xG //doesnt know x and G just A
	selects random u
	T1 = uG
	c = HASH(G, xG, uG)
	s = u + c * x

	T1, s, c -------------------------->
										c ?= HASH(G, A, T1)
										sG ?= T1 + cA

*/

// GSPFSProve generates a Schnorr proof for the value x
func GSPFSProve(x *big.Int) *GSPFSProof {

	// res = xG
	resX, resY := zkCurve.C.ScalarMult(zkCurve.G.X, zkCurve.G.Y, x.Bytes())

	// u is a raondom number
	u, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)

	// generate random point uG
	uX, uY := zkCurve.C.ScalarMult(zkCurve.G.X, zkCurve.G.Y, u.Bytes())

	// genereate string to hash for challenge
	stringToHash := zkCurve.G.X.String() + "," + zkCurve.G.Y.String() + "," +
		resX.String() + "," + resY.String() + "," +
		uX.String() + "," + uY.String()

	stringHashed := sha256.Sum256([]byte(stringToHash))

	// c = bigInt(SHA256(stringToHash))
	Challenge := new(big.Int).SetBytes(stringHashed[:])

	// v = u - c * x
	HiddenValue := new(big.Int).Sub(u, new(big.Int).Mul(Challenge, x))
	HiddenValue.Mod(HiddenValue, zkCurve.N)

	return &GSPFSProof{ECPoint{uX, uY}, HiddenValue, Challenge}
}

// TODO: check if result should be within the proof

// Verify checks if a proof-commit pair is valid
func GSPFSVerify(result ECPoint, proof *GSPFSProof) bool {
	// Remeber that result = xG and RandCommit = uG

	hasher := sha256.New()

	stringToHash := zkCurve.G.X.String() + "," + zkCurve.G.Y.String() + "," +
		result.X.String() + "," + result.Y.String() + "," +
		proof.RandCommit.X.String() + "," + proof.RandCommit.Y.String()

	// testC is the challenge string generated from the Proof and commitment being verified
	hasher.Write([]byte(stringToHash))
	testC := new(big.Int).SetBytes(hasher.Sum(nil))

	// (u - c * x)G, look at HiddenValue from GSPFS.Proof()
	sX, sY := zkCurve.C.ScalarMult(zkCurve.G.X, zkCurve.G.Y, proof.HiddenValue.Bytes())

	// cResult = c(xG), we use testC as that follows the proof verficaion process more closely than using Challenge
	cX, cY := zkCurve.C.ScalarMult(result.X, result.Y, testC.Bytes())

	// cxG + (u - cx)G = uG
	totX, totY := zkCurve.C.Add(sX, sY, cX, cY)

	if proof.RandCommit.X.Cmp(totX) != 0 || proof.RandCommit.Y.Cmp(totY) != 0 {
		return false
	}
	return true
}

// =========== EQUIVILANCE PROOFS ===================

type EquivProof struct {
	uG          ECPoint // kG is the scalar mult of k (random num) with base G
	uH          ECPoint
	Challenge   *big.Int // Challenge is hash sum of challenge commitment
	HiddenValue *big.Int // Hidden Value hides the discrete log x that we want to prove equivilance for
}

/*
	Equivilance Proofs: prove that both A and B both use x as a discrete log

	Public: generator points G and H

	V									P
	know x								knows A = xG ; B = xH
	selects random u
	T1 = uG
	T2 = uH
	c = HASH(G, H, xG, xH, uG, uH)
	s = u + c * x

	T1, T2, s, c ---------------------->
										c ?= HASH(G, H, A, B, T1, T2)
										sG ?= T1 + cA
										sH ?= T2 + cB
*/

func EquivilanceProve(
	Base1, Result1, Base2, Result2 ECPoint, x *big.Int) EquivProof {
	// Base1and Base2 will most likely be G and H, Result1 and Result2 will be xG and xH
	// x trying to be proved that both G and H are raised with x

	checkX, checkY := zkCurve.C.ScalarMult(Base1.X, Base1.Y, x.Bytes())
	if checkX.Cmp(Result1.X) != 0 || checkY.Cmp(Result1.Y) != 0 {
		Dprintf("EquivProof check: Base1 and Result1 are not related by x... \n")
	}
	checkX, checkY = zkCurve.C.ScalarMult(Base2.X, Base2.Y, x.Bytes())
	if checkX.Cmp(Result2.X) != 0 || checkY.Cmp(Result2.Y) != 0 {
		Dprintf("EquivProof check: Base2 and Result2 are not related by x... \n")
	}

	// random number
	u, err := rand.Int(rand.Reader, zkCurve.N) // random number to hide x later
	check(err)

	// uG
	uBase1X, uBase1Y := zkCurve.C.ScalarMult(Base1.X, Base1.Y, u.Bytes())
	// uH
	uBase2X, uBase2Y := zkCurve.C.ScalarMult(Base2.X, Base2.Y, u.Bytes())

	// HASH( G, H, xG, xH, kG, kH)
	stringToHash := Base1.X.String() + "||" + Base1.Y.String() + ";" +
		Base2.X.String() + "||" + Base2.Y.String() + ";" +
		Result1.X.String() + "||" + Result1.Y.String() + ";" +
		Result2.X.String() + "||" + Result2.Y.String() + ";" +
		uBase1X.String() + "||" + uBase1Y.String() + ";" +
		uBase2X.String() + "||" + uBase2Y.String() + ";"

	hasher := sha256.New()
	hasher.Write([]byte(stringToHash))

	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))

	HiddenValue := new(big.Int).Add(u, new(big.Int).Mul(Challenge, x))
	HiddenValue.Mod(HiddenValue, zkCurve.N)

	return EquivProof{
		ECPoint{uBase1X, uBase1Y}, // uG
		ECPoint{uBase2X, uBase2Y}, // uH
		Challenge,
		HiddenValue} //Kinda dumb this bracket cannot be on the next line...

}

func EquivilanceVerify(
	Base1, Result1, Base2, Result2 ECPoint, eqProof EquivProof) bool {
	// Regenerate challenge string
	stringToHash := Base1.X.String() + "||" + Base1.Y.String() + ";" +
		Base2.X.String() + "||" + Base2.Y.String() + ";" +
		Result1.X.String() + "||" + Result1.Y.String() + ";" +
		Result2.X.String() + "||" + Result2.Y.String() + ";" +
		eqProof.uG.X.String() + "||" + eqProof.uG.Y.String() + ";" +
		eqProof.uH.X.String() + "||" + eqProof.uH.Y.String() + ";"

	hasher := sha256.New()
	hasher.Write([]byte(stringToHash))

	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))

	if Challenge.Cmp(eqProof.Challenge) != 0 {
		Dprintf(" [crypto] c comparison failed. proof: %v calculated: %v\n",
			eqProof.Challenge, Challenge)
		return false
	}

	return true

}
