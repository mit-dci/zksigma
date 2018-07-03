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

type side int

const (
	left  side = 0
	right side = 1
)

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

func Init() {
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

	// For some reason modRandom doesnt work...
	// randomValue = rand() mod N
	// modRandom := new(big.Int).Mod(randomValue, zkCurve.N)

	// mG, rH :: lhs, rhs
	lhsX, lhsY := zkCurve.C.ScalarMult(zkCurve.G.X, zkCurve.G.Y, modValue.Bytes())
	rhsX, rhsY := zkCurve.C.ScalarMult(zkCurve.H.X, zkCurve.H.Y, randomValue.Bytes())

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

// EquivilanceProve generates an equivilance proof that Result1 and Result2 use the same discrete log x
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

	// HASH(G, H, xG, xH, kG, kH)
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

// EquivilanceVerify checks if a proof is valid
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

	// sG ?= uG + cG
	sGX, sGY := zkCurve.C.ScalarMult(Base1.X, Base1.Y, eqProof.HiddenValue.Bytes())
	cGX, cGY := zkCurve.C.ScalarMult(Result1.X, Result1.Y, eqProof.Challenge.Bytes())
	testX, testY := zkCurve.C.Add(eqProof.uG.X, eqProof.uG.Y, cGX, cGY)

	if sGX.Cmp(testX) != 0 || sGY.Cmp(testY) != 0 {
		Dprintf(" [crypto] lhs/rhs cmp failed. lhsX %v lhsY %v rhsX %v rhsY %v\n",
			sGX, sGY, testX, testY)
		return false
	}

	// sH ?= uH + cH
	sHX, sHY := zkCurve.C.ScalarMult(Base2.X, Base2.Y, eqProof.HiddenValue.Bytes())
	cHX, cHY := zkCurve.C.ScalarMult(Result2.X, Result2.Y, eqProof.Challenge.Bytes())
	testX, testY = zkCurve.C.Add(eqProof.uH.X, eqProof.uH.Y, cHX, cHY)

	if sHX.Cmp(testX) != 0 || sHY.Cmp(testY) != 0 {
		Dprintf(" [crypto] lhs/rhs cmp failed. lhsX %v lhsY %v rhsX %v rhsY %v\n",
			sHX, sHY, testX, testY)
		return false
	}

	// All three checks passed, proof must be correct
	return true

}

// The following ia combo of disjunctive proof and equivilance proofs

type EquivORLogProof struct {
	T1 ECPoint  // Either u1 * Base1 or s1*Base1 - c1 * Result1
	T2 ECPoint  // Either u1 * Base2 or s1*Base2 - c1 * Result2
	T3 ECPoint  // Either u2 * Base3 or s2*Base3 - c2 * Result3
	C  *big.Int // Either s1=u1 + c1x or random element
	C1 *big.Int // Either s2=u2 + c2x or random element
	C2 *big.Int // Challenge 1
	S1 *big.Int // Challenge 2
	S2 *big.Int // Sum of challenges
}

/*
	EquivilanceORLog Proofs:
	- Given A = xG, B = xH, D = yJ prove:
		- that A and B both have the same discrete log OR,
		- that we know the discrete log of D

	Public: generator points G, H, and J

	V									P
	Proving A and B use x
	know x AND/OR y						knows A = xG; B = xH; D = yJ // Can all be same base
	selects random u1, u2, u3
	T1 = u1G
	T2 = u1H
	T3 = u3J + (-u2)D // neg(u2)
	c = HASH(G, H, J, A, B, D, T1, T2, T3)
	deltaC = c + (-u2)
	s = u1 + deltaC * x

	T1, T2, T3, c, deltaC, u2, s, u3 -> T1, T2, T3, c, c1, c2, s1, s2
										c ?= HASH(G, H, J, A, B, D, T1, T2, T3)
										s1G ?= T1 + cA
										s1H ?= T2 + cB
										s2J ?= T3 + cD

	===================================================================
	V									P
	To prove that we know y
	know x AND/OR y						knows A = xG; B = xH; D = yJ // Can all be same base
	selects random u1, u2, u3
	T1 = u1G + (-u2)A
	T2 = u1H + (-u2)B
	T3 = u3J
	c = HASH(G, H, J, A, B, D, T1, T2, T3)
	deltaC = c + (-u2)
	s = u1 + deltaC * x

	T1, T2, T3, c, u2, deltaC, u1, s -> T1, T2, T3, c, c1, c2, s1, s2
										c ?= HASH(G, H, J, A, B, D, T1, T2, T3)
										s1G ?= T1 + cA
										s1H ?= T2 + cB
										s2J ?= T3 + cD

*/

func EquivilanceORLogProve(
	Base1, Result1, Base2, Result2, Base3, Result3 ECPoint,
	x *big.Int, option side) EquivORLogProof {

	u1, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)
	u2, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)
	u3, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)

	u2Neg := new(big.Int).Neg(u2)
	u2Neg.Mod(u2Neg, zkCurve.N)

	if option == left { //Proving Equivilance
		// u1G = T1
		T1X, T1Y := zkCurve.C.ScalarMult(Base1.X, Base1.Y, u1.Bytes())
		// u1H = T2
		T2X, T2Y := zkCurve.C.ScalarMult(Base2.X, Base2.Y, u1.Bytes())
		// u3J + (-u2)D = T3
		u3JX, u3JY := zkCurve.C.ScalarMult(Base3.X, Base3.Y, u3.Bytes())
		nu2DX, nu2DY := zkCurve.C.ScalarMult(Result3.X, Result3.Y, u2Neg.Bytes())
		T3X, T3Y := zkCurve.C.Add(u3JX, u3JY, nu2DX, nu2DY)

		// stringToHash = (G, H, J, A, B, D, T1, T2, T3)
		stringToHash := Base1.X.String() + "," + Base1.Y.String() + ";" +
			Base2.X.String() + "," + Base2.Y.String() + ";" +
			Base3.X.String() + "," + Base3.Y.String() + ";" +
			Result1.X.String() + "," + Result1.Y.String() + ";" +
			Result2.X.String() + "," + Result2.Y.String() + ";" +
			Result3.X.String() + "," + Result3.Y.String() + ";" +
			T1X.String() + "," + T1Y.String() + ";" +
			T2X.String() + "," + T2Y.String() + ";" +
			T3X.String() + "," + T3Y.String() + ";"

		hasher := sha256.New()
		hasher.Write([]byte(stringToHash))
		Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
		Challenge = Challenge.Mod(Challenge, zkCurve.N)

		deltaC := new(big.Int).Add(Challenge, u2Neg)
		deltaC.Mod(deltaC, zkCurve.N)

		s := new(big.Int).Add(u1, new(big.Int).Mul(deltaC, x))

		return EquivORLogProof{
			ECPoint{T1X, T1Y},
			ECPoint{T2X, T2Y},
			ECPoint{T3X, T3Y},
			Challenge, deltaC, u2, s, u3}

	} else { // Proving Discrete Log

		// u1G + (-u2A) = T1
		u1GX, u1GY := zkCurve.C.ScalarMult(Base1.X, Base1.Y, u1.Bytes())
		nu2AX, nu2AY := zkCurve.C.ScalarMult(Result1.X, Result1.Y, u2Neg.Bytes())
		T1X, T1Y := zkCurve.C.Add(u1GX, u1GY, nu2AX, nu2AY)
		// u1H + (-u2B) = T2
		u1HX, u1HY := zkCurve.C.ScalarMult(Base2.X, Base2.Y, u1.Bytes())
		nu2BX, nu2BY := zkCurve.C.ScalarMult(Result2.X, Result2.Y, u2Neg.Bytes())
		T2X, T2Y := zkCurve.C.Add(u1HX, u1HY, nu2BX, nu2BY)

		// u3J = T3
		T3X, T3Y := zkCurve.C.ScalarMult(Base3.X, Base3.Y, u3.Bytes())

		// stringToHash = (G, H, J, A, B, D, T1, T2, T3)
		stringToHash := Base1.X.String() + "," + Base1.Y.String() + ";" +
			Base2.X.String() + "," + Base2.Y.String() + ";" +
			Base3.X.String() + "," + Base3.Y.String() + ";" +
			Result1.X.String() + "," + Result1.Y.String() + ";" +
			Result2.X.String() + "," + Result2.Y.String() + ";" +
			Result3.X.String() + "," + Result3.Y.String() + ";" +
			T1X.String() + "," + T1Y.String() + ";" +
			T2X.String() + "," + T2Y.String() + ";" +
			T3X.String() + "," + T3Y.String() + ";"

		hasher := sha256.New()
		hasher.Write([]byte(stringToHash))
		Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
		Challenge = Challenge.Mod(Challenge, zkCurve.N)

		deltaC := new(big.Int).Add(Challenge, u2Neg)
		deltaC.Mod(deltaC, zkCurve.N)

		s := new(big.Int).Add(u1, new(big.Int).Mul(deltaC, x))

		return EquivORLogProof{
			ECPoint{T1X, T1Y},
			ECPoint{T2X, T2Y},
			ECPoint{T3X, T3Y},
			Challenge, u2, deltaC, u3, s}

	}

}

// =============== DISJUNCTIVE PROOFS ========================

// Referance: https://drive.google.com/file/d/0B_ndzgLH0bcvMjg3M1ROUWQwWTBCN0loQ055T212eV9JRU1v/view
// see section 4.2

/*
	Disjunctive Proofs: prove that you know either x or y but do not reveal
						which one you know

	Public: generator points G and H

	V			 						P
	(proving x)
	knows x AND/OR y					knows A = xG ; B = yH // can be yG
	selects random u1, u2, u3
	T1 = u1G
	T2 = u2H + (-u3)yH
	c = HASH(T1, T2, G, A, B)
	deltaC = c - u3
	s = u1 + deltaC * x

	(V perspective)						(P perspective)
	T1, T2, c, deltaC, u3, s, u2 -----> T1, T2, c, c1, c2, s1, s2
										c ?= HASH(T1, T2, G, A, B)
										c ?= c1 + c2 // mod zkCurve.N
										s1G ?= T1 + c1A
										s2G ?= T2 + c2A
	To prove y instead:
	Same as above with y in place of x
	T2, T1, c, u3, deltaC, u2, s -----> T1, T2, c, c1, c2, s1, s2
										Same checks as above

	Note:
	It should be indistingushiable for V with T1, T2, c, c1, c2, s1, s2
	to tell if we are proving x or y. The above arrows show how the variables
	used in the proof translate to T1, T2, etc.

	Sorry about the proof interaction summary above, trying to
	be consice with my comments in this code
*/

// DisjunctiveProof is also Generalized Schnorr Proof with FS-transform
type DisjunctiveProof struct {
	T1 ECPoint
	T2 ECPoint
	C  *big.Int
	C1 *big.Int
	C2 *big.Int
	S1 *big.Int
	S2 *big.Int
}

// DisjunctiveProve generates a disjunctive proof for the given x
func DisjunctiveProve(
	Base1, Result1, Base2, Result2 ECPoint, x *big.Int, option side) *DisjunctiveProof {

	// Declaring them like this because Golang crys otherwise
	ProveBase := zkCurve.Zero()
	ProveResult := zkCurve.Zero()
	OtherBase := zkCurve.Zero()
	OtherResult := zkCurve.Zero()

	// Generate a proof for A
	if option == left {
		ProveBase = Base1
		ProveResult = Result1
		OtherBase = Base2
		OtherResult = Result2
	} else if option == right { // Generate a proof for B
		ProveBase = Base2
		ProveResult = Result2
		OtherBase = Base1
		OtherResult = Result1
	} else { // number for option is not correct
		Dprintf("ERROR --- Invalid option number given for DisjunctiveProve\n")
		return nil
	}

	if !ProveBase.Mult(x).Equal(ProveResult) {
		Dprintf("Seems like we're lying about values we know...", x, ProveBase, ProveResult)
		// TODO: do something with error checking or whatever
		return nil
	}

	u1, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)
	u2, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)
	u3, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)
	// for (-u3)yH
	u3Neg := new(big.Int).Neg(u3)
	u3Neg.Mod(u3Neg, zkCurve.N)

	// T1 = u1G
	T1X, T1Y := zkCurve.C.ScalarMult(ProveBase.X, ProveBase.Y, u1.Bytes())

	// u2H
	tempX, tempY := zkCurve.C.ScalarMult(OtherBase.X, OtherBase.Y, u2.Bytes())
	// (-u3)yH
	temp2X, temp2Y := zkCurve.C.ScalarMult(OtherResult.X, OtherResult.Y, u3Neg.Bytes())
	// T2 = u2H + (-u3)yH (yH is OtherResult)
	T2X, T2Y := zkCurve.C.Add(tempX, tempY, temp2X, temp2Y)

	// String for proving Base1 and Result1
	stringToHash := Base1.X.String() + "," + Base1.Y.String() + ";" +
		Result1.X.String() + "," + Result1.Y.String() + ";" +
		Base2.X.String() + "," + Base2.Y.String() + ";" +
		Result2.X.String() + "," + Result2.Y.String() + ";" +
		T1X.String() + "," + T1Y.String() + ";" +
		T2X.String() + "," + T2Y.String() + ";"

	// If we are proving Base2 and Result2 then we must switch T1 and T2 in string
	if option == 1 {
		stringToHash = Base1.X.String() + "," + Base1.Y.String() + ";" +
			Result1.X.String() + "," + Result1.Y.String() + ";" +
			Base2.X.String() + "," + Base2.Y.String() + ";" +
			Result2.X.String() + "," + Result2.Y.String() + ";" +
			T2X.String() + "," + T2Y.String() + ";" +
			T1X.String() + "," + T1Y.String() + ";"
	}

	hasher := sha256.New()
	hasher.Write([]byte(stringToHash))
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))

	deltaC := new(big.Int).Sub(Challenge, u3)
	deltaC.Mod(deltaC, zkCurve.N)

	s := new(big.Int).Add(u1, new(big.Int).Mul(deltaC, x))

	// Look at mapping given in block comment above
	if option == left {
		return &DisjunctiveProof{
			ECPoint{T1X, T1Y},
			ECPoint{T2X, T2Y},
			Challenge,
			deltaC,
			u3,
			s,
			u2}
	} else {
		return &DisjunctiveProof{
			ECPoint{T2X, T2Y},
			ECPoint{T1X, T1Y},
			Challenge,
			u3,
			deltaC,
			u2,
			s}
	}

	// // Should never reach this statement, best not to have undefined behaviour though
	// Dprintf("ERROR --- Should not be here loc: AAA")
	// return nil
}

/*
	Copy-Pasta from above for convienence
	GIVEN: T1, T2, c, c1, c2, s1, s2
	c ?= HASH(T1, T2, G, A, B)
	c ?= c1 + c2 // mod zkCurve.N
	s1G ?= T1 + c1A
	s2G ?= T2 + c2A
*/

// DisjunctiveVerify checks if a djProof is valid for the given bases and results
func DisjunctiveVerify(
	Base1, Result1, Base2, Result2 ECPoint, djProof *DisjunctiveProof) bool {

	T1 := djProof.T1
	T2 := djProof.T2
	C := djProof.C
	C1 := djProof.C1
	C2 := djProof.C2
	S1 := djProof.S1
	S2 := djProof.S2

	stringToHash := Base1.X.String() + "," + Base1.Y.String() + ";" +
		Result1.X.String() + "," + Result1.Y.String() + ";" +
		Base2.X.String() + "," + Base2.Y.String() + ";" +
		Result2.X.String() + "," + Result2.Y.String() + ";" +
		T1.X.String() + "," + T1.Y.String() + ";" +
		T2.X.String() + "," + T2.Y.String() + ";"

	hasher := sha256.New()
	hasher.Write([]byte(stringToHash))
	// C
	checkC := new(big.Int).SetBytes(hasher.Sum(nil))
	if checkC.Cmp(C) != 0 {
		Dprintf("DJproof failed : checkC does not agree with proofC\n")
		return false
	}

	// C1 + C2
	totalC := new(big.Int).Add(C1, C2)
	totalC.Mod(totalC, zkCurve.N)
	if totalC.Cmp(C) != 0 {
		Dprintf("DJproof failed : totalC does not agree with proofC\n")
		return false
	}

	// T1 + c1A
	c1AX, c1AY := zkCurve.C.ScalarMult(Result1.X, Result1.Y, C1.Bytes())
	checks1GX, checks1GY := zkCurve.C.Add(c1AX, c1AY, T1.X, T1.Y)
	s1GX, s1GY := zkCurve.C.ScalarMult(Base1.X, Base1.Y, S1.Bytes())

	if checks1GX.Cmp(s1GX) != 0 || checks1GY.Cmp(s1GY) != 0 {
		Dprintf("DJproof failed : s1G not equal to T1 + c1A\n")
		return false
	}

	// T2 + c2B
	c2AX, c2AY := zkCurve.C.ScalarMult(Result2.X, Result2.Y, C2.Bytes())
	checks2GX, checks2GY := zkCurve.C.Add(c2AX, c2AY, T2.X, T2.Y)
	s2GX, s2GY := zkCurve.C.ScalarMult(Base2.X, Base2.Y, S2.Bytes())

	if checks2GX.Cmp(s2GX) != 0 || checks2GY.Cmp(s2GY) != 0 {
		Dprintf("DJproof failed : s2G not equal to T2 + c2B\n")
		return false
	}

	return true
}

// ============ zkLedger Stuff =======================
// ============ Consistance Proofs ===================

type ConsistencyProof struct {
	T1        ECPoint
	T2        ECPoint
	Challenge *big.Int
	s1        *big.Int
	s2        *big.Int
}

/*
	Consistency Proofs: similar to Equivilance proofs except that we
						make some assumptions about the public info.
						Here we want to prove that the r used in CM and
						Y are the same.


	Public:
	- generator points G and H,
	- PK (pubkey) = skH, // sk is secret key
	- CM (commitment) = vG + rH
	- Y = rPK

	V									P
	selects v and r for commitment		knows CM = vG + rH; Y = rPK
	selects random u1, u2
	T1 = u1G + u2H
	T2 = u2PK
	c = HASH(G, H, T1, T2, PK, CM, Y)
	s1 = u1 + c * v
	s2 = u2 + c * r

	T1, T2, c, s1, s2 ----------------->
										c ?= HASH(G, H, T1, T2, PK, CM, Y)
										s1G + s2H ?= T1 + cCM
										s2PK ?= T2 + cY
*/

func ConsistencyProve(
	Point1, Point2, PubKey ECPoint, value, randomness *big.Int) *ConsistencyProof {
	// Base1and Base2 will most likely be G and H, Result1 and Result2 will be xG and xH
	// x trying to be proved that both G and H are raised with x

	modValue := new(big.Int).Mod(value, zkCurve.N)
	//modRandom := new(big.Int).Mod(randomness, zkCurve.N)

	// do a quick correctness check to ensure the value we are testing and the
	// randomness are correct
	if !Point1.Equal(PedCommitR(value, randomness)) {
		fmt.Println("Tsk tsk tsk, lying about our commitments, ay?")
	}

	if !Point2.Equal(PubKey.Mult(randomness)) {
		fmt.Println(
			"Such disgrace! Lying about our Randomness Token! The audacity!")
	}

	u1, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)

	u2, err2 := rand.Int(rand.Reader, zkCurve.N)
	check(err2)

	T1 := PedCommitR(u1, u2)
	T2 := PubKey.Mult(u2)

	stringToHash := zkCurve.G.X.String() + "," + zkCurve.G.Y.String() + ";" +
		zkCurve.H.X.String() + "," + zkCurve.H.Y.String() + ";" +
		Point1.X.String() + "," + Point1.Y.String() + ";" +
		Point2.X.String() + "," + Point2.Y.String() + ";" +
		PubKey.X.String() + "," + PubKey.Y.String() + ";" +
		T1.X.String() + "," + T1.Y.String() + ";" +
		T2.X.String() + "," + T2.Y.String() + ";"

	hasher := sha256.New()
	hasher.Write([]byte(stringToHash))
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))

	s1 := new(big.Int).Add(u1, new(big.Int).Mul(modValue, Challenge))
	s2 := new(big.Int).Add(u2, new(big.Int).Mul(randomness, Challenge))
	s1.Mod(s1, zkCurve.N)
	s2.Mod(s2, zkCurve.N) // this was s1 instead of s2, took me an hour to find...

	// Really spammy debug statements if you want them for some reason
	// Dprintf("Proof T1 : %v\n", T1)
	// Dprintf("Proof T2 : %v\n", T2)
	// Dprintf("Proof C : %v\n", Challenge)
	// Dprintf("Proof S1 : %v\n", s1)
	// Dprintf("Proof S2 : %v\n", s2)
	// Dprintf("Proof T1 + cCM : %v\n", T1.Add(Point1.Mult(Challenge)))
	// Dprintf("Proof s1G + s2H : %v", PedCommitR(s1, s2))
	// Dprintf("Proof s2Pk : %v\n", PubKey.Mult(s2))
	// Dprintf("Proof T2 + cY : %v", T1.Add(Point2.Mult(Challenge)))

	return &ConsistencyProof{T1, T2, Challenge, s1, s2}

}

/*
	Give: T1, T2, c, s1, s2; Public: G, H, PK, CM, Y
	Check the following:
			c ?= HASH(G, H, T1, T2, PK, CM, Y)
	s1G + s2H ?= T1 + cCM
		 s2PK ?= T2 + cY
*/

// ConsistencyVerify checks if a proof is valid
func ConsistencyVerify(
	Point1, Point2, PubKey ECPoint, conProof *ConsistencyProof) bool {

	// CM should be point1, Y should be point2

	// Regenerate challenge string
	stringToHash := zkCurve.G.X.String() + "," + zkCurve.G.Y.String() + ";" +
		zkCurve.H.X.String() + "," + zkCurve.H.Y.String() + ";" +
		Point1.X.String() + "," + Point1.Y.String() + ";" +
		Point2.X.String() + "," + Point2.Y.String() + ";" +
		PubKey.X.String() + "," + PubKey.Y.String() + ";" +
		conProof.T1.X.String() + "," + conProof.T1.Y.String() + ";" +
		conProof.T2.X.String() + "," + conProof.T2.Y.String() + ";"

	hasher := sha256.New()
	hasher.Write([]byte(stringToHash))

	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))

	// c ?= HASH(G, H, T1, T2, PK, CM, Y)
	if Challenge.Cmp(conProof.Challenge) != 0 {
		Dprintf(" [crypto] c comparison failed. proof: %v calculated: %v\n",
			conProof.Challenge, Challenge)
		return false
	}
	// lhs = left hand side, rhs = right hand side
	// s1G + s2H ?= T1 + cCM, CM should be point1
	// s1G + s2H from how PedCommitR works
	lhs := PedCommitR(conProof.s1, conProof.s2)
	// cCM
	temp := Point1.Mult(Challenge)
	// T1 + cCM
	rhs := conProof.T1.Add(temp)

	if !lhs.Equal(rhs) {
		Dprintf("Point1 comparison is failing\n")
		return false
	}

	// s2PK ?= T2 + cY
	lhs = PubKey.Mult(conProof.s2)
	temp = Point2.Mult(Challenge)
	rhs = conProof.T2.Add(temp)

	if !lhs.Equal(rhs) {
		Dprintf("Point2 comparison is failing\n")
		return false
	}

	// All three checks passed, proof must be correct
	return true

}

// =================== AVERAGES ===================
// The following is to generate a proof if the transaction we are checking
// involves the bank being audited

/*
	For a commitment, A = vG + rH, if v != 0 then we need to map it to 1
	otherwise if v == 0 then we need to map it to 0

	if v != 0 then B = bG + r'H  (bG = inv(v)G)
	and C = cG + r''H (G is multiplied by 1 or c = ab = 1)

	else if v == 0 then C = rH (G is multiplied by 0)
	and B is disregarded

*/
/*
	Proving the case where v != 0 (b = inv(v), c = ab = 1)

	Public: G, H, CM, B, C, CMTok where
	- CM = vG + rH // we do not know r, only v
	- B = inv(v)G + r'H
	- C = G + r''H
	- CMTok = rPK = r(skH) // same r from A

	P 										V
	(Proving true statement)
	selects u1, u2, u3 at random			knows CM, B, C, CMTok
	selects ua, ub at random
	Compute:
	- T1 = u1G + u2Ta
	- T2 = u1B + u3H
	- c = HASH(G,H,A,B,C,T1,T2, Ta)
	Compute:
	- j = u1 + v * c				// can be though of as s1
	- k = u2 + inv(sk) * c			// s2
	- l = u3 + (uc - v * ub) * c 	// s3

	B, C, T1, T2, c, j, k, l  ------------->
											 proofA ?= true
	 										 proofC ?= true
											 c ?= HASH(G,H,A,B,C,T1,T2, Ta)
											 cCM + T1 ?= jG + kCMTok
											 cC + T2 ?= jB + lH


	(proving false statement)
	Everything is the same except v = 0 and inv(v) replaced with 0
	Compute:
	- T1 = u1G + u2Ta
	- T2 = (ub * u1 + u3)H


	TODO: think of speical properties of non-zero numbers
	to simulate a case for c = 0
*/

// TODO: differnt name for avgProof
type avgProof struct {
	B         ECPoint // commitment for b = 0 OR inv(a)
	C         ECPoint // commitment for c = 0 OR 1
	T1        ECPoint // commitment to test if ab = c
	T2        ECPoint // commitment to test if ab = c
	Challenge *big.Int
	j         *big.Int
	k         *big.Int
	l         *big.Int
	proofA    *GSPFSProof // proof that we know value of tx
	proofC    *GSPFSProof // proof that we know value of c
}

// TODO: add true and false flags to all proof gens incase of proof gen failure

// option left is proving that A and C commit to zero and simulates that A, B and C commit to v, inv(v) and 1 respectively
// option right is proving that A, B and C commit to v, inv(v) and 1 respectively and sumulating that A and C commit to 0
func averageProve(CM, CMTok ECPoint, value, sk *big.Int, option side) (avgProof, bool) {

	u1, err := rand.Int(rand.Reader, zkCurve.N)
	u2, err := rand.Int(rand.Reader, zkCurve.N)
	u3, err := rand.Int(rand.Reader, zkCurve.N)
	ub, err := rand.Int(rand.Reader, zkCurve.N)
	uc, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)

	if option == left {

		if value.Cmp(big.NewInt(0)) != 0 {
			Dprintf("We are lying about value of tx and trying to generate inccorect proof")
			return avgProof{}, false
		}

		// true statement and correct proofs for left side of OR
		proofA := GSPFSProve(value)
		proofC := GSPFSProve(big.NewInt(0))

		// starting false statemetn and correct proofs for right side of OR statement

		// B = 0 + ubH, here since we want to prove v = 0, we later accomidate for the lack of inverses
		B := PedCommitR(new(big.Int).ModInverse(big.NewInt(0), zkCurve.N), ub)

		// C = 0 + ucH
		C := PedCommitR(big.NewInt(0), uc)

		// T1 = u1G + u2Ta
		// u1G
		u1G := zkCurve.G.Mult(u1)
		// u2Ta
		u2Ta := CMTok.Mult(u2)
		// Sum the above two
		T1X, T1Y := zkCurve.C.Add(u1G.X, u1G.Y, u2Ta.X, u2Ta.Y)

		// T2 = (ub * u1 + u3)H
		// s = ub * u1 + u3
		s := new(big.Int).Add(u3, new(big.Int).Mul(ub, u1))
		T2 := zkCurve.H.Mult(s)

		stringToHash := zkCurve.G.X.String() + "," + zkCurve.G.Y.String() + ";" +
			zkCurve.H.X.String() + "," + zkCurve.H.Y.String() + ";" +
			CM.X.String() + "," + CM.Y.String() + ";" +
			CMTok.X.String() + "," + CMTok.Y.String() + ";" +
			B.X.String() + "," + B.Y.String() + ";" +
			C.X.String() + "," + C.Y.String() + ";" +
			T1X.String() + "," + T1Y.String() + ";" +
			T2.X.String() + "," + T2.Y.String() + ";"

		hasher := sha256.New()
		hasher.Write([]byte(stringToHash))
		Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
		Challenge = new(big.Int).Mod(Challenge, zkCurve.N)

		// j = u1 + v * c , v = 0
		j := u1
		j = new(big.Int).Mod(j, zkCurve.N)

		// k = u2 + inv(sk) * c
		// inv(sk)
		isk := new(big.Int).ModInverse(sk, zkCurve.N)
		k := new(big.Int).Add(u2, new(big.Int).Mul(isk, Challenge))
		k = new(big.Int).Mod(k, zkCurve.N)

		// l = u3 + (uc - v * ub) * c , v = 0
		l := new(big.Int).Add(u3, new(big.Int).Mul(uc, Challenge))

		return avgProof{
			B,
			C,
			ECPoint{T1X, T1Y},
			ECPoint{T2.X, T2.Y},
			Challenge,
			j, k, l,
			proofA, proofC}, true // TODO: fix the nils

	} else if option == right {

		if value.Cmp(big.NewInt(0)) == 0 {
			Dprintf("We are lying about value of tx and trying to generate inccorect proof")
			return avgProof{}, false
		}

		// TODO: do I use value or modValue for this?
		// modValue := new(big.Int).Mod(value, zkCurve.N)

		proofA := GSPFSProve(value)
		proofC := GSPFSProve(big.NewInt(1))

		// B = inv(v)G + ubH
		B := PedCommitR(new(big.Int).ModInverse(value, zkCurve.N), ub)

		// C = G + ucH
		C := PedCommitR(big.NewInt(1), uc)

		// T1 = u1G + u2Ta
		// u1G
		u1G := zkCurve.G.Mult(u1)
		// u2Ta
		u2Ta := CMTok.Mult(u2)
		// Sum the above two
		T1X, T1Y := zkCurve.C.Add(u1G.X, u1G.Y, u2Ta.X, u2Ta.Y)

		// T2 = u1B + u3H
		// u1B
		u1B := B.Mult(u1)
		// u3H
		u3H := zkCurve.H.Mult(u3)
		// Sum of the above two
		T2X, T2Y := zkCurve.C.Add(u1B.X, u1B.Y, u3H.X, u3H.Y)

		stringToHash := zkCurve.G.X.String() + "," + zkCurve.G.Y.String() + ";" +
			zkCurve.H.X.String() + "," + zkCurve.H.Y.String() + ";" +
			CM.X.String() + "," + CM.Y.String() + ";" +
			CMTok.X.String() + "," + CMTok.Y.String() + ";" +
			B.X.String() + "," + B.Y.String() + ";" +
			C.X.String() + "," + C.Y.String() + ";" +
			T1X.String() + "," + T1Y.String() + ";" +
			T2X.String() + "," + T2Y.String() + ";"

		hasher := sha256.New()
		hasher.Write([]byte(stringToHash))
		Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
		Challenge = new(big.Int).Mod(Challenge, zkCurve.N)

		// j = u1 + v * c , can be though of as s1
		j := new(big.Int).Add(u1, new(big.Int).Mul(value, Challenge))
		j = new(big.Int).Mod(j, zkCurve.N)

		// k = u2 + inv(sk) * c
		// inv(sk)
		isk := new(big.Int).ModInverse(sk, zkCurve.N)
		k := new(big.Int).Add(u2, new(big.Int).Mul(isk, Challenge))
		k = new(big.Int).Mod(k, zkCurve.N)

		// l = u3 + (uc - v * ub) * c
		temp := new(big.Int).Sub(uc, new(big.Int).Mul(value, ub))
		l := new(big.Int).Add(u3, new(big.Int).Mul(temp, Challenge))

		return avgProof{
			B,
			C,
			ECPoint{T1X, T1Y},
			ECPoint{T2X, T2Y},
			Challenge,
			j, k, l,
			proofA, proofC}, true

	} else {
		Dprintf("avgProof: side passed is not valid")
		return avgProof{}, false
	}
}

/*
	proofA ?= true
	proofC ?= true
	c ?= HASH(G,H,A,B,C,T1,T2, Ta)
	cA + T1 ?= jG + kTa
	cC + T2 ?= jB + lH
*/

func avgVerify(CM, CMTok ECPoint, aProof avgProof) bool {

	if !GSPFSVerify(CM, aProof.proofA) {
		Dprintf("avgProof for proofA is false")
		return false
	}

	if !GSPFSVerify(aProof.C, aProof.proofC) {
		Dprintf("avgProof for proofC is false")
		return false
	}

	stringToHash := zkCurve.G.X.String() + "," + zkCurve.G.Y.String() + ";" +
		zkCurve.H.X.String() + "," + zkCurve.H.Y.String() + ";" +
		CM.X.String() + "," + CM.Y.String() + ";" +
		CMTok.X.String() + "," + CMTok.Y.String() + ";" +
		aProof.B.X.String() + "," + aProof.B.Y.String() + ";" +
		aProof.C.X.String() + "," + aProof.C.Y.String() + ";" +
		aProof.T1.X.String() + "," + aProof.T1.Y.String() + ";" +
		aProof.T2.X.String() + "," + aProof.T2.Y.String() + ";"

	hasher := sha256.New()
	hasher.Write([]byte(stringToHash))
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, zkCurve.N)

	if Challenge.Cmp(aProof.Challenge) != 0 {
		Dprintf("avgVerify: proof contains incorrect chanllenge\n")
		return false
	}

	// cCM + T1 ?= jG + kCMTok
	// cCM
	chalA := CM.Mult(Challenge)
	// + T1
	lhs1 := chalA.Add(aProof.T1)
	//jG
	jG := zkCurve.G.Mult(aProof.j)
	// kCMTok
	kCMTok := CMTok.Mult(aProof.k)
	// jG + kCMTok
	rhs1 := jG.Add(kCMTok)

	if !lhs1.Equal(rhs1) {
		Dprintf("avgVerify: cCM + T1 != jG + kCMTok\n")
		return false
	}

	// cC + T2 ?= jB + lH
	chalC := aProof.C.Mult(Challenge)
	lhs2 := chalC.Add(aProof.T2)

	jB := aProof.B.Mult(aProof.j)
	lH := zkCurve.H.Mult(aProof.l)
	rhs2 := jB.Add(lH)

	if !lhs2.Equal(rhs2) {
		Dprintf("avgVerify: cC + T2 != jB + lH\n")
		return false
	}

	return true
}
