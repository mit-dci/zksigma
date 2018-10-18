package zkSigma

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"math/big"

	"github.com/narula/btcd/btcec"
)

// FLAGS
var DEBUG = flag.Bool("debug1", false, "Debug output")
var NOBASIC = flag.Bool("nobasic", true, "Skips basic tests")

// MAKE SURE TO CALL init() BEFORE DOING ANYTHING
// Global vars used to maintain all the crypto constants
var ZKCurve zkpCrypto // look for init()
var HPoints []ECPoint // look for init()

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
	C elliptic.Curve // Curve, this is primarily used for it's operations, the Curve itself is not used
	G ECPoint        // generator 1
	H ECPoint        // generator 2
	N *big.Int       // exponent prime
}

// Geeric stuff
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
		fmt.Printf("ERROR: %v \n", e.Error())
		return -1
	}
	return 0
}

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
	modS := new(big.Int).Mod(s, ZKCurve.N)
	X, Y := ZKCurve.C.ScalarMult(p.X, p.Y, modS.Bytes())
	return ECPoint{X, Y}
}

// Add adds points p and p2 and returns the resulting point
func (p ECPoint) Add(p2 ECPoint) ECPoint {
	if p.Equal(ZKCurve.Zero()) && ZKCurve.C.IsOnCurve(p2.X, p2.Y) {
		return p2
	} else if p2.Equal(ZKCurve.Zero()) && ZKCurve.C.IsOnCurve(p.X, p.Y) {
		return p
	} else if !ZKCurve.C.IsOnCurve(p.X, p.Y) || !ZKCurve.C.IsOnCurve(p2.X, p2.Y) {
		Dprintf("ECPoint.Add():\n - p and p2 is not on the curve\n")
		Dprintf(" -  POINT: %v\n - POINT2: %v\n", p, p2)
		return ECPoint{nil, nil}
	}

	X, Y := ZKCurve.C.Add(p.X, p.Y, p2.X, p2.Y)

	return ECPoint{X, Y}
}

func (p ECPoint) Sub(p2 ECPoint) ECPoint {
	if p.Equal(ZKCurve.Zero()) && ZKCurve.C.IsOnCurve(p2.X, p2.Y) {
		return p2.Neg()
	} else if p2.Equal(ZKCurve.Zero()) && ZKCurve.C.IsOnCurve(p.X, p.Y) {
		return p
	} else if !ZKCurve.C.IsOnCurve(p.X, p.Y) || !ZKCurve.C.IsOnCurve(p2.X, p2.Y) {
		Dprintf("ECPoint.Add():\n - p and p2 is not on the curve\n")
		Dprintf(" -  POINT: %v\n - POINT2: %v\n", p, p2)
		return ECPoint{nil, nil}
	}

	temp := p2.Neg()
	X, Y := ZKCurve.C.Add(p.X, p.Y, temp.X, temp.Y)

	return ECPoint{X, Y}
}

// Neg returns the addadtive inverse of point p
func (p ECPoint) Neg() ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := negY.Mod(negY, ZKCurve.C.Params().P)
	return ECPoint{p.X, modValue}
}

func (p ECPoint) Bytes() []byte {
	return append(p.X.Bytes(), p.Y.Bytes()...)
}

// ============= BASIC zklCrypto OPERATIONS ==================

// *****************************************
// * USED PedCommit and PedCommitR INSTEAD *
// *****************************************

// CommitR uses the Public Key (pk) and a random number (r mod e.N) to generate a commitment of r as an ECPoint
// A commitment is the locking of a value with a public key that can be posted publically and verifed by everyone
func (e zkpCrypto) CommitR(pk ECPoint, r *big.Int) ECPoint {
	newR := new(big.Int).Mod(r, e.N)
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

// Zero generates an ECPoint with the coordinates (0,0) typically to represent inifinty
func (e zkpCrypto) Zero() ECPoint {
	return ECPoint{big.NewInt(0), big.NewInt(0)}
}

// =============== KEYGEN OPERATIONS ==============

// The following code was just copy-pasta'ed into this codebase,
// I trust that the keygen stuff works, if it doesnt ask Willy

func NewECPrimeGroupKey() zkpCrypto {
	curValue := ECPoint{btcec.S256().Gx, btcec.S256().Gy}
	s256 := sha256.New()
	hashedString := s256.Sum([]byte("This is the new Random point and stuff"))

	HX, HY := btcec.S256().ScalarMult(curValue.X, curValue.Y, hashedString)

	return zkpCrypto{btcec.S256(), ECPoint{btcec.S256().Gx,
		btcec.S256().Gy}, ECPoint{HX, HY}, btcec.S256().N}
}

func KeyGen() (ECPoint, *big.Int) {

	sk, err := rand.Int(rand.Reader, ZKCurve.N)
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

func Init() {
	ZKCurve = NewECPrimeGroupKey()
	HPoints = GenerateH2tothe()
}

// =============== PEDERSEN COMMITMENTS ================

// PedCommit generates a pedersen commitment of (value) using agreeded upon generators of (ZKCurve),
// also returns the random value generated for the commitment
func PedCommit(value *big.Int) (ECPoint, *big.Int) {

	// modValue = value mod N
	modValue := new(big.Int).Mod(value, ZKCurve.N)

	// randomValue = rand() mod N
	randomValue, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	// mG, rH :: lhs, rhs
	// mG, rH :: lhs, rhs
	lhsX, lhsY := ZKCurve.C.ScalarBaseMult(modValue.Bytes())
	rhs := ZKCurve.H.Mult(randomValue)

	//mG + rH
	return ECPoint{lhsX, lhsY}.Add(rhs), randomValue
}

// CommitWithR generates a pedersen commitment with a given random value
func PedCommitR(value, randomValue *big.Int) ECPoint {

	// modValue = value mod N
	modValue := new(big.Int).Mod(value, ZKCurve.N)
	modRandom := new(big.Int).Mod(randomValue, ZKCurve.N)

	// mG, rH :: lhs, rhs
	lhsX, lhsY := ZKCurve.C.ScalarBaseMult(modValue.Bytes())
	rhs := ZKCurve.H.Mult(modRandom)

	//mG + rH
	return ECPoint{lhsX, lhsY}.Add(rhs)
}

// Open checks if the values given result in the PedComm being varifed
func Open(value, randomValue *big.Int, PedComm ECPoint) bool {

	// Generate commit using given values
	testCommit := PedCommitR(value, randomValue)
	return testCommit.Equal(PedComm)
}

// =========== GENERALIZED SCHNORR PROOFS ===============

// GSPFS is Generalized Schnorr Proofs with Fiat-Shamir transform
// GSPFSProof is proof of knowledge of x

type GSPFSProof struct {
	Base        ECPoint  // Base point
	RandCommit  ECPoint  // this is H = uG, where u is random value and G is a generator point
	HiddenValue *big.Int // s = x * c + u, here c is the challenge and x is what we want to prove knowledge of
	Challenge   *big.Int // challenge string hash sum, only use for sanity checks
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
// TODO: this should also take in the pulic commit rather than generating it internal
func GSPFSProve(result ECPoint, x *big.Int) *GSPFSProof {

	return GSPAnyBaseProve(ZKCurve.G, result, x)
}

func GSPAnyBaseProve(base, result ECPoint, x *big.Int) *GSPFSProof {

	modValue := new(big.Int).Mod(x, ZKCurve.N)

	test := base.Mult(modValue)

	// res = xG, G is any base point in this proof
	if !test.Equal(result) {
		Dprintf("GSPFSProve: the point given is not xG\n")
		return &GSPFSProof{}
	}

	// u is a raondom number
	u, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	// generate random point uG
	uG := base.Mult(u)

	// genereate string to hash for challenge
	temp := [][]byte{result.Bytes(), uG.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	// v = u - c * x
	HiddenValue := new(big.Int).Sub(u, new(big.Int).Mul(Challenge, modValue))
	HiddenValue = HiddenValue.Mod(HiddenValue, ZKCurve.N)

	return &GSPFSProof{base, uG, HiddenValue, Challenge}
}

// GSPFSVerify checks if a proof-commit pair is valid
func GSPFSVerify(result ECPoint, proof *GSPFSProof) bool {
	// Remeber that result = xG and RandCommit = uG

	hasher := sha256.New()

	temp := [][]byte{result.Bytes(), proof.RandCommit.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	// testC is the challenge string generated from the Proof and commitment being verified
	hasher.Write(bytesToHash)
	testC := new(big.Int).SetBytes(hasher.Sum(nil))
	testC = new(big.Int).Mod(testC, ZKCurve.N)

	if testC.Cmp(proof.Challenge) != 0 {
		Dprintf("GSPFSVerify: testC and proof's challenge do not agree!\n")
		return false
	}

	var s ECPoint
	if proof.Base.Equal(ZKCurve.G) {
		// (u - c * x)G, look at HiddenValue from GSPFS.Proof()
		s.X, s.Y = ZKCurve.C.ScalarBaseMult(proof.HiddenValue.Bytes())
	} else {
		s = proof.Base.Mult(proof.HiddenValue)
	}

	// cResult = c(xG), we use testC as that follows the proof verficaion process more closely than using Challenge
	c := result.Mult(proof.Challenge)

	// cxG + (u - cx)G = uG
	tot := s.Add(c)

	if !proof.RandCommit.Equal(tot) {
		return false
	}
	return true
}

// =========== EQUIVILANCE PROOFS ===================

type EquivProof struct {
	UG          ECPoint // kG is the scalar mult of k (random num) with base G
	UH          ECPoint
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
	Base1, Result1, Base2, Result2 ECPoint, x *big.Int) (EquivProof, error) {
	// Base1and Base2 will most likely be G and H, Result1 and Result2 will be xG and xH
	// x trying to be proved that both G and H are raised with x

	modValue := new(big.Int).Mod(x, ZKCurve.N)
	check1 := Base1.Mult(modValue)

	if !check1.Equal(Result1) {
		Dprintf("EquivProof check: Base1 and Result1 are not related by x\n")
		return EquivProof{}, &errorProof{"EquivilanceProve", "Base1 and Result1 are not related by x"}
	}

	check2 := Base2.Mult(modValue)
	if !check2.Equal(Result2) {
		Dprintf("EquivProof check: Base2 and Result2 are not related by x... \n")
		return EquivProof{}, &errorProof{"EquivilanceProve", "Base2 and Result2 are not related by x"}
	}

	// random number
	u, err := rand.Int(rand.Reader, ZKCurve.N) // random number to hide x later
	check(err)

	// uG
	uBase1 := Base1.Mult(u)
	// uH
	uBase2 := Base2.Mult(u)

	// HASH(G, H, xG, xH, uG, uH)
	temp := [][]byte{Base1.Bytes(), Result1.Bytes(), Base2.Bytes(), Result2.Bytes(), uBase1.Bytes(), uBase2.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)

	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	// s = u + c * x
	HiddenValue := new(big.Int).Add(u, new(big.Int).Mul(Challenge, modValue))
	HiddenValue = HiddenValue.Mod(HiddenValue, ZKCurve.N)

	return EquivProof{
		uBase1, // uG
		uBase2, // uH
		Challenge,
		HiddenValue}, nil

}

/*
	c ?= HASH(G, H, A, B, T1, T2)
	sG ?= T1 + cA
	sH ?= T2 + cB
*/
// EquivilanceVerify checks if a proof is valid
func EquivilanceVerify(
	Base1, Result1, Base2, Result2 ECPoint, eqProof EquivProof) bool {
	// Regenerate challenge string
	temp := [][]byte{Base1.Bytes(), Result1.Bytes(), Base2.Bytes(), Result2.Bytes(), eqProof.UG.Bytes(), eqProof.UH.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)

	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	if Challenge.Cmp(eqProof.Challenge) != 0 {
		Dprintf(" [crypto] c comparison failed. proof: %v calculated: %v\n",
			eqProof.Challenge, Challenge)
		return false
	}

	// sG ?= uG + cA
	sG := Base1.Mult(eqProof.HiddenValue)
	cG := Result1.Mult(eqProof.Challenge)
	test := eqProof.UG.Add(cG)

	if !sG.Equal(test) {
		Dprintf("EquiviVerify: sG comparison did not pass\n")
		return false
	}

	// sH ?= uH + cB
	sH := Base2.Mult(eqProof.HiddenValue)
	cH := Result2.Mult(eqProof.Challenge)
	test = eqProof.UH.Add(cH)

	if !sH.Equal(test) {
		Dprintf("EquivVerify: sH comparison did not pass\n")
		return false
	}

	// All three checks passed, proof must be correct
	return true

}

// =============== DISJUNCTIVE PROOFS ========================

// Referance: https://drive.google.com/file/d/0B_ndzgLH0bcvMjg3M1ROUWQwWTBCN0loQ055T212eV9JRU1v/view
// see section 4.2

/*
	Disjunctive Proofs: prove that you know either x or y but do not reveal
						which one you know

	Public: generator points G and H, A, B

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
										c ?= c1 + c2 // mod ZKCurve.N
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
	Base1, Result1, Base2, Result2 ECPoint, x *big.Int, option side) (*DisjunctiveProof, error) {

	modValue := new(big.Int).Mod(x, ZKCurve.N)

	// Declaring them like this because Golang crys otherwise
	var ProveBase, ProveResult, OtherBase, OtherResult ECPoint

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
		Dprintf("DisjunctiveProve: side provided is not valid\n")
		return &DisjunctiveProof{}, &errorProof{"DisjunctiveProve", "invalid side provided"}
	}

	if !ProveBase.Mult(x).Equal(ProveResult) {
		Dprintf("DisjunctiveProve: ProveBase and ProveResult are not related by x!\n")
		return &DisjunctiveProof{}, &errorProof{"DisjunctiveProve", "Base and Result to be proved not related by x"}
	}

	u1, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)
	u2, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)
	u3, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)
	// for (-u3)yH
	u3Neg := new(big.Int).Neg(u3)
	u3Neg.Mod(u3Neg, ZKCurve.N)

	// T1 = u1G
	T1 := ProveBase.Mult(u1)

	// u2H
	temp := OtherBase.Mult(u2)
	// (-u3)yH
	temp2 := OtherResult.Mult(u3Neg)
	// T2 = u2H + (-u3)yH (yH is OtherResult)
	T2 := temp.Add(temp2)

	var tempArr [][]byte
	if option == 0 {
		// String for proving Base1 and Result1
		tempArr = [][]byte{Base1.Bytes(), Result1.Bytes(), Base2.Bytes(), Result2.Bytes(), T1.Bytes(), T2.Bytes()}
	} else {
		// If we are proving Base2 and Result2 then we must switch T1 and T2 in string
		tempArr = [][]byte{Base1.Bytes(), Result1.Bytes(), Base2.Bytes(), Result2.Bytes(), T2.Bytes(), T1.Bytes()}
	}

	var bytesToHash []byte
	for _, v := range tempArr {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	deltaC := new(big.Int).Sub(Challenge, u3)
	deltaC.Mod(deltaC, ZKCurve.N)

	s := new(big.Int).Add(u1, new(big.Int).Mul(deltaC, modValue))

	// Look at mapping given in block comment above
	if option == left {
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

/*
	Copy-Pasta from above for convienence
	GIVEN: T1, T2, c, c1, c2, s1, s2
	c ?= HASH(T1, T2, G, A, B)
	c ?= c1 + c2 // mod ZKCurve.N
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

	temp := [][]byte{Base1.Bytes(), Result1.Bytes(), Base2.Bytes(), Result2.Bytes(), T1.Bytes(), T2.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)
	checkC := new(big.Int).SetBytes(hasher.Sum(nil))
	checkC = new(big.Int).Mod(checkC, ZKCurve.N)

	if checkC.Cmp(C) != 0 {
		Dprintf("DJproof failed : checkC does not agree with proofC\n")
		return false
	}

	// C1 + C2
	totalC := new(big.Int).Add(C1, C2)
	totalC.Mod(totalC, ZKCurve.N)
	if totalC.Cmp(C) != 0 {
		Dprintf("DJproof failed : totalC does not agree with proofC\n")
		return false
	}

	// T1 + c1A
	c1A := Result1.Mult(C1)
	checks1G := T1.Add(c1A)
	s1G := Base1.Mult(S1)

	if !checks1G.Equal(s1G) {
		Dprintf("DJproof failed : s1G not equal to T1 + c1A\n")
		return false
	}

	// T2 + c2B
	c2A := Result2.Mult(C2)
	checks2G := c2A.Add(T2)
	s2G := Base2.Mult(S2)

	if !checks2G.Equal(s2G) {
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
	- CMTok = rPK

	V									P
	selects v and r for commitment		knows CM = vG + rH; CMTok = rPK
	selects random u1, u2
	T1 = u1G + u2H
	T2 = u2PK
	c = HASH(G, H, T1, T2, PK, CM, CMTok)
	s1 = u1 + c * v
	s2 = u2 + c * r

	T1, T2, c, s1, s2 ----------------->
										c ?= HASH(G, H, T1, T2, PK, CM, CMTok)
										s1G + s2H ?= T1 + cCM
										s2PK ?= T2 + cCMTok
*/

func ConsistencyProve(
	CM, CMTok, PubKey ECPoint, value, randomness *big.Int) (*ConsistencyProof, error) {
	// Base1and Base2 will most likely be G and H, Result1 and Result2 will be xG and xH
	// x trying to be proved that both G and H are raised with x

	modValue := new(big.Int).Mod(value, ZKCurve.N)
	//modRandom := new(big.Int).Mod(randomness, ZKCurve.N)

	// do a quick correctness check to ensure the value we are testing and the
	// randomness are correct
	if !CM.Equal(PedCommitR(value, randomness)) {
		Dprintf("ConsistancyProve: Commitment passed does not match value and randomness\n")
		return &ConsistencyProof{}, &errorProof{"ConsistancyProve", "value and randomVal does not produce CM"}
	}

	if !CMTok.Equal(PubKey.Mult(randomness)) {
		Dprintf("ConsistancyProve:Randomness token does not match pubkey and randomValue\n")
		return &ConsistencyProof{}, &errorProof{"ConsistancyProve", "Pubkey and randomVal does not produce CMTok"}
	}

	u1, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	u2, err2 := rand.Int(rand.Reader, ZKCurve.N)
	check(err2)

	T1 := PedCommitR(u1, u2)
	T2 := PubKey.Mult(u2)

	temp := [][]byte{ZKCurve.G.Bytes(), ZKCurve.H.Bytes(), CM.Bytes(), CMTok.Bytes(), PubKey.Bytes(), T1.Bytes(), T2.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	s1 := new(big.Int).Add(u1, new(big.Int).Mul(modValue, Challenge))
	s2 := new(big.Int).Add(u2, new(big.Int).Mul(randomness, Challenge))
	s1.Mod(s1, ZKCurve.N)
	s2.Mod(s2, ZKCurve.N) // this was s1 instead of s2, took me an hour to find...

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

	return &ConsistencyProof{T1, T2, Challenge, s1, s2}, nil

}

/*
	Give: T1, T2, c, s1, s2; Public: G, H, PK, CM, CMTok
	Check the following:
			c ?= HASH(G, H, T1, T2, PK, CM, CMTok)
	s1G + s2H ?= T1 + cCM
		 s2PK ?= T2 + cCMTok
*/

// ConsistencyVerify checks if a proof is valid
func ConsistencyVerify(
	CM, CMTok, PubKey ECPoint, conProof *ConsistencyProof) bool {

	// CM should be point1, Y should be point2

	// Regenerate challenge string
	temp := [][]byte{ZKCurve.G.Bytes(), ZKCurve.H.Bytes(), CM.Bytes(), CMTok.Bytes(), PubKey.Bytes(), conProof.T1.Bytes(), conProof.T2.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	// c ?= HASH(G, H, T1, T2, PK, CM, Y)
	if Challenge.Cmp(conProof.Challenge) != 0 {
		Dprintf("ConsistancyVerify: c comparison failed. proof: %v calculated: %v\n",
			conProof.Challenge, Challenge)
		return false
	}
	// lhs = left hand side, rhs = right hand side
	// s1G + s2H ?= T1 + cCM, CM should be point1
	// s1G + s2H from how PedCommitR works
	lhs := PedCommitR(conProof.s1, conProof.s2)
	// cCM
	temp1 := CM.Mult(Challenge)
	// T1 + cCM
	rhs := conProof.T1.Add(temp1)

	if !lhs.Equal(rhs) {
		Dprintf("CM check is failing\n")
		return false
	}

	// s2PK ?= T2 + cY
	lhs = PubKey.Mult(conProof.s2)
	temp1 = CMTok.Mult(Challenge)
	rhs = conProof.T2.Add(temp1)

	if !lhs.Equal(rhs) {
		Dprintf("CMTok check is failing\n")
		return false
	}

	// All three checks passed, proof must be correct
	return true

}

// =================== a * b = c MULTIPLICATIVE RELATIONSHIP ===================
// The following is to generate a proof if the transaction we are checking
// involves the bank being audited

/*
	ABCProof: generate a proof that commitment C is either 0 or 1
			  depending on if we are involved in a tx. This will later
			  be used to generate a sum to preform an average calculation

	Public: G, H, CM, B, C, CMTok where
	- CM = vG + uaH // we do not know ua, only v
	- B = inv(v)G + ubH //inv is multiplicative inverse, in the case of v = 0, inv(v) = 0
	- C = (v * inv(v))G + ucH
	- CMTok = rPK = r(skH) // same r from A

	P 										V
	generate in order:
	- commitment of inv(v), B
	- commitment of v * inv(v), C // either 0 or 1 ONLY
	- Disjunctive proof of a = 0 or c = 1
	select u1, u2, u3 at random
	select ub, uc at random
	Compute:
	- T1 = u1G + u2CMTok
	- T2 = u1B + u3H
	- c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	Compute:
	- j = u1 + v * c
	- k = u2 + inv(sk) * c
	- l = u3 + (uc - v * ub) * c

	disjuncAC, B, C, T1, T2, c, j, k, l
								   	------->
											 disjuncAC ?= true
											 c ?= HASH(G,H,CM,CMTok,B,C,T1,T2)
											 cCM + T1 ?= jG + kCMTok
											 cC + T2 ?= jB + lH
*/

type ABCProof struct {
	B         ECPoint  // commitment for b = 0 OR inv(v)
	C         ECPoint  // commitment for c = 0 OR 1 ONLY
	T1        ECPoint  // T1 = u1G + u2MTok
	T2        ECPoint  // T2 = u1B + u3H
	Challenge *big.Int //c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	j         *big.Int // j = u1 + v * c
	k         *big.Int // k = u2 + inv(sk) * c
	l         *big.Int // l = u3 + (uc - v * ub) * c
	CToken    ECPoint
	disjuncAC *DisjunctiveProof
}

// option left is proving that A and C commit to zero and simulates that A, B and C commit to v, inv(v) and 1 respectively
// option right is proving that A, B and C commit to v, inv(v) and 1 respectively and sumulating that A and C commit to 0
func ABCProve(CM, CMTok ECPoint, value, sk *big.Int, option side) (*ABCProof, error) {

	// We cannot check that CM log is acutally the value, but the verification should catch that

	u1, err := rand.Int(rand.Reader, ZKCurve.N)
	u2, err := rand.Int(rand.Reader, ZKCurve.N)
	u3, err := rand.Int(rand.Reader, ZKCurve.N)
	ub, err := rand.Int(rand.Reader, ZKCurve.N)
	uc, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	B := ECPoint{}
	C := ECPoint{}
	CToken := ZKCurve.H.Mult(sk).Mult(uc)

	disjuncAC := new(DisjunctiveProof)
	var e error
	// Disjunctive Proof of a = 0 or c = 1
	if option == left && value.Cmp(big.NewInt(0)) == 0 {
		// MUST:a = 0! ; side = left
		// B = 0 + ubH, here since we want to prove v = 0, we later accomidate for the lack of inverses
		B = PedCommitR(new(big.Int).ModInverse(big.NewInt(0), ZKCurve.N), ub)

		// C = 0 + ucH
		C = PedCommitR(big.NewInt(0), uc)

		// CM is considered the "base" of CMTok since it would be only uaH and not ua sk H
		// C - G is done regardless of the c = 0 or 1 becuase in the case c = 0 it does matter what that random number is
		disjuncAC, e = DisjunctiveProve(CM, CMTok, ZKCurve.H, C.Sub(ZKCurve.G), sk, left)
	} else if option == right && value.Cmp(big.NewInt(0)) != 0 {
		// MUST:c = 1! ; side = right

		B = PedCommitR(new(big.Int).ModInverse(value, ZKCurve.N), ub)

		// C = G + ucH
		C = PedCommitR(big.NewInt(1), uc)

		// Look at notes a couple lines above on what the input is like this
		disjuncAC, e = DisjunctiveProve(CM, CMTok, ZKCurve.H, C.Sub(ZKCurve.G), uc, right)
	} else {
		Dprintf("ABCProof: Side/value combination not correct\n")
		return &ABCProof{}, &errorProof{"ABCProof", "invalid side-value pair passed"}
	}

	if e != nil {
		Dprintf("Disjunctive Proof in ABCProof failed to generated!\n")
		return &ABCProof{}, &errorProof{"ABCProof", "DisjuntiveProve within ABCProve failed to generate"}
	}

	// CMTok is Ta for the rest of the proof
	// T1 = u1G + u2Ta
	// u1G
	u1G := ZKCurve.G.Mult(u1)
	// u2Ta
	u2Ta := CMTok.Mult(u2)
	// Sum the above two
	T1X, T1Y := ZKCurve.C.Add(u1G.X, u1G.Y, u2Ta.X, u2Ta.Y)

	// T2 = u1B + u3H
	// u1B
	u1B := B.Mult(u1)
	// u3H
	u3H := ZKCurve.H.Mult(u3)
	// Sum of the above two
	T2X, T2Y := ZKCurve.C.Add(u1B.X, u1B.Y, u3H.X, u3H.Y)

	// c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	temp := [][]byte{ZKCurve.G.Bytes(), ZKCurve.H.Bytes(), CM.Bytes(), CMTok.Bytes(), B.Bytes(), C.Bytes(), T1X.Bytes(), T1Y.Bytes(), T2X.Bytes(), T2Y.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	// j = u1 + v * c , can be though of as s1
	j := new(big.Int).Add(u1, new(big.Int).Mul(value, Challenge))
	j = new(big.Int).Mod(j, ZKCurve.N)

	// k = u2 + inv(sk) * c
	// inv(sk)
	isk := new(big.Int).ModInverse(sk, ZKCurve.N)
	k := new(big.Int).Add(u2, new(big.Int).Mul(isk, Challenge))
	k = new(big.Int).Mod(k, ZKCurve.N)

	// l = u3 + (uc - v * ub) * c
	temp1 := new(big.Int).Sub(uc, new(big.Int).Mul(value, ub))
	l := new(big.Int).Add(u3, new(big.Int).Mul(temp1, Challenge))

	return &ABCProof{
		B,
		C,
		ECPoint{T1X, T1Y},
		ECPoint{T2X, T2Y},
		Challenge,
		j, k, l, CToken,
		disjuncAC}, nil

}

/*
	proofA ?= true
	proofC ?= true
	c ?= HASH(G,H,CM,CMTok,B,C,T1,T2)
	cCM + T1 ?= jG + kCMTok
	cC + T2 ?= jB + lH
*/

func ABCVerify(CM, CMTok ECPoint, aProof *ABCProof) bool {

	// Notes in ABCProof talk about why the Disjunc takes in this specific input even though it looks non-intuative
	// Here it is important that you subtract exactly 1 G from the aProof.C becuase that only allows for you to prove c = 1!
	if !DisjunctiveVerify(CM, CMTok, ZKCurve.H, aProof.C.Sub(ZKCurve.G), aProof.disjuncAC) {
		Dprintf("ABCProof for disjuncAC is false or not generated properly\n")
		return false
	}

	temp := [][]byte{ZKCurve.G.Bytes(), ZKCurve.H.Bytes(), CM.Bytes(), CMTok.Bytes(), aProof.B.Bytes(), aProof.C.Bytes(), aProof.T1.Bytes(), aProof.T2.Bytes()}

	var bytesToHash []byte
	for _, v := range temp {
		bytesToHash = append(bytesToHash, v...)
	}

	hasher := sha256.New()
	hasher.Write(bytesToHash)
	Challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	Challenge = new(big.Int).Mod(Challenge, ZKCurve.N)

	// c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	if Challenge.Cmp(aProof.Challenge) != 0 {
		Dprintf("ABCVerify: proof contains incorrect challenge\n")
		return false
	}

	// cCM + T1 ?= jG + kCMTok
	// cCM
	chalA := CM.Mult(Challenge)
	// + T1
	lhs1 := chalA.Add(aProof.T1)
	//jG
	jG := ZKCurve.G.Mult(aProof.j)
	// kCMTok
	kCMTok := CMTok.Mult(aProof.k)
	// jG + kCMTok
	rhs1 := jG.Add(kCMTok)

	if !lhs1.Equal(rhs1) {
		Dprintf("ABCVerify: cCM + T1 != jG + kCMTok\n")
		return false
	}

	// cC + T2 ?= jB + lH
	chalC := aProof.C.Mult(Challenge)
	lhs2 := chalC.Add(aProof.T2)

	jB := aProof.B.Mult(aProof.j)
	lH := ZKCurve.H.Mult(aProof.l)
	rhs2 := jB.Add(lH)

	if !lhs2.Equal(rhs2) {
		Dprintf("ABCVerify: cC + T2 != jB + lH\n")
		return false
	}

	return true
}
