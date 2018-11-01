package zkSigma

import (
	"crypto/rand"
	"math/big"
)

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
	Challenge := GenerateChallenge(result.Bytes(), uG.Bytes())

	// v = u - c * x
	HiddenValue := new(big.Int).Sub(u, new(big.Int).Mul(Challenge, modValue))
	HiddenValue = HiddenValue.Mod(HiddenValue, ZKCurve.N)

	return &GSPFSProof{base, uG, HiddenValue, Challenge}
}

// GSPFSVerify checks if a proof-commit pair is valid
func GSPFSVerify(result ECPoint, proof *GSPFSProof) bool {
	// Remeber that result = xG and RandCommit = uG

	testC := GenerateChallenge(result.Bytes(), proof.RandCommit.Bytes())

	if testC.Cmp(proof.Challenge) != 0 {
		Dprintf("GSPFSVerify: testC and proof's challenge do not agree!\n")
		return false
	}

	var s ECPoint
	if proof.Base.Equal(ZKCurve.G) {
		// (u - c * x)G, look at HiddenValue from GSPFS.Proof()
		s = SBaseMult(proof.HiddenValue)
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
	Challenge := GenerateChallenge(Base1.Bytes(), Result1.Bytes(),
		Base2.Bytes(), Result2.Bytes(),
		uBase1.Bytes(), uBase2.Bytes())

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
	Challenge := GenerateChallenge(Base1.Bytes(), Result1.Bytes(),
		Base2.Bytes(), Result2.Bytes(),
		eqProof.UG.Bytes(), eqProof.UH.Bytes())

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

	var Challenge *big.Int
	if option == 0 {
		// String for proving Base1 and Result1
		Challenge = GenerateChallenge(Base1.Bytes(), Result1.Bytes(),
			Base2.Bytes(), Result2.Bytes(),
			T1.Bytes(), T2.Bytes())
	} else {
		// If we are proving Base2 and Result2 then we must switch T1 and T2 in string
		Challenge = GenerateChallenge(Base1.Bytes(), Result1.Bytes(),
			Base2.Bytes(), Result2.Bytes(),
			T2.Bytes(), T1.Bytes()) //T2 and T1 SWAPPED!
	}

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

	checkC := GenerateChallenge(Base1.Bytes(), Result1.Bytes(),
		Base2.Bytes(), Result2.Bytes(),
		T1.Bytes(), T2.Bytes())

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

	Challenge := GenerateChallenge(ZKCurve.G.Bytes(), ZKCurve.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		PubKey.Bytes(),
		T1.Bytes(), T2.Bytes())

	s1 := new(big.Int).Add(u1, new(big.Int).Mul(modValue, Challenge))
	s2 := new(big.Int).Add(u2, new(big.Int).Mul(randomness, Challenge))
	s1.Mod(s1, ZKCurve.N)
	s2.Mod(s2, ZKCurve.N) // this was s1 instead of s2, took me an hour to find...

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
	Challenge := GenerateChallenge(ZKCurve.G.Bytes(), ZKCurve.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		PubKey.Bytes(),
		conProof.T1.Bytes(), conProof.T2.Bytes())

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
	T1 := u1G.Add(u2Ta)

	// T2 = u1B + u3H
	// u1B
	u1B := B.Mult(u1)
	// u3H
	u3H := ZKCurve.H.Mult(u3)
	// Sum of the above two
	T2 := u1B.Add(u3H)

	// c = HASH(G,H,CM,CMTok,B,C,T1,T2)
	Challenge := GenerateChallenge(ZKCurve.G.Bytes(), ZKCurve.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		B.Bytes(), C.Bytes(),
		T1.Bytes(), T2.Bytes())

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
		T1,
		T2,
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

	Challenge := GenerateChallenge(ZKCurve.G.Bytes(), ZKCurve.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		aProof.B.Bytes(), aProof.C.Bytes(),
		aProof.T1.Bytes(), aProof.T2.Bytes())

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

// InequalityProve generates a proof to show that two commitments, A and B, are not equal
// Given two commitments A and B that we know the values for - a and b respectively - we
// can prove that a != b without needed any new commitments, just generate a proof
// // There is no Inequality verify since this generates an ABCProof, so just use ABCVerify
func InequalityProve(A, B, CMTokA, CMTokB ECPoint, a, b, sk *big.Int) (*ABCProof, error) {

	if a.Cmp(b) == 0 {
		Dprintf("InequalityProve: a and b should not be equal! Duh!\n")
		return &ABCProof{}, &errorProof{"InequalityProve", "a and b should not be equal..."}
	}

	// should I check if a > b? I think that shouldn't be a problem
	// generate a-b for ABCProof, D will be created  commitment
	value := new(big.Int).Sub(a, b)
	CM := A.Sub(B)

	CMTok := CMTokA.Sub(CMTokB)

	proof, proofStatus := ABCProve(CM, CMTok, value, sk, right)

	if proofStatus != nil {
		return &ABCProof{}, proofStatus
	}

	return proof, proofStatus

}
