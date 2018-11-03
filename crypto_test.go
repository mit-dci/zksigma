package zkSigma

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestInit(t *testing.T) {
	if ZKCurve.C == nil {
		Init()
	}
	fmt.Println("Global Variables Initialized")
}

func TestECPointMethods(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestECPointMethods")
		t.Skip("Skipped TestECPointMethods")
	}

	v := big.NewInt(3)
	p := ZKCurve.G.Mult(v)
	negp := p.Neg()
	sum := p.Add(negp)
	if !sum.Equal(ZKCurve.Zero()) {
		logStuff("p : %v\n", p)
		logStuff("negp : %v\n", negp)
		logStuff("sum : %v\n", sum)
		t.Fatalf("p + -p should be 0\n")
	}
	negnegp := negp.Neg()
	if !negnegp.Equal(p) {
		logStuff("p : %v\n", p)
		logStuff("negnegp : %v\n", negnegp)
		t.Fatalf("-(-p) should be p\n")
	}
	sum = p.Add(ZKCurve.Zero())
	if !sum.Equal(p) {
		logStuff("p : %v\n", p)
		logStuff("sum : %v\n", sum)
		t.Fatalf("p + 0 should be p\n")
	}
	fmt.Println("Passed TestZKCurveMethods")
}

func TestZkpCryptoStuff(t *testing.T) {

	if ZKCurve.C == nil {
		Init()
	}

	if *NOBASIC {
		fmt.Println("Skipped TestZkpCryptoStuff")
		t.Skip("Skipped TestZkpCryptoStuff")
	}

	value := big.NewInt(-100)

	testCommit, randomValue := PedCommit(value) // xG + rH

	value = new(big.Int).Mod(value, ZKCurve.N)

	// vG
	ValEC := SBaseMult(value)
	InvValEC := ValEC.Neg() // 1/vG (acutally mod operation but whatever you get it)

	logStuff("         vG : %v --- value : %v \n", ValEC, value)
	logStuff("       1/vG : %v\n", InvValEC)

	temp := ValEC.Add(InvValEC)
	logStuff("TestZkpCrypto:")
	logStuff("Added the above: %v\n", temp)

	if !temp.Equal(ZKCurve.Zero()) {
		logStuff("Added the above: %v", temp)
		logStuff("The above should have been (0,0)")
		t.Fatalf("Failed Addition of inverse points failed")
	}

	testOpen := InvValEC.Add(testCommit)  // 1/vG + vG + rH ?= rH (1/vG + vG = 0, hopefully)
	RandEC := ZKCurve.H.Mult(randomValue) // rH

	if !RandEC.Equal(testOpen) {
		logStuff("RandEC : %v\n", RandEC)
		logStuff("testOpen : %v\n", testOpen)
		t.Fatalf("RandEC should have been equal to testOpen\n")
	}

	fmt.Println("Passed TestzkpCryptoStuff")

}

func TestZkpCryptoCommitR(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestZkpCryptoCommitR")
		t.Skip("Skipped TestZkpCryptoCommitR")
	}

	u, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	testCommit := ZKCurve.CommitR(ZKCurve.H, u)

	if !(ZKCurve.VerifyR(testCommit, ZKCurve.H, u)) {
		logStuff("testCommit: %v\n", testCommit)
		logStuff("ZKCurve.H: %v, \n", ZKCurve.H)
		logStuff("u : %v\n", u)
		t.Fatalf("testCommit should have passed verification\n")
	}

	fmt.Println("Passed TestzkpCryptoCommitR")
}

func TestPedersenCommit(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestPedersenCommit")
		t.Skip("Skipped TestPedersenCommit")
	}

	x := big.NewInt(1000)
	badx := big.NewInt(1234)

	commit, u := PedCommit(x)

	commitR := PedCommitR(x, u)

	if !commit.Equal(commitR) {
		logStuff("x : %v --- u : %v\n", x, u)
		logStuff("commit: %v\n", commit)
		logStuff("commitR: %v\n", commitR)
		t.Fatalf("commit and commitR should be equal")
	}

	if !Open(x, u, commit) || !Open(x, u, commitR) {
		logStuff("x : %v --- u : %v\n", x, u)
		logStuff("commit: %v\n", commit)
		logStuff("commitR: %v\n", commitR)
		t.Fatalf("commit and/or commitR did not successfully open")
	}

	if Open(badx, u.Neg(u), commit) || Open(badx, u.Neg(u), commitR) {
		logStuff("x : %v --- u : %v\n", x, u)
		logStuff("commit: %v\n", commit)
		logStuff("commitR: %v\n", commitR)
		t.Fatalf("commit and/or commitR should not have opened properly")
	}

	fmt.Println("Passed TestPedersenCommit")

}

func TestGSPFS(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestGSPFS")
		t.Skip("Skipped TestGSPFS")
	}

	x, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	// MUST use G here becuase of GSPFSProve implementation
	result := SBaseMult(x)

	testProof := GSPFSProve(result, x)

	if !GSPFSVerify(result, testProof) {
		logStuff("x : %v\n", x)
		logStuff("randPoint : %v\n", result)
		logStuff("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof didnt generate properly - 1\n")
	}

	// Using H here should break the proof
	result = ZKCurve.H.Mult(x)

	logStuff("Next GSPFSVerify should fail\n")
	if GSPFSVerify(result, testProof) {
		logStuff("x : %v\n", x)
		logStuff("randPoint : %v\n", result)
		logStuff("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof should not have worked - 2\n")
	}

	fmt.Println("Passed TestGSPFS")

}

func TestEquivilance(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestEquivilance")
		t.Skip("Skipped TestEquivilance")
	}

	x, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base1 := ZKCurve.G
	Result1 := Base1.Mult(x)

	Base2 := ZKCurve.H
	Result2 := Base2.Mult(x)

	eqProof, status1 := EquivilanceProve(Base1, Result1, Base2, Result2, x)

	if status1 != nil {
		proofStatus(status1.(*errorProof))
		t.Fatalf("error code should have indicated successful proof")
	}

	if !EquivilanceVerify(Base1, Result1, Base2, Result2, eqProof) {
		logStuff("Base1 : %v\n", Base1)
		logStuff("Result1 : %v\n", Result1)
		logStuff("Base2 : %v\n", Base2)
		logStuff("Result2 : %v\n", Result2)
		logStuff("Proof : %v \n", eqProof)
		t.Fatalf("Equivilance Proof verification failed")
	}

	logStuff("Next comparison should fail\n")
	// Bases swapped shouldnt work
	if EquivilanceVerify(Base2, Result1, Base1, Result2, eqProof) {
		logStuff("Base1 : %v\n", Base1)
		logStuff("Result1 : %v\n", Result1)
		logStuff("Base2 : %v\n", Base2)
		logStuff("Result2 : %v\n", Result2)
		logStuff("Proof : %v \n", eqProof)
		t.Fatalf("Equivilance Proof verification doesnt work")
	}

	logStuff("Next comparison should fail\n")
	// Bad proof
	eqProof.HiddenValue = big.NewInt(-1)
	if EquivilanceVerify(Base2, Result1, Base1, Result2, eqProof) {
		logStuff("Base1 : %v\n", Base1)
		logStuff("Result1 : %v\n", Result1)
		logStuff("Base2 : %v\n", Base2)
		logStuff("Result2 : %v\n", Result2)
		logStuff("Proof : %v \n", eqProof)
		t.Fatalf("Equivilance Proof verification doesnt work")
	}

	x, _ = rand.Int(rand.Reader, ZKCurve.N)
	_, status2 := EquivilanceProve(Base1, Result1, Base2, Result2, x)

	// here I check proofStatus in the else statement becuase I want to make sure
	// the failed case will raise an error
	if status2 == nil {
		t.Fatalf("error code should have indicated failed proof")
	} else {
		proofStatus(status2.(*errorProof))
	}

	fmt.Println("Passed TestEquivilance")

}

func TestDisjunctive(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestDisjunctive")
		t.Skip("Skipped TestDisjunctive")
	}

	x := big.NewInt(100)
	y := big.NewInt(101)

	Base1 := ZKCurve.G
	Result1 := ZKCurve.G.Mult(x)
	Base2 := ZKCurve.H
	Result2 := ZKCurve.H.Mult(y)

	djProofLEFT, status1 := DisjunctiveProve(Base1, Result1, Base2, Result2, x, Left)

	if status1 != nil {
		proofStatus(status1.(*errorProof))
		t.Fatalf("TestDisjuntive - incorrect error message for correct proof, case 1\n")
	}

	djProofRIGHT, status2 := DisjunctiveProve(Base1, Result1, Base2, Result2, y, Right)

	if status2 != nil {
		proofStatus(status2.(*errorProof))
		t.Fatalf("TestDisjuntive - incorrect error message for correct proof, case 2\n")
	}

	logStuff("Testing DisjunctiveProof:\n")
	logStuff("First djProof : ")
	if !DisjunctiveVerify(Base1, Result1, Base2, Result2, djProofLEFT) {
		t.Fatalf("djProof failed to generate properly for left side\n")
	}

	logStuff("Passed \n [testing] Second djProof : ")
	if !DisjunctiveVerify(Base1, Result1, Base2, Result2, djProofRIGHT) {
		t.Fatalf("djProof failed to generate properly for right side\n")
	}

	logStuff("Passed \n [testing] Next djProof attemp should result in an error message\n")
	_, status3 := DisjunctiveProve(Base1, Result1, Base2, Result2, y, Left) // This should fail

	if proofStatus(status3.(*errorProof)) == 0 {
		t.Fatalf("TestDisjuntive - incorrect error message for incorrect proof, case 3\n")
	}

	fmt.Println("Passed TestDisjunctiveg")

}

func TestConsistency(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestConsistency")
		t.Skip("Skipped TestConsistency")
	}

	x, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	sk, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)
	pk := ZKCurve.H.Mult(sk)

	comm, u := PedCommit(x)
	y := pk.Mult(u)

	conProof, status1 := ConsistencyProve(comm, y, pk, x, u)

	if status1 != nil {
		proofStatus(status1.(*errorProof))
		t.Fatalf("TestConsistancy - incorrect error message for correct proof, case 1\n")
	}

	logStuff(" [testing] Testing correct consistency proof\n")
	if !ConsistencyVerify(comm, y, pk, conProof) {
		t.Fatalf("Error -- Proof should be correct\n")
	}

	logStuff(" [testing] Next proof should fail\n")

	conProof, status2 := ConsistencyProve(y, comm, pk, x, u)

	if proofStatus(status2.(*errorProof)) == 0 {
		t.Fatalf("TestConsistancy - incorrect error message for correct proof, case 2\n")
	}

	fmt.Println("Passed TestConsistency")
}

// TODO: make a toooooon more test cases
func TestABCProof(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestABCProof")
		t.Skip("Skipped TestABCProof")
	}

	if ZKCurve.C == nil {
		Init()
	}

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	value, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	ua, _ := rand.Int(rand.Reader, ZKCurve.N)

	PK := ZKCurve.H.Mult(sk)
	A := ZKCurve.H.Mult(ua)       // uaH
	temp := ZKCurve.G.Mult(value) // value(G)

	// A = vG + uaH
	A = A.Add(temp)
	AToken := PK.Mult(ua)

	aProof, status := ABCProve(A, AToken, value, sk, Right)

	if status != nil {
		proofStatus(status.(*errorProof))
		logStuff("ABCProof RIGHT failed to generate!\n")
		t.Fatalf("ABCProof RIGHT failed\n")
	}

	if !ABCVerify(A, AToken, aProof) {
		logStuff("ABCProof RIGHT Failed to verify!\n")
		t.Fatalf("ABCVerify RIGHT failed\n")
	}

	A = ZKCurve.H.Mult(ua)
	aProof, status = ABCProve(A, AToken, big.NewInt(0), sk, Left)

	if status != nil {
		proofStatus(status.(*errorProof))
		logStuff("ABCProof LEFT failed to generate!\n")
		t.Fatalf("ABCProof LEFT failed\n")
	}

	if !ABCVerify(A, AToken, aProof) {
		logStuff("ABCProof LEFT Failed to verify!\n")
		t.Fatalf("ABCVerify LEFT failed\n")
	}

	A, ua = PedCommit(big.NewInt(1000))
	AToken = PK.Mult(ua)

	aProof, status = ABCProve(A, AToken, big.NewInt(1001), sk, Right)

	if status != nil {
		logStuff("False proof genereation succeeded! (bad)\n")
		t.Fatalf("ABCProve generated for false proof\n")
	}

	logStuff("Next ABCVerify should catch false proof\n")

	if ABCVerify(A, AToken, aProof) {
		logStuff("ABCVerify: should have failed on false proof check!\n")
		t.Fatalf("ABCVerify: not working...\n")
	}

	fmt.Println("Passed TestABCProof")

}

func TestInequalityProve(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestInequalityProve")
		t.Skip("Skipped TestABCProof")
	}

	if ZKCurve.C == nil {
		Init()
	}

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	a, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	b, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	A, ua := PedCommit(a)
	B, ub := PedCommit(b)

	PK := ZKCurve.H.Mult(sk)

	// Even though we generated the values for ua and ub in this test case, we do not
	// need to know ua or ub, only the commitment tokens are needed, which is already
	// used in many other proofs
	CMTokA := PK.Mult(ua)
	CMTokB := PK.Mult(ub)

	aProof, status := InequalityProve(A, B, CMTokA, CMTokB, a, b, sk)

	if status != nil {
		proofStatus(status.(*errorProof))
		logStuff("ABCProof for InequalityProve failed to generate!\n")
		t.Fatalf("ABCProof for InequalityProve failed\n")
	}

	if !ABCVerify(A.Sub(B), CMTokA.Sub(CMTokB), aProof) {
		logStuff("ABCProof for InequalityProve failed to verify!\n")
		t.Fatalf("ABCVerify for InequalityProve failed\n")
	}

	// Swapped positions of commitments, tokens and values, will work just fine
	aProof, status = InequalityProve(B, A, CMTokB, CMTokA, b, a, sk)

	if status != nil {
		proofStatus(status.(*errorProof))
		logStuff("ABCProof for InequalityProve failed to generate!\n")
		t.Fatalf("ABCProof for InequalityProve failed\n")
	}

	if !ABCVerify(B.Sub(A), CMTokB.Sub(CMTokA), aProof) {
		logStuff("ABCProof for InequalityProve failed to verify!\n")
		t.Fatalf("ABCVerify for InequalityProve failed\n")
	}

	// Mismatched commitments and values, a proof does generate but the
	// verification step will catch the false proof.
	// Use the -debug1 flag to see this in action
	aProof, status = InequalityProve(A, B, CMTokA, CMTokB, b, a, sk)

	if status != nil {
		proofStatus(status.(*errorProof))
		logStuff("ABCProof for InequalityProve failed to generate!\n")
		t.Fatalf("ABCProof for InequalityProve failed\n")
	}

	if ABCVerify(A.Sub(B), CMTokA.Sub(CMTokB), aProof) {
		logStuff("ABCProof for InequalityProve failed to verify!\n")
		t.Fatalf("ABCVerify for InequalityProve failed\n")
	}

	fmt.Println("Passed TestInequalityProve")

}

func TestBreakABCProve(t *testing.T) {

	if *EVILPROOF {
		fmt.Println("Skipped TestBreakABCProve")
		t.Skip("Skipped TestBreakABCProve")
	}

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	value, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	ua, _ := rand.Int(rand.Reader, ZKCurve.N)

	PK := ZKCurve.H.Mult(sk)
	CM := ZKCurve.H.Mult(ua)      // uaH
	temp := ZKCurve.G.Mult(value) // value(G)

	// A = vG + uaH
	CM = CM.Add(temp)
	CMTok := PK.Mult(ua)

	u1, _ := rand.Int(rand.Reader, ZKCurve.N)
	u2, _ := rand.Int(rand.Reader, ZKCurve.N)
	u3, _ := rand.Int(rand.Reader, ZKCurve.N)
	ub, _ := rand.Int(rand.Reader, ZKCurve.N)
	uc, _ := rand.Int(rand.Reader, ZKCurve.N)

	B := ECPoint{}
	C := ECPoint{}
	CToken := ZKCurve.H.Mult(uc)

	// B = 2/v
	B = PedCommitR(new(big.Int).ModInverse(new(big.Int).Quo(big.NewInt(2), value), ZKCurve.N), ub)

	// C = 2G + ucH, the 2 here is the big deal
	C = PedCommitR(big.NewInt(2), uc)

	disjuncAC, _ := DisjunctiveProve(CMTok, CM, ZKCurve.H, C.Sub(ZKCurve.G.Mult(big.NewInt(2))), uc, Right)

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
	Challenge := GenerateChallenge(ZKCurve.G.Bytes(), ZKCurve.H.Bytes(),
		CM.Bytes(), CMTok.Bytes(),
		B.Bytes(), C.Bytes(),
		T1X.Bytes(), T1Y.Bytes(),
		T2X.Bytes(), T2Y.Bytes())

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

	evilProof := &ABCProof{
		B,
		C,
		ECPoint{T1X, T1Y},
		ECPoint{T2X, T2Y},
		Challenge,
		j, k, l, CToken,
		disjuncAC}

	logStuff("Attemping to pass malicious true proof into verification function\n")
	logStuff("This test should throw a couple error messages in debug\n")

	if ABCVerify(CM, CMTok, evilProof) {
		logStuff("ABCVerify - EVIL: accepted attack input! c = 2, should fail...\n")
		t.Fatalf("ABCVerify - EVIL: failed to catch attack!\n")
	}

}

type etx struct {
	CM    ECPoint
	CMTok ECPoint
	ABCP  *ABCProof
}

//TODO: make a sk-pk that is consistant accross all test cases
func TestAverages_Basic(t *testing.T) {

	if *NOBASIC {
		fmt.Println("Skipped TestAverages_Basic")
		t.Skip("Skipped TestAverages_Basic")
	}

	// remeber to change both number here...
	numTx := 100
	numTranx := big.NewInt(100)

	totalValue := big.NewInt(0)
	totalRand := big.NewInt(0)
	txn := make([]etx, numTx)
	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	PK := ZKCurve.H.Mult(sk)
	value := big.NewInt(0)
	commRand := big.NewInt(0)

	// Generate
	for ii := 0; ii < numTx; ii++ {
		value, _ = rand.Int(rand.Reader, ZKCurve.N)
		totalValue.Add(totalValue, value)
		txn[ii].CM, commRand = PedCommit(value)
		totalRand.Add(totalRand, commRand)
		txn[ii].CMTok = PK.Mult(commRand)
		txn[ii].ABCP, _ = ABCProve(txn[ii].CM, txn[ii].CMTok, value, sk, Right)
	}

	// Purely for testing purposes, usually this is computed at the end by auditor
	// actualAverage := new(big.Int).Quo(totalValue, numTranx)

	// ========= BANK PROCESS ===========

	// To calculate average we need to first show proof of knowledge
	// of the sums of both the total value of transactions and the
	// sum of the C-bit commitments
	// This process is extactly the same process described in zkLedger
	// (Neha Nerula) paper in section 4.2

	//Need to aggregate a bunch of stuff to do equivilance proofs and what not
	totalCM := ZKCurve.Zero()
	totalCMTok := ZKCurve.Zero()
	totalC := ZKCurve.Zero()
	totalCTok := ZKCurve.Zero()

	for ii := 0; ii < numTx; ii++ {
		totalCM = txn[ii].CM.Add(totalCM)
		totalCMTok = txn[ii].CMTok.Add(totalCMTok)
		totalC = txn[ii].ABCP.C.Add(totalC)
		totalCTok = txn[ii].ABCP.CToken.Add(totalCTok)
	}

	// makes the call look cleaner
	B1 := totalC.Add(ZKCurve.G.Mult(numTranx).Neg())
	R1 := totalCTok
	B2 := ZKCurve.H
	R2 := PK

	eProofNumTx, status := EquivilanceProve(B1, R1, B2, R2, sk)

	if status != nil {
		proofStatus(status.(*errorProof))
		logStuff("Average Test: equivilance proof failed to generate for numTx\n")
		t.Fatalf("Averages did not gerneate correct NUMTX equivilance proof\n")
	}

	B1 = totalCM.Add(ZKCurve.G.Mult(totalValue).Neg())
	R1 = totalCMTok

	eProofValue, status1 := EquivilanceProve(B1, R1, B2, R2, sk)

	if status1 != nil {
		proofStatus(status1.(*errorProof))
		logStuff("Average Test: equivilance proof failed to generate for value sum\n")
		t.Fatalf("Averages did not gerneate correct VALUE equivilance proof\n")
	}

	// ASSUME:
	// eProofs passed to auditor
	// clear text answers of total value and total number tx passed to auditor
	// auditor WILL recalculate all the totals (totalCM, totalCMTok, etc) before doing the following
	// auditor WILL recualculate the B1's as shown above
	// auditor WILL verify eProofs and then perform the final average calcualtion, shown below
	// ======== AUDITOR PROCESS ===========

	B1 = totalC.Add(ZKCurve.G.Mult(numTranx).Neg())
	R1 = totalCTok
	B2 = ZKCurve.H
	R2 = PK

	checkTx := EquivilanceVerify(B1, R1, B2, R2, eProofNumTx)

	if !checkTx {
		logStuff("Average Test: NUMTX equivilance proof did not verify\n")
		t.Fatalf("Equivilance proof of NUMTX did not verify\n")
	}

	B1 = totalCM.Add(ZKCurve.G.Mult(totalValue).Neg())
	R1 = totalCMTok

	checkVal := EquivilanceVerify(B1, R1, B2, R2, eProofValue)

	if !checkVal {
		logStuff("Average Test: SUM equivilance proof did not verify\n")
		t.Fatalf("Equivilance proof of SUM did not verify\n")
	}

	fmt.Println("Passed TestAverages")

}

// ============== BENCHMARKS =================
func BenchmarkInit(b *testing.B) {
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		Init()
	}
}

func BenchmarkPedCommit(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		PedCommit(value)
	}
}

func BenchmarkPedCommitR(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	randVal, _ := rand.Int(rand.Reader, ZKCurve.N)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		PedCommitR(value, randVal)
	}
}

func BenchmarkOpen(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	randVal, _ := rand.Int(rand.Reader, ZKCurve.N)
	CM := PedCommitR(value, randVal)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		Open(value, randVal, CM)
	}
}

func BenchmarkGSPFS_AnyBase(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base := ZKCurve.G
	CM := ZKCurve.G.Mult(value)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		GSPAnyBaseProve(Base, CM, value)
	}
}

func BenchmarkGSPFS_Verify(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base := ZKCurve.G
	CM := ZKCurve.G.Mult(value)
	proof := GSPAnyBaseProve(Base, CM, value)

	for ii := 0; ii < b.N; ii++ {
		GSPFSVerify(CM, proof)
	}
}

func BenchmarkEquivProve(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base1 := ZKCurve.G
	Result1 := Base1.Mult(value)
	Base2 := ZKCurve.H
	Result2 := Base2.Mult(value)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		EquivilanceProve(Base1, Result1, Base2, Result2, value)
	}
}

func BenchmarkEquivVerify(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base1 := ZKCurve.G
	Result1 := Base1.Mult(value)
	Base2 := ZKCurve.H
	Result2 := Base2.Mult(value)
	proof, _ := EquivilanceProve(Base1, Result1, Base2, Result2, value)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		EquivilanceVerify(Base1, Result1, Base2, Result2, proof)
	}
}

func BenchmarkDisjuncProve_LEFT(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	randVal, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base1 := ZKCurve.G
	Result1 := Base1.Mult(value)
	Base2 := ZKCurve.H
	Result2 := Base2.Mult(randVal)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		DisjunctiveProve(Base1, Result1, Base2, Result2, value, Left)
	}
}

func BenchmarkDisjuncProve_RIGHT(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	randVal, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base1 := ZKCurve.G
	Result1 := Base1.Mult(value)
	Base2 := ZKCurve.H
	Result2 := Base2.Mult(randVal)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		DisjunctiveProve(Base1, Result1, Base2, Result2, randVal, Right)
	}
}

func BenchmarkDisjuncVerify_LEFT(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	randVal, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base1 := ZKCurve.G
	Result1 := Base1.Mult(value)
	Base2 := ZKCurve.H
	Result2 := Base2.Mult(randVal)
	proof, _ := DisjunctiveProve(Base1, Result1, Base2, Result2, value, Left)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		DisjunctiveVerify(Base1, Result1, Base2, Result2, proof)
	}
}

func BenchmarkDisjuncVerify_RIGHT(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)
	randVal, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base1 := ZKCurve.G
	Result1 := Base1.Mult(value)
	Base2 := ZKCurve.H
	Result2 := Base2.Mult(randVal)
	proof, _ := DisjunctiveProve(Base1, Result1, Base2, Result2, randVal, Right)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		DisjunctiveVerify(Base1, Result1, Base2, Result2, proof)
	}
}

func BenchmarkConsistancyProve(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal := PedCommit(value)
	CMTok := PK.Mult(randVal)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		ConsistencyProve(CM, CMTok, PK, value, randVal)
	}
}

func BenchmarkConsistancyVerify(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal := PedCommit(value)
	CMTok := PK.Mult(randVal)
	proof, _ := ConsistencyProve(CM, CMTok, PK, value, randVal)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		ConsistencyVerify(CM, CMTok, PK, proof)
	}
}

func BenchmarkABCProve_0(b *testing.B) {
	value := big.NewInt(0)

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal := PedCommit(value)
	CMTok := PK.Mult(randVal)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		ABCProve(CM, CMTok, value, sk, Left)
	}
}

func BenchmarkABCProve_1(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal := PedCommit(value)
	CMTok := PK.Mult(randVal)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		ABCProve(CM, CMTok, value, sk, Right)
	}
}

func BenchmarkABCVerify_0(b *testing.B) {
	value := big.NewInt(0)

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal := PedCommit(value)
	CMTok := PK.Mult(randVal)
	proof, _ := ABCProve(CM, CMTok, value, sk, Left)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		ABCVerify(CM, CMTok, proof)
	}
}

func BenchmarkABCVerify_1(b *testing.B) {
	value, _ := rand.Int(rand.Reader, ZKCurve.N)

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	PK := ZKCurve.H.Mult(sk)

	CM, randVal := PedCommit(value)
	CMTok := PK.Mult(randVal)
	proof, _ := ABCProve(CM, CMTok, value, sk, Right)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		ABCVerify(CM, CMTok, proof)
	}
}

func BenchmarkInequalityProve(b *testing.B) {

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	a, _ := rand.Int(rand.Reader, big.NewInt(10000000000))      // "realistic rarnge"
	bValue, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
	A, ua := PedCommit(a)
	B, ub := PedCommit(bValue)

	PK := ZKCurve.H.Mult(sk)

	// even though we generated the values for ua and ub in this test case, we do not
	// need to know ua or ub, only the commitment tokens, which is already used in many other proofs
	CMTokA := PK.Mult(ua)
	CMTokB := PK.Mult(ub)

	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		InequalityProve(A, B, CMTokA, CMTokB, a, bValue, sk)
	}
}
