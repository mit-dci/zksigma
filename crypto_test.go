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
	v := big.NewInt(3)
	p := ZKCurve.G.Mult(v)
	negp := p.Neg()
	sum := p.Add(negp)
	if !sum.Equal(ZKCurve.Zero()) {
		Dprintf("p : %v\n", p)
		Dprintf("negp : %v\n", negp)
		Dprintf("sum : %v\n", sum)
		t.Fatalf("p + -p should be 0\n")
	}
	negnegp := negp.Neg()
	if !negnegp.Equal(p) {
		Dprintf("p : %v\n", p)
		Dprintf("negnegp : %v\n", negnegp)
		t.Fatalf("-(-p) should be p\n")
	}
	sum = p.Add(ZKCurve.Zero())
	if !sum.Equal(p) {
		Dprintf("p : %v\n", p)
		Dprintf("sum : %v\n", sum)
		t.Fatalf("p + 0 should be p\n")
	}
	fmt.Println("Passed TestZKCurveMethods")
}

func TestZkpCryptoStuff(t *testing.T) {
	value := big.NewInt(-100)

	testCommit, randomValue := PedCommit(value) // xG + rH

	value = new(big.Int).Mod(value, ZKCurve.N)

	// vG
	tempX, tempY := ZKCurve.C.ScalarMult(ZKCurve.G.X, ZKCurve.G.Y, value.Bytes())

	ValEC := ECPoint{tempX, tempY}          // vG
	InvValEC := ZKCurve.G.Mult(value).Neg() // 1/vG (acutally mod operation but whatever you get it)
	Dprintf("         vG : %v --- value : %v \n", ValEC, value)
	Dprintf("       1/vG : %v\n", InvValEC)

	tempX, tempY = ZKCurve.C.Add(ValEC.X, ValEC.Y, InvValEC.X, InvValEC.Y)
	Dprintf("TestZkpCrypto:")
	Dprintf("Added the above: %v, %v\n", tempX, tempY)

	if tempX.Cmp(ZKCurve.Zero().X) != 0 || tempY.Cmp(ZKCurve.Zero().Y) != 0 {
		Dprintf("Added the above: %v, %v", tempX, tempY)
		Dprintf("The above should have been (0,0)")
		t.Fatalf("Failed Addition of inverse points failed")
	}

	testOpen := InvValEC.Add(testCommit)                                               // 1/vG + vG + rH ?= rH (1/vG + vG = 0, hopefully)
	tempX, tempY = ZKCurve.C.ScalarMult(ZKCurve.H.X, ZKCurve.H.Y, randomValue.Bytes()) // rH
	RandEC := ECPoint{tempX, tempY}

	if !RandEC.Equal(testOpen) {
		Dprintf("RandEC : %v\n", RandEC)
		Dprintf("testOpen : %v\n", testOpen)
		t.Fatalf("RandEC should have been equal to testOpen\n")
	}

	fmt.Println("Passed TestzkpCryptoStuff")

}

func TestZkpCryptoCommitR(t *testing.T) {

	u, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	testCommit := ZKCurve.CommitR(ZKCurve.H, u)

	if !(ZKCurve.VerifyR(testCommit, ZKCurve.H, u)) {
		Dprintf("testCommit: %v\n", testCommit)
		Dprintf("ZKCurve.H: %v, \n", ZKCurve.H)
		Dprintf("u : %v\n", u)
		t.Fatalf("testCommit should have passed verification\n")
	}

	fmt.Println("Passed TestzkpCryptoCommitR")
}

func TestPedersenCommit(t *testing.T) {

	x := big.NewInt(1000)
	badx := big.NewInt(1234)

	commit, u := PedCommit(x)

	commitR := PedCommitR(x, u)

	if !commit.Equal(commitR) {
		Dprintf("x : %v --- u : %v\n", x, u)
		Dprintf("commit: %v\n", commit)
		Dprintf("commitR: %v\n", commitR)
		t.Fatalf("commit and commitR should be equal")
	}

	if !Open(x, u, commit) || !Open(x, u, commitR) {
		Dprintf("x : %v --- u : %v\n", x, u)
		Dprintf("commit: %v\n", commit)
		Dprintf("commitR: %v\n", commitR)
		t.Fatalf("commit and/or commitR did not successfully open")
	}

	if Open(badx, u.Neg(u), commit) || Open(badx, u.Neg(u), commitR) {
		Dprintf("x : %v --- u : %v\n", x, u)
		Dprintf("commit: %v\n", commit)
		Dprintf("commitR: %v\n", commitR)
		t.Fatalf("commit and/or commitR should not have opened properly")
	}

	fmt.Println("Passed TestPedersenCommit")

}

func TestGSPFS(t *testing.T) {

	x, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	// MUST use G here becuase of GSPFSProve implementation
	rX, rY := ZKCurve.C.ScalarBaseMult(x.Bytes())
	result := ECPoint{rX, rY}

	testProof := GSPFSProve(result, x)

	if !GSPFSVerify(result, testProof) {
		Dprintf("x : %v\n", x)
		Dprintf("randPoint : %v\n", result)
		Dprintf("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof didnt generate properly - 1\n")
	}

	// Using H here should break the proof
	result = ZKCurve.H.Mult(x)

	Dprintf("Next GSPFSVerify should fail\n")
	if GSPFSVerify(result, testProof) {
		Dprintf("x : %v\n", x)
		Dprintf("randPoint : %v\n", result)
		Dprintf("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof should not have worked - 2\n")
	}

	fmt.Println("Passed TestGSPFS")

}

func TestEquivilance(t *testing.T) {

	x, _ := rand.Int(rand.Reader, ZKCurve.N)
	Base1 := ZKCurve.G
	Result1 := Base1.Mult(x)

	Base2 := ZKCurve.H
	Result2 := Base2.Mult(x)

	eqProof, status1 := EquivilanceProve(Base1, Result1, Base2, Result2, x)

	if !EquivilanceVerify(Base1, Result1, Base2, Result2, eqProof) {
		Dprintf("Base1 : %v\n", Base1)
		Dprintf("Result1 : %v\n", Result1)
		Dprintf("Base2 : %v\n", Base2)
		Dprintf("Result2 : %v\n", Result2)
		Dprintf("Proof : %v \n", eqProof)
		t.Fatalf("Equivilance Proof verification failed")
	}

	Dprintf("Next comparison should fail\n")
	// Bases swapped shouldnt work
	if EquivilanceVerify(Base2, Result1, Base1, Result2, eqProof) {
		Dprintf("Base1 : %v\n", Base1)
		Dprintf("Result1 : %v\n", Result1)
		Dprintf("Base2 : %v\n", Base2)
		Dprintf("Result2 : %v\n", Result2)
		Dprintf("Proof : %v \n", eqProof)
		t.Fatalf("Equivilance Proof verification doesnt work")
	}

	Dprintf("Next comparison should fail\n")
	// Bad proof
	eqProof.HiddenValue = big.NewInt(-1)
	if EquivilanceVerify(Base2, Result1, Base1, Result2, eqProof) {
		Dprintf("Base1 : %v\n", Base1)
		Dprintf("Result1 : %v\n", Result1)
		Dprintf("Base2 : %v\n", Base2)
		Dprintf("Result2 : %v\n", Result2)
		Dprintf("Proof : %v \n", eqProof)
		t.Fatalf("Equivilance Proof verification doesnt work")
	}

	if !status1 {
		t.Fatalf("One of the proofs' status is not correct\n")
	}

	fmt.Println("Passed TestEquivilance")

}

func TestDisjunctive(t *testing.T) {

	x := big.NewInt(100)
	y := big.NewInt(101)

	Base1 := ZKCurve.G
	Result1 := ZKCurve.G.Mult(x)
	Base2 := ZKCurve.H
	Result2 := ZKCurve.H.Mult(y)

	djProofLEFT, status1 := DisjunctiveProve(Base1, Result1, Base2, Result2, x, left)
	djProofRIGHT, status2 := DisjunctiveProve(Base1, Result1, Base2, Result2, y, right)

	Dprintf("Testing DisjunctiveProof:\n")
	Dprintf("First djProof : ")
	if !DisjunctiveVerify(Base1, Result1, Base2, Result2, djProofLEFT) {
		t.Fatalf("djProof failed to generate properly for left side\n")
	}

	Dprintf("Passed \n [debug] Second djProof : ")
	if !DisjunctiveVerify(Base1, Result1, Base2, Result2, djProofRIGHT) {
		t.Fatalf("djProof failed to generate properly for right side\n")
	}

	Dprintf("Passed \n [debug] Next djProof attemp should result in an error message\n")
	_, status3 := DisjunctiveProve(Base1, Result1, Base2, Result2, y, left) // This should fail

	if !status1 || !status2 || status3 {
		t.Fatalf("One of the proofs' status is incorrect\n")
	}

	fmt.Println("Passed TestDisjunctiveg")

}

func TestConsistency(t *testing.T) {

	x, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	sk, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)
	pk := ZKCurve.H.Mult(sk)

	comm, u := PedCommit(x)
	y := pk.Mult(u)

	conProof, status1 := ConsistencyProve(comm, y, pk, x, u)

	Dprintf(" [debug] Testing correct consistency proof\n")
	if !ConsistencyVerify(comm, y, pk, conProof) {
		t.Fatalf("Error -- Proof should be correct\n")
	}

	Dprintf(" [debug] Next proof should fail\n")

	conProof, status2 := ConsistencyProve(y, comm, pk, x, u)

	// Below will break not run since proof doesnt generate
	// Dprintf(" [debug] Testing incorrect consistency proof\n")
	// if ConsistencyVerify(comm, y, pk, conProof) {
	// 	t.Fatalf("Error -- Proof should be wrong\n")
	// }

	if !status1 || status2 {
		t.Fatalf("One of the proofs' status is incorrect\n")
	}

	fmt.Println("Passed TestConsistency")
}

// TODO: make a toooooon more test cases
func TestABCProof(t *testing.T) {

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
	A.X, A.Y = ZKCurve.C.Add(A.X, A.Y, temp.X, temp.Y)
	AToken := PK.Mult(ua)

	aProof, status := ABCProve(A, AToken, value, sk, right)

	if !status {
		Dprintf("ABCProof RIGHT failed to generate!\n")
		fmt.Printf("aProof: \n\n %v \n\n", aProof)
		t.Fatalf("ABCProof RIGHT failed\n")
	}

	if !ABCVerify(A, AToken, aProof) {
		Dprintf("ABCProof RIGHT Failed to verify!\n")
		Dprintf("aProof: \n\n %v \n\n", aProof)
		t.Fatalf("ABCVerify RIGHT failed\n")
	}

	A = ZKCurve.H.Mult(ua)
	aProof, status = ABCProve(A, AToken, big.NewInt(0), sk, left)

	if !status {
		Dprintf("ABCProof LEFT failed to generate!\n")
		fmt.Printf("aProof: \n\n %v \n\n", aProof)
		t.Fatalf("ABCProof LEFT failed\n")
	}

	if !ABCVerify(A, AToken, aProof) {
		Dprintf("ABCProof LEFT Failed to verify!\n")
		Dprintf("aProof: \n\n %v \n\n", aProof)
		t.Fatalf("ABCVerify LEFT failed\n")
	}

	A, ua = PedCommit(big.NewInt(1000))
	AToken = PK.Mult(ua)

	aProof, status = ABCProve(A, AToken, big.NewInt(1001), sk, right)

	// if !status {
	// 	Dprintf("False proof genereation succeeded! (bad)\n")
	// 	t.Fatalf("ABCProve generated for false proof\n")
	// }

	Dprintf("Next ABCVerify should catch false proof\n")

	if ABCVerify(A, AToken, aProof) {
		Dprintf("ABCVerify: should have failed on false proof check!\n")
		t.Fatalf("ABCVerify: not working...\n")
	}

	aProof, status = BreakABCProve(A, AToken, big.NewInt(1000), sk, right)

	Dprintf("Next ABCVerify should catch attack\n")

	if ABCVerify(A, AToken, aProof) {
		Dprintf("ABCVerify: accepted attack input! c = 2, should fail...\n")
		t.Fatalf("ABCVerify: failed to catch attack!\n")
	}

	fmt.Println("Passed TestABCProof")

}

type etx struct {
	CM    ECPoint
	CMTok ECPoint
	ABCP  *ABCProof
}

//TODO: make a sk-pk that is consistant accross all test cases
func TestAverages_Basic(t *testing.T) {

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
		txn[ii].ABCP, _ = ABCProve(txn[ii].CM, txn[ii].CMTok, value, sk, right)
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

	if !status {
		Dprintf("Average Test: equivilance proof failed to generate for numTx\n")
		t.Fatalf("Averages did not gerneate correct NUMTX equivilance proof\n")
	}

	B1 = totalCM.Add(ZKCurve.G.Mult(totalValue).Neg())
	R1 = totalCMTok

	eProofValue, status1 := EquivilanceProve(B1, R1, B2, R2, sk)

	if !status1 {
		Dprintf("Average Test: equivilance proof failed to generate for value sum\n")
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
		Dprintf("Average Test: NUMTX equivilance proof did not verify\n")
		t.Fatalf("Equivilance proof of NUMTX did not verify\n")
	}

	B1 = totalCM.Add(ZKCurve.G.Mult(totalValue).Neg())
	R1 = totalCMTok

	checkVal := EquivilanceVerify(B1, R1, B2, R2, eProofValue)

	if !checkVal {
		Dprintf("Average Test: SUM equivilance proof did not verify\n")
		t.Fatalf("Equivilance proof of SUM did not verify\n")
	}

	fmt.Println("Passed TestAverages")

}

func TestABCProof_Extensive(t *testing.T) {
	if !*EXTEN {
		fmt.Println("SKIPPED ABCTest_Extensive - use '-extensive' flag")
	} else {

		failed := false

		sk, _ := rand.Int(rand.Reader, ZKCurve.N)
		PK := ZKCurve.H.Mult(sk)
		ua, _ := rand.Int(rand.Reader, ZKCurve.N)

		for ii := 0; ii < 1000; ii++ { //roughly 5 seconds per 1000 cases

			value, _ := rand.Int(rand.Reader, big.NewInt(10000000000)) // "realistic rarnge"
			A := ZKCurve.H.Mult(ua)                                    // uaH
			temp := ZKCurve.G.Mult(value)                              // value(G); ZKCurve.C.ScalarBaseMult(value.Bytes())

			// A = vG + uaH
			A.X, A.Y = ZKCurve.C.Add(A.X, A.Y, temp.X, temp.Y)
			AToken := PK.Mult(ua) //ZKCurve.H.Mult(ua), where can I get uaH?

			aProof, status := ABCProve(A, AToken, value, sk, right)

			if !status {
				failed = true
				Dprintf("ABCProof RIGHT failed to generate!\n")
				// Dprintf("aProof: \n\n %v \n\n", aProof)
				Dprintf("ABCProof RIGHT failed\n")
			}

			if !ABCVerify(A, AToken, aProof) {
				failed = true
				Dprintf("ABCProof RIGHT Failed to verify!\n")
				// Dprintf("aProof: \n\n %v \n\n", aProof)
				Dprintf("ABCVerify RIGHT failed\n")
			}

			if failed && value.Cmp(big.NewInt(0)) != 0 {
				Dprintf("TestABC_Extensive produced a failing test case!\n")
				Dprintf("---\nFailed case:\nvalue: %v \nrandom: %v \nsk: %v\n", value, ua, sk)
				failed = false
			}
		}
		fmt.Println("Passed TestABC_Extensive")
	}
}
