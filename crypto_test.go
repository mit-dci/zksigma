package zkCrypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestInit(t *testing.T) {
	Init()
	fmt.Println("Global Variables Initialized")
}

func TestECPointMethods(t *testing.T) {
	v := big.NewInt(3)
	p := zkCurve.G.Mult(v)
	negp := p.Neg()
	sum := p.Add(negp)
	if !sum.Equal(zkCurve.Zero()) {
		fmt.Printf("p : %v\n", p)
		fmt.Printf("negp : %v\n", negp)
		fmt.Printf("sum : %v\n", sum)
		t.Fatalf("p + -p should be 0\n")
	}
	negnegp := negp.Neg()
	if !negnegp.Equal(p) {
		fmt.Printf("p : %v\n", p)
		fmt.Printf("negnegp : %v\n", negnegp)
		t.Fatalf("-(-p) should be p\n")
	}
	sum = p.Add(zkCurve.Zero())
	if !sum.Equal(p) {
		fmt.Printf("p : %v\n", p)
		fmt.Printf("sum : %v\n", sum)
		t.Fatalf("p + 0 should be p\n")
	}
	fmt.Println("Passed TestzkCurveMethods")
}

func TestZkpCryptoStuff(t *testing.T) {
	value := big.NewInt(-100)
	//pk, sk := KeyGen()

	testCommit, randomValue := PedCommit(value) // xG + rH

	value = new(big.Int).Mod(value, zkCurve.N)

	// vG
	tempX, tempY := zkCurve.C.ScalarMult(zkCurve.G.X, zkCurve.G.Y, value.Bytes())

	ValEC := ECPoint{tempX, tempY}          // vG
	InvValEC := zkCurve.G.Mult(value).Neg() // 1/vG (acutally mod operation but whatever you get it)
	Dprintf("         vG : %v --- value : %v \n", ValEC, value)
	Dprintf("       1/vG : %v\n", InvValEC)

	tempX, tempY = zkCurve.C.Add(ValEC.X, ValEC.Y, InvValEC.X, InvValEC.Y)
	Dprintf("Added the above: %v, %v\n", tempX, tempY)

	if tempX.Cmp(zkCurve.Zero().X) != 0 || tempY.Cmp(zkCurve.Zero().Y) != 0 {
		fmt.Printf("Added the above: %v, %v", tempX, tempY)
		fmt.Printf("The above should have been (0,0)")
		t.Fatalf("Failed Addition of inverse points failed")
	}

	testOpen := InvValEC.Add(testCommit)                                               // 1/vG + vG + rH ?= rH (1/vG + vG = 0, hopefully)
	tempX, tempY = zkCurve.C.ScalarMult(zkCurve.H.X, zkCurve.H.Y, randomValue.Bytes()) // rH
	RandEC := ECPoint{tempX, tempY}

	if !RandEC.Equal(testOpen) {
		fmt.Printf("RandEC : %v\n", RandEC)
		fmt.Printf("testOpen : %v\n", testOpen)
		t.Fatalf("RandEC should have been equal to testOpen\n")
	}

	fmt.Println("Passed TestzkpCryptoStuff")

}

func TestZkpCryptoCommitR(t *testing.T) {

	u, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)

	testCommit := zkCurve.CommitR(zkCurve.H, u)

	if !(zkCurve.VerifyR(testCommit, zkCurve.H, u)) {
		fmt.Printf("testCommit: %v\n", testCommit)
		fmt.Printf("zkCurve.H: %v, \n", zkCurve.H)
		fmt.Printf("u : %v\n", u)
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
		fmt.Printf("x : %v --- u : %v\n", x, u)
		fmt.Printf("commit: %v\n", commit)
		fmt.Printf("commitR: %v\n", commitR)
		t.Fatalf("commit and commitR should be equal")
	}

	if !Open(x, u, commit) || !Open(x, u, commitR) {
		fmt.Printf("x : %v --- u : %v\n", x, u)
		fmt.Printf("commit: %v\n", commit)
		fmt.Printf("commitR: %v\n", commitR)
		t.Fatalf("commit and/or commitR did not successfully open")
	}

	if Open(badx, u.Neg(u), commit) || Open(badx, u.Neg(u), commitR) {
		fmt.Printf("x : %v --- u : %v\n", x, u)
		fmt.Printf("commit: %v\n", commit)
		fmt.Printf("commitR: %v\n", commitR)
		t.Fatalf("commit and/or commitR should not have opened properly")
	}

	fmt.Println("Passed TestPedersenCommit")

}

func TestGSPFS(t *testing.T) {

	x, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)

	// MUST use G here becuase of GSPFSProve implementation
	randPoint := zkCurve.G.Mult(x)

	testProof := GSPFSProve(x)

	if !GSPFSVerify(randPoint, testProof) {
		fmt.Printf("x : %v\n", x)
		fmt.Printf("randPoint : %v\n", randPoint)
		fmt.Printf("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof didnt generate properly\n")
	}

	// Using H here should break the proof
	randPoint = zkCurve.H.Mult(x)

	if GSPFSVerify(randPoint, testProof) {
		fmt.Printf("x : %v\n", x)
		fmt.Printf("randPoint : %v\n", randPoint)
		fmt.Printf("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof should not have worked\n")
	}

	fmt.Println("Passed TestGSPFS")

}

func TestEquivilance(t *testing.T) {

	x := big.NewInt(100)
	Base1 := zkCurve.G
	Result1X, Result1Y := zkCurve.C.ScalarMult(Base1.X, Base1.Y, x.Bytes())
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := zkCurve.H
	Result2X, Result2Y := zkCurve.C.ScalarMult(Base2.X, Base2.Y, x.Bytes())
	Result2 := ECPoint{Result2X, Result2Y}

	eqProof := EquivilanceProve(Base1, Result1, Base2, Result2, x)

	if !EquivilanceVerify(Base1, Result1, Base2, Result2, eqProof) {
		fmt.Printf("Base1 : %v\n", Base1)
		fmt.Printf("Result1 : %v\n", Result1)
		fmt.Printf("Base2 : %v\n", Base2)
		fmt.Printf("Result2 : %v\n", Result2)
		fmt.Printf("Proof : %v \n", eqProof)
		t.Fatalf("Equivilance Proof verification failed")
	}

	Dprintf("Next comparison should fail\n")
	// Bases swapped shouldnt work
	if EquivilanceVerify(Base2, Result1, Base1, Result2, eqProof) {
		fmt.Printf("Base1 : %v\n", Base1)
		fmt.Printf("Result1 : %v\n", Result1)
		fmt.Printf("Base2 : %v\n", Base2)
		fmt.Printf("Result2 : %v\n", Result2)
		fmt.Printf("Proof : %v \n", eqProof)
		t.Fatalf("Equivilance Proof verification doesnt work")
	}

	Dprintf("Next comparison should fail\n")
	// Bad proof
	eqProof.HiddenValue = big.NewInt(-1)
	if EquivilanceVerify(Base2, Result1, Base1, Result2, eqProof) {
		fmt.Printf("Base1 : %v\n", Base1)
		fmt.Printf("Result1 : %v\n", Result1)
		fmt.Printf("Base2 : %v\n", Base2)
		fmt.Printf("Result2 : %v\n", Result2)
		fmt.Printf("Proof : %v \n", eqProof)
		t.Fatalf("Equivilance Proof verification doesnt work")
	}

	fmt.Println("Passed TestEquivilance")

}

func TestDisjunctive(t *testing.T) {

	x := big.NewInt(100)
	y := big.NewInt(101)

	Base1 := zkCurve.G
	Result1 := zkCurve.G.Mult(x)
	Base2 := zkCurve.H
	Result2 := zkCurve.H.Mult(y)

	djProofLEFT := DisjunctiveProve(Base1, Result1, Base2, Result2, x, left)
	djProofRIGHT := DisjunctiveProve(Base1, Result1, Base2, Result2, y, right)

	Dprintf("[debug] First djProof : ")
	if !DisjunctiveVerify(Base1, Result1, Base2, Result2, djProofLEFT) {
		t.Fatalf("djProof failed to generate properly for left side\n")
	}

	Dprintf("Passed \n [debug] Second djProof : ")
	if !DisjunctiveVerify(Base1, Result1, Base2, Result2, djProofRIGHT) {
		t.Fatalf("djProof failed to generate properly for right side\n")
	}

	Dprintf("Passed \n [debug] Next djProof attemp should result in an error message\n")
	djProofTEST := DisjunctiveProve(Base1, Result1, Base2, Result2, y, left) // This should fail

	if djProofTEST != nil {
		t.Fatalf("djProof should not have been generated\n")
	}

	fmt.Println("Passed TestDisjunctiveg")

}

// This is not critical to the zkLedger, holding off on building the verify and test function for more useful stuff
// func TestEquiviOrLog

func TestConsistency(t *testing.T) {

	x, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)

	sk, err := rand.Int(rand.Reader, zkCurve.N)
	check(err)
	pk := zkCurve.H.Mult(sk)

	comm, u := PedCommit(x)
	y := pk.Mult(u)

	conProof := ConsistencyProve(comm, y, pk, x, u)

	Dprintf(" [debug] Testing correct consistency proof\n")
	if !ConsistencyVerify(comm, y, pk, conProof) {
		t.Fatalf("Error -- Proof should be correct\n")
	}

	Dprintf(" [debug] Next proof should fail\n")

	conProof = ConsistencyProve(y, comm, pk, x, u)

	Dprintf(" [debug] Testing incorrect consistency proof\n")
	if ConsistencyVerify(comm, y, pk, conProof) {
		t.Fatalf("Error -- Proof should be wrong\n")
	}

	fmt.Println("Passed TestConsistency")
}

func TestAvg(t *testing.T) {
	sk, err := rand.Int(rand.Reader, zkCurve.N)
	pk := zkCurve.H.Mult(sk)
	value, err := rand.Int(rand.Reader, zkCurve.N)

	CM, randomness := PedCommit(value)
	CMTok := pk.Mult(randomness)
	check(err)

	Dprintf(" [debug] TRUE-RIGHT Next proof should pass\n")

	proof, status := averageProve(CM, CMTok, value, sk, right)

	if !status {
		Dprintf("avgProof: status is false but should be true")
	}

	if !avgVerify(CM, CMTok, proof) {
		Dprintf("avg proof not working\n")
		t.Fatalf("avg proof verify should have been true\n")
	}

	Dprintf(" [debug] FALSE-LEFT Next proof should fail\n")

	proof, status = averageProve(CM, CMTok, value, sk, left)

	if !status {
		Dprintf("avgProof: status is true but should be false\n")
	}

	value = big.NewInt(0)
	CM, randomness = PedCommit(value)
	CMTok = pk.Mult(randomness)

	Dprintf(" [debug] TRUE-LEFT Next proof should pass\n")

	proof, status = averageProve(CM, CMTok, value, sk, left)

	if !status {
		Dprintf("avgProof: status is false but should be true\n")
	}

	if !avgVerify(CM, CMTok, proof) {
		Dprintf("avg proof not working\n")
		t.Fatalf("avg proof verify should have been true\n")
	}

	Dprintf(" [debug] FALSE-RIGHT Next proof should fail\n")

	proof, status = averageProve(CM, CMTok, value, sk, right)

	if !status {
		Dprintf("avgProof: status is true but should be false\n")
	}

	fmt.Println("Passed TestAvg")
}
