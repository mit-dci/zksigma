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
	p := ZKCurve.G.Mult(v)
	negp := p.Neg()
	sum := p.Add(negp)
	if !sum.Equal(ZKCurve.Zero()) {
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
	sum = p.Add(ZKCurve.Zero())
	if !sum.Equal(p) {
		fmt.Printf("p : %v\n", p)
		fmt.Printf("sum : %v\n", sum)
		t.Fatalf("p + 0 should be p\n")
	}
	fmt.Println("Passed TestZKCurveMethods")
}

func TestZkpCryptoStuff(t *testing.T) {
	value := big.NewInt(-100)
	//pk, sk := KeyGen()

	testCommit, randomValue := PedCommit(value) // xG + rH

	value = new(big.Int).Mod(value, ZKCurve.N)

	// vG
	tempX, tempY := ZKCurve.C.ScalarMult(ZKCurve.G.X, ZKCurve.G.Y, value.Bytes())

	ValEC := ECPoint{tempX, tempY}          // vG
	InvValEC := ZKCurve.G.Mult(value).Neg() // 1/vG (acutally mod operation but whatever you get it)
	Dprintf("         vG : %v --- value : %v \n", ValEC, value)
	Dprintf("       1/vG : %v\n", InvValEC)

	tempX, tempY = ZKCurve.C.Add(ValEC.X, ValEC.Y, InvValEC.X, InvValEC.Y)
	Dprintf("Added the above: %v, %v\n", tempX, tempY)

	if tempX.Cmp(ZKCurve.Zero().X) != 0 || tempY.Cmp(ZKCurve.Zero().Y) != 0 {
		fmt.Printf("Added the above: %v, %v", tempX, tempY)
		fmt.Printf("The above should have been (0,0)")
		t.Fatalf("Failed Addition of inverse points failed")
	}

	testOpen := InvValEC.Add(testCommit)                                               // 1/vG + vG + rH ?= rH (1/vG + vG = 0, hopefully)
	tempX, tempY = ZKCurve.C.ScalarMult(ZKCurve.H.X, ZKCurve.H.Y, randomValue.Bytes()) // rH
	RandEC := ECPoint{tempX, tempY}

	if !RandEC.Equal(testOpen) {
		fmt.Printf("RandEC : %v\n", RandEC)
		fmt.Printf("testOpen : %v\n", testOpen)
		t.Fatalf("RandEC should have been equal to testOpen\n")
	}

	fmt.Println("Passed TestzkpCryptoStuff")

}

func TestZkpCryptoCommitR(t *testing.T) {

	u, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	testCommit := ZKCurve.CommitR(ZKCurve.H, u)

	if !(ZKCurve.VerifyR(testCommit, ZKCurve.H, u)) {
		fmt.Printf("testCommit: %v\n", testCommit)
		fmt.Printf("ZKCurve.H: %v, \n", ZKCurve.H)
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

	x, err := rand.Int(rand.Reader, ZKCurve.N)
	check(err)

	// MUST use G here becuase of GSPFSProve implementation
	randPoint := ZKCurve.G.Mult(x)

	testProof := GSPFSProve(x)

	if !GSPFSVerify(randPoint, testProof) {
		fmt.Printf("x : %v\n", x)
		fmt.Printf("randPoint : %v\n", randPoint)
		fmt.Printf("testProof : %v\n", testProof)
		t.Fatalf("GSPFS Proof didnt generate properly\n")
	}

	// Using H here should break the proof
	randPoint = ZKCurve.H.Mult(x)

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
	Base1 := ZKCurve.G
	Result1X, Result1Y := ZKCurve.C.ScalarMult(Base1.X, Base1.Y, x.Bytes())
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ZKCurve.H
	Result2X, Result2Y := ZKCurve.C.ScalarMult(Base2.X, Base2.Y, x.Bytes())
	Result2 := ECPoint{Result2X, Result2Y}

	eqProof, status1 := EquivilanceProve(Base1, Result1, Base2, Result2, x)

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

	Dprintf("[debug] First djProof : ")
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

// This is not critical to the zkLedger, holding off on building the verify and test function for more useful stuff
// func TestEquiviOrLog

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

	Dprintf(" [debug] Testing incorrect consistency proof\n")
	// if ConsistencyVerify(comm, y, pk, conProof) {
	// 	t.Fatalf("Error -- Proof should be wrong\n")
	// }

	if !status1 || status2 {
		t.Fatalf("One of the proofs' status is incorrect\n")
	}

	fmt.Println("Passed TestConsistency")
}

func TestABC(t *testing.T) {
	sk, err := rand.Int(rand.Reader, ZKCurve.N)
	pk := ZKCurve.H.Mult(sk)
	value, err := rand.Int(rand.Reader, ZKCurve.N)

	CM, randomness := PedCommit(value)
	CMTok := pk.Mult(randomness)
	check(err)

	Dprintf(" [debug] TRUE-RIGHT Next proof should pass\n")

	proof, status, _ := ABCProve(CM, CMTok, value, sk, 1)

	if !status {
		Dprintf("avgProof: status is false but should be true")
	}

	if !ABCVerify(CM, CMTok, proof) {
		Dprintf("avg proof not working\n")
		t.Fatalf("avg proof verify should have been true\n")
	}

	Dprintf(" [debug] FALSE-LEFT Next proof should fail\n")

	proof, status, _ = ABCProve(CM, CMTok, value, sk, 0)

	if !status {
		Dprintf("avgProof: status is true but should be false\n")
	}

	value = big.NewInt(0)
	CM, randomness = PedCommit(value)
	CMTok = pk.Mult(randomness)

	Dprintf(" [debug] TRUE-LEFT Next proof should pass\n")

	proof, status, _ = ABCProve(CM, CMTok, value, sk, 0)

	if !status {
		Dprintf("avgProof: status is false but should be true\n")
	}

	if !ABCVerify(CM, CMTok, proof) {
		Dprintf("avg proof not working\n")
		t.Fatalf("avg proof verify should have been true\n")
	}

	Dprintf(" [debug] FALSE-RIGHT Next proof should fail\n")

	proof, status, _ = ABCProve(CM, CMTok, value, sk, 1)

	if !status {
		Dprintf("avgProof: status is true but should be false\n")
	}

	fmt.Println("Passed TestABC")
}

func TestAverages(t *testing.T) {

	var TxCommits []ECPoint
	var TxRands []ECPoint
	var AvgCommits []ECPoint
	var AvgRands []ECPoint

	// total_rToken := big.NewInt(0)
	// total_crToken := big.NewInt(0)

	var numTx int64
	numTx = 10
	var TxValues []*big.Int

	TxValues = make([]*big.Int, numTx)
	TxCommits = make([]ECPoint, numTx)
	TxRands = make([]ECPoint, numTx)
	AvgCommits = make([]ECPoint, numTx)
	AvgRands = make([]ECPoint, numTx)

	sk, _ := rand.Int(rand.Reader, ZKCurve.N)
	pk := ZKCurve.H.Mult(sk)

	var temp *big.Int

	// Generating random transactions
	for ii := int64(0); ii < numTx; ii++ {
		value, _ := rand.Int(rand.Reader, big.NewInt(1000))
		TxValues[ii] = new(big.Int).Set(value)

		TxCommits[ii], temp = PedCommit(value)
		TxRands[ii] = pk.Mult(temp)
		// total_rToken = new(big.Int).Add(total_rToken, temp)

		aProof, status, uc := ABCProve(TxCommits[ii], TxRands[ii], value, sk, 1)
		if !status {
			Dprintf("Something went wrong...\n")
		}

		AvgCommits[ii] = aProof.C
		AvgRands[ii] = pk.Mult(uc)
		// total_crToken = new(big.Int).Add(total_crToken, temp)
	}

	var TxAgg ECPoint
	var RandAgg ECPoint
	var AvgAgg ECPoint
	var CRandAgg ECPoint
	TotalClear := big.NewInt(0)
	NonZeroTx := big.NewInt(0)

	TxAgg = ZKCurve.Zero()
	RandAgg = ZKCurve.Zero()
	AvgAgg = ZKCurve.Zero()
	CRandAgg = ZKCurve.Zero()

	for ii := int64(0); ii < numTx; ii++ {
		TxAgg = TxAgg.Add(TxCommits[ii])
		RandAgg = RandAgg.Add(TxRands[ii])
		AvgAgg = AvgAgg.Add(AvgCommits[ii])
		CRandAgg = CRandAgg.Add(AvgRands[ii])
		TotalClear = TotalClear.Add(TotalClear, TxValues[ii])
		if TxValues[ii].Cmp(big.NewInt(0)) == 0 {
			numTx--
		}

	}

	NonZeroTx = big.NewInt(numTx)
	ClearAverage := new(big.Int).Quo(TotalClear, NonZeroTx)

	// TOTAL CLEAR WILL BE REPLACED WITH BANK ANSWER
	gv := ZKCurve.G.Mult(TotalClear).Neg()
	T := TxAgg.Add(gv)

	EProofSum, _ := EquivilanceProve(T, RandAgg, ZKCurve.H, pk, sk)
	Dprintf("EProofSum : %v\n", EProofSum)

	if !EquivilanceVerify(T, RandAgg, ZKCurve.H, pk, EProofSum) {
		fmt.Printf("Something wrongs... avg : %v\n", ClearAverage)
	}

	// TXCOUNT WILL BE REPLACED WITH BANK ANSWER
	nv := ZKCurve.G.Mult(NonZeroTx).Neg()
	L := AvgAgg.Add(nv)

	EProofAvg, _ := EquivilanceProve(L, CRandAgg, ZKCurve.H, pk, sk)
	Dprintf("EProofSum : %v\n", EProofAvg)

	if !EquivilanceVerify(L, CRandAgg, ZKCurve.H, pk, EProofAvg) {
		fmt.Printf("Something wrongs... avg : %v\n", ClearAverage)
	}

}
