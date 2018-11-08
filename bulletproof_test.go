package zksigma

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestSetup(t *testing.T) {

	if !*BULLET {
		fmt.Println("Skipped Bullerproof setup")
		t.Skipf("Skipped Bulletproof setup\n")
	}

	BPInit()
	fmt.Println("Bulletproof setup completed")
}

// func TestPrintStuff(t *testing.T) {
// 	fmt.Printf("ZKGen.N: %v\n", ZKGen.N)
// 	fmt.Printf("ZKGen.M: %v\n", ZKGen.M)
// 	fmt.Printf("ZKGen.G: %v\n\n\n", ZKGen.VecG)
// 	fmt.Printf("ZKGen.H: %v\n\n\n", ZKGen.VecH)
// }

var Giant64 = []*big.Int{
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(10), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(42)}

func TestBinaryDecomp(t *testing.T) {

	if !*BULLET {
		fmt.Println("Skipped Bulletproof TestBinaryDecomp, use -bullet to run")
		t.Skip("Skipped Bulletproof TestBinaryDecomp")
	}

	// 113 =  b01110001 test
	answer := []*big.Int{
		big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	check := binaryDecomp(big.NewInt(113))

	for ii, vv := range answer {
		if vv.Cmp(check[ii]) != 0 {
			t.Logf("BianryDecomp failed at:\n")
			t.Logf("answer[%v]: %v\n", ii, vv)
			t.Logf(" check[%v]: %v\n", ii, check[ii])
			t.Fatalf("binaryDecomp did not generate the correct array\n")
		}
	}

	fmt.Println("Passed TestBinaryDecomp")
}

func TestDotProd(t *testing.T) {

	if !*BULLET {
		fmt.Println("Skipped Bulletproof TestDotProd")
		t.Skip("Skipped Bulletproof TestDotProd")
	}

	if big.NewInt(42*42+10*10).Cmp(dotProd(Giant64, Giant64)) != 0 {
		t.Logf("dotProd not working properly:\n")
		t.Logf("expected: %v\n", big.NewInt(42*42))
		t.Fatalf("Failed TestDotProd\n")
	}

	fmt.Println("Passed TestDotProd")

}

// Not sure how to test some of these since going through the math by hand is difficult
// For now if nothing seg-faults Ill just assume it is working as intended until further notice

func TestCallEachFunc(t *testing.T) {

	if !*BULLET {
		fmt.Println("Skipped Bulletproof TestCallEachFunc")
		t.Skip("Skipped Bulletproof TestCallEachFunc")
	}

	binaryDecomp(big.NewInt(1234567))
	fmt.Println(" - binaryDecomp runs")
	dotProd(Giant64, Giant64)
	fmt.Println(" - dotProd runs")
	ecDotProd(OnesVec, ZKGen.VecG)
	fmt.Println(" - ecDotProd runs")
	vecPedComm(OnesVec, ZKGen.VecG, ZKGen.VecH)
	fmt.Println(" - vecPedComm runs")
	vecMult(Giant64, Giant64)
	fmt.Println(" - vecMult runs")
	splitVec(Giant64)
	fmt.Println(" - splitVec runs")
	genVec(big.NewInt(1))
	fmt.Println(" - genVec runs")

	fmt.Println("Passed TestCallEachFunc")
}

func TestInProdProve(t *testing.T) {

	if !*BULLET {
		fmt.Println("Skipped Bulletproof TestInProdProve")
		t.Skip("Skipped Bulletproof TestInProdProve")
	} else {
		fmt.Println("WARNING: InProdProve currently broken, next test will fail")
	}

	a := make([]*big.Int, numBits)
	b := make([]*big.Int, numBits)

	for ii := range a {
		a[ii], _ = rand.Int(rand.Reader, ZKGen.MaxVal)
		b[ii], _ = rand.Int(rand.Reader, ZKGen.MaxVal)
	}

	// proof, status := InProdProve(a, b, ZKGen.VecG, ZKGen.VecH)

	proof, err := InProdProveRecursive(a, b, big.NewInt(0), ZKGen.VecG, ZKGen.VecH, make([]ECPoint, 0), make([]ECPoint, 0))

	if err != nil {
		t.Fatalf("InProdProof did not generate properly!\n")
	}

	status, err := InProdVerify1(ZKGen.VecG, ZKGen.VecH, proof)
	if !status || err != nil {
		t.Fatalf("InProdProof did not verify!\n")
	}

	fmt.Println("Passed TestInProdProve")
}
