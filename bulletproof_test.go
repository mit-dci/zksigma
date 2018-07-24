package zkCrypto

import (
	"fmt"
	"math/big"
	"testing"
)

func TestSetup(t *testing.T) {
	Init()
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
	big.NewInt(10), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
	big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(42)}

func TestBinaryDecomp(t *testing.T) {
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
			Dprintf("BianryDecomp failed at:\n")
			Dprintf("answer[%v]: %v\n", ii, vv)
			Dprintf(" check[%v]: %v\n", ii, check[ii])
			t.Fatalf("binaryDecomp did not generate the correct array\n")
		}
	}

	fmt.Println("Passed TestBinaryDecomp")
}

func TestDotProd(t *testing.T) {

	if big.NewInt(42*42).Cmp(dotProd(Giant64, Giant64)) != 0 {
		Dprintf("dotProd not working properly:\n")
		Dprintf("expected: %v\n", big.NewInt(10*10+42*42))
		Dprintf("Giant64 .* temp: %v\n", check)
		t.Fatalf("Failed TestDotProd\n")
	}

	fmt.Println("Passed TestDotProd")

}
