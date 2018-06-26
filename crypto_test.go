package zkCrypto

import (
	"fmt"
	"math/big"
	"testing"
)

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

func TestzkpCryptoStuff(t *testing.T) {
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
	Dprintf("Added the above: %v, %v", tempX, tempY)

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
