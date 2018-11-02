package main

import (
	"fmt"

	"github.com/mit-dci/zkSigma"
)

func main() {
	zkSigma.Init()
	fmt.Println(zkSigma.ZKCurve)
}
