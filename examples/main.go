package main

import (
	"fmt"

	"github.com/mit-dci/zksigma"
)

func main() {
	zksigma.Init()
	fmt.Println(zksigma.ZKCurve)
}
