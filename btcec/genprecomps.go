// Copyright 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This file is ignored during the regular build due to the following build tag.
// It is called by go generate and used to automatically generate pre-computed
// tables used to accelerate operations.
// +build ignore

package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcec"
)

func main() {
	fi, err := os.Create("secp256k1.go")
	if err != nil {
		log.Fatal(err)
	}
	defer fi.Close()

	fi2, err2 := os.Create("secp256k1H.go")
	if err2 != nil {
		log.Fatal(err2)
	}
	defer fi2.Close()

	// Compress the serialized byte points.
	serialized := btcec.S256().SerializedBytePoints()
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write(serialized); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	w.Close()

	serializedH := btcec.S256().SerializedBytePointsH()
	var compressedH bytes.Buffer
	wH := zlib.NewWriter(&compressedH)
	if _, err := wH.Write(serializedH); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	wH.Close()

	// Encode the compressed byte points with base64.
	encoded := make([]byte, base64.StdEncoding.EncodedLen(compressed.Len()))
	base64.StdEncoding.Encode(encoded, compressed.Bytes())

	encodedH := make([]byte, base64.StdEncoding.EncodedLen(compressedH.Len()))
	base64.StdEncoding.Encode(encodedH, compressedH.Bytes())

	fmt.Fprintln(fi, "// Copyright (c) 2015 The btcsuite developers")
	fmt.Fprintln(fi, "// Use of this source code is governed by an ISC")
	fmt.Fprintln(fi, "// license that can be found in the LICENSE file.")
	fmt.Fprintln(fi)
	fmt.Fprintln(fi, "package btcec")
	fmt.Fprintln(fi)
	fmt.Fprintln(fi, "// Auto-generated file (see genprecomps.go)")
	fmt.Fprintln(fi, "// DO NOT EDIT")
	fmt.Fprintln(fi)
	fmt.Fprintf(fi, "var secp256k1BytePoints = %q\n", string(encoded))

	a1, b1, a2, b2 := btcec.S256().EndomorphismVectors()
	fmt.Println("The following values are the computed linearly " +
		"independent vectors needed to make use of the secp256k1 " +
		"endomorphism:")
	fmt.Printf("a1: %x\n", a1)
	fmt.Printf("b1: %x\n", b1)
	fmt.Printf("a2: %x\n", a2)
	fmt.Printf("b2: %x\n", b2)

	// H
	fmt.Fprintln(fi2, "// Copyright (c) 2015 The btcsuite developers")
	fmt.Fprintln(fi2, "// Use of this source code is governed by an ISC")
	fmt.Fprintln(fi2, "// license that can be found in the LICENSE file.")
	fmt.Fprintln(fi2)
	fmt.Fprintln(fi2, "package btcec")
	fmt.Fprintln(fi2)
	fmt.Fprintln(fi2, "// Auto-generated file (see genprecomps.go)")
	fmt.Fprintln(fi2, "// DO NOT EDIT")
	fmt.Fprintln(fi2)
	fmt.Fprintf(fi2, "var secp256k1BytePointsH = %q\n", string(encodedH))
}
