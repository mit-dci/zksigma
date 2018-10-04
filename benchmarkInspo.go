package zkSigma

// TODO: build some benchmarks...
// copied from apl

/*
func BenchmarkCommitPC(b *testing.B) {
	pc := ECPedersen{EC.C, EC.G, EC.H}
	value := new(big.Int).SetInt64(50)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		pc.Commit(value)
	}
}

func BenchmarkOpenPC(b *testing.B) {
	pc := ECPedersen{EC.C, EC.G, EC.H}
	value := new(big.Int).SetInt64(50)

	comm, r := pc.Commit(value)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		pc.Open(value, r, comm)
	}
}

func BenchmarkGSPFS_Prove(b *testing.B) {
	ec := NewECPrimeGroupKey()
	curve, gen1, exp := ec.C, ec.H, ec.N
	gspftInstance := GSPFS{curve, exp, gen1}

	x, err := rand.Int(rand.Reader, new(big.Int).SetInt64(4294967295))
	//x, err := rand.Int(rand.Reader, new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(32), nil)) // proving knowledge of secret key x
	check(err)
	point := ec.H.Mult(x)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		gspftInstance.Prove(point, x)
	}
}

func BenchmarkGSPFS_Verify(b *testing.B) {
	ec := NewECPrimeGroupKey()
	curve, gen1, exp := ec.C, ec.H, ec.N
	gspftInstance := GSPFS{curve, exp, gen1}

	x, err := rand.Int(rand.Reader, new(big.Int).SetInt64(4294967295))
	//x, err := rand.Int(rand.Reader, new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(32), nil)) // proving knowledge of secret key x
	check(err)
	point := ec.H.Mult(x)
	proof := gspftInstance.Prove(point, x)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		gspftInstance.Verify(point, proof)
	}
}

func BenchmarkZKProofs100(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H

	// we prove of knowledge of x, testing the left hand side

	for n := 0; n < b.N; n++ {
		RangeProverProve(value)
		ProveConsistency(cmaux, baux, pk, value, r)
		ProveEquivalence(Base1, Result1, Base2, Result2, x)
		ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)
	}
}

func BenchmarkZKVerifies100(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H

	// we prove of knowledge of x, testing the left hand side
	rp, rz := RangeProverProve(value)
	comm := pc.CommitWithR(value, rz)
	cons := ProveConsistency(cmaux, baux, pk, value, r)
	equiv := ProveEquivalence(Base1, Result1, Base2, Result2, x)
	disj := ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)

	for n := 0; n < b.N; n++ {
		RangeProverVerify(comm, rp)
		VerifyConsistency(cmaux, baux, pk, cons)
		VerifyEquivalence(Base1, Result1, Base2, Result2, equiv)
		VerifyDisjunctive(Base1z, Result1z, Base2z, Result2z, disj)
	}
}

func BenchmarkZKLosdos100(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H

	for n := 0; n < b.N; n++ {
		// we prove
		rp, rz := RangeProverProve(value)
		comm := pc.CommitWithR(value, rz)
		cons := ProveConsistency(cmaux, baux, pk, value, r)
		equiv := ProveEquivalence(Base1, Result1, Base2, Result2, x)
		disj := ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)

		// we verify
		RangeProverVerify(comm, rp)
		VerifyConsistency(cmaux, baux, pk, cons)
		VerifyEquivalence(Base1, Result1, Base2, Result2, equiv)
		VerifyDisjunctive(Base1z, Result1z, Base2z, Result2z, disj)
	}
}

func BenchmarkProveConsistency(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ProveConsistency(cmaux, baux, pk, value, r)
	}
}

func BenchmarkVerifyConsistency(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)
	cons := ProveConsistency(cmaux, baux, pk, value, r)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		VerifyConsistency(cmaux, baux, pk, cons)
	}

}

func BenchmarkProveEquivalence(b *testing.B) {
	ec := NewECPrimeGroupKey()
	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ProveEquivalence(Base1, Result1, Base2, Result2, x)
	}

}

func BenchmarkVerifyEquivalence(b *testing.B) {
	ec := NewECPrimeGroupKey()
	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	equiv := ProveEquivalence(Base1, Result1, Base2, Result2, x)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		VerifyEquivalence(Base1, Result1, Base2, Result2, equiv)
	}

}

func BenchmarkProveDisjunctive(b *testing.B) {
	ec := NewECPrimeGroupKey()

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)
	}
}

func BenchmarkVerifyDisjunctive(b *testing.B) {
	ec := NewECPrimeGroupKey()

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H
	disj := ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		VerifyDisjunctive(Base1z, Result1z, Base2z, Result2z, disj)
	}
}

func BenchmarkRangeProver_Prove(b *testing.B) {
	value := big.NewInt(50)
	for n := 0; n < b.N; n++ {
		RangeProverProve(value)
	}
}

func BenchmarkRangeProver_Verify(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pec := ECPedersen{ec.C, ec.G, ec.H}
	value := big.NewInt(50)
	proof, r := RangeProverProve(value)
	comm := pec.CommitWithR(value, r)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		RangeProverVerify(comm, proof)
	}
}
*/
