/*
**WARNING: zkSigma is research code and should not be used with sensitive data.  It definitely has bugs!**

zkSigma is a library for generating non-interactive zero-knowledge proofs, also known as NIZKs. The proofs in zkSigma are based on Generalized Schnorr Proofs; they can be publicly verified and do not require any trusted setup.

Features:

* Generating non-interative zero-knowledge proofs for various logical statements

* Simplified elliptic curve operations

* Plug and Play API

More info on Github
*/
package zksigma

// Side is an enum to pick what side of the proof you want to generate
type Side int

const (
	// Left generates the left side of a proof
	Left Side = 0
	// Right generates the right side of a proof
	Right Side = 1
)
