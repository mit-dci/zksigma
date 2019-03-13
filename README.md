# zkSigma

**WARNING: zkSigma is research code and should not be used with sensitive data. It definitely has bugs!**

zkSigma is a library for generating non-interactive zero-knowledge proofs, also 
known as NIZKs. The proofs in zkSigma are based on Generalized Schnorr Proofs; 
they can be publicly verified and do not require any trusted setup.

Features:
- Generating non-interactive zero-knowledge proofs for various logical statements
- Simplified elliptic curve operations
- Plug and Play API
- Built in serialization and deserialization of proofs

Statements that can be proved:
- I can open a Pedersen Commitment `A`(=`aG+uH`) (Open)
- I know the discrete log of a commitment `A`(=`aG`) (GSPFS Proof)
- I know the discrete log of commitments `A`(=`xG`) and `B`(=`xH`) and they are equal (Equivalence Proof)
- I know the discrete log of either commitment `A` or `B` (Disjunctive Proof)
- I know that the blinding factor of commitments `A` and `B` is equal (Consistency Proof)
- I know `a`, `b`, and `c` in commitments `A`, `B` and `C` and `a * b = c` (ABC Proof)
- I know `a` and `b` in commitments `A` and `B` and `a != b` (InequalityProof is a special case of ABC Proof)


Running the tests:
- Will show debugging messages, good for debugging a proof that is not generating or verifying
```
go test -debug1
```
- Run rangeproof tests (default: off)
```
go test -range
```

Notation: 
- lower case letters are scalars (`a`, `b`, `c`, `x`,...)
- lower case letters starting with `u` are randomly generated scalars (`ua`, `ub`, `u1`, `u2`, ...)
- upper case letters are always elliptic curve points (type `ECPoint`) (`G`, `H`, `A`, `B`,...)
  - `G` = Base Point of `ZKCurve.C`
  - `H` = Secondary Base Point whose relation to `G` should not be known
  - `A`, `B`, `CM`, `CMTok`, etc, are usually of the form `vG+uH` unless otherwise stated
- `sk` and `PK` are always secret key and public key. `sk` is a randomly chosen scalar.  `PK = sk * H`
- `CM` = Commitment of the form `aG + uH`
- `CMTok` = Commitment Token of the form `ua * PK`

## Articles related to NIZK Proofs

[Sigma Protocols](http://www.cs.au.dk/~ivan/Sigma.pdf)
: A three step protocol where a prover and verifier can exchange a commitment and a challenge in order to verify proof of knowledge behind the commitment. [Simple explanation here.](https://en.wikipedia.org/wiki/Proof_of_knowledge#Sigma_protocols)


[Unifying Zero-Knowledge Proofs of Knowledge](ftp://ftp.inf.ethz.ch/pub/crypto/publications/Maurer09.pdf)
: This paper explains zero-knowledge proof of knowledge and provides the foundation on which all our proofs are built upon. 

[zkLedger](https://www.usenix.org/conference/nsdi18/presentation/narula)
: A privacy preserving distributed ledger that allows for verifiable auditing. The original motivation for creating zksigma.

[Bulletproofs](https://doc-internal.dalek.rs/bulletproofs/inner_product_proof/index.html)
: A faster form of rangeproofs that only requires log(n) steps to verify that a commitment is within a given range. This might be integrated into this library in the future.

## Comparison to zkSNARKS

You cannot use zkSigma to prove general statements.
