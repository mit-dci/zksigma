# zkSigma

**WARNING: zkSigma is research code and should not be used with sensitive data.  It definitely has bugs!**

zkSigma is a library for generating non-interactive zero-knowledge proofs, also known as NIZKs. The proofs in zkSigma are based on Generalized Schnorr Proofs; they can be publicly verified and do not require any trusted setup.


Features:
- Generating non-interative zero-knowledge proofs for various logical statements
- Simplified elliptic curve operations
- Plug and Play API

Statements that can be proved:
- I can open a Pedersen Commitment A(= aG + uH) (Open)
- I know the discrete log of a commitment A(=aG) (GSPFS Proof)
- I know the discrete log of commitments A(=xG) and B(=xH) and they are equal (Equivilance Proof)
- I know either the discrete log of commitments A or B (Disjunctive Proof)
- I know that the blinding factor of commitments A and B are equal (Consistancy Proof)
- I know a, b, and c in commitments A, B and C and a * b = c (ABC Proof)
- I know commitments a and b in commitments A and B and  a != b  (InequalityProve -> ABCProof)


Running the tests:
- Will show debugging messages, good for debugging a proof that is not genrating or verifing
```
go test -debug1
```
- Run bulletproof tests 
```
go test -bullet
```
- Run rangeproofs
```
go test -range
```
- Skip basic tests
```
go test -nobasic
```


Notation: 
- lower case letters are scalars (a, b, c, x,...)
- lower case letters starting with u are randomly generated scalars (ua, ub, u1, u2, ...)
- upper case letters are always elliptic curve points (ECPoints) (G, H, A, B,...)
  - G = Base Point of ZKCurve.C
  - H = Secondry Base Point whose relation to G should not be known
  - A, B, CM, CMTok, etc, are usually of the form vG+uH unless otherwise stated
- sk and PK are always secret key and public key. sk is a randomly chosen scalar.  PK = sk * H
- CM = Commitment of the form aG + uaH
- CMTok = Commitment Token of the form ua * PK

Coming Soon<sup>TM</sup>:
- Rangeproofs (rp.Aggragate currently broken, need to investigate)
- Bulletproofs (inner product proof currently broken, need to investigate, something about golang deep copy maybe, fairly confident the logic of the implemnatiaon is correct)
    - Referance for recursive implementation [here](https://github.com/bbuenz/BulletProofLib/tree/master/src/main/java/edu/stanford/cs/crypto/efficientct/innerproduct)
    - Referance for iterative implementation [here](https://github.com/dalek-cryptography/bulletproofs/blob/main/src/inner_product_proof.rs)

**Dependancies**:
- github.com/narula/btcd/btcec (can be swapped out for any curve that satisfies Golang's elliptic.Curve interface)


### Some fun reading

[Simga Protocols](http://www.cs.au.dk/~ivan/Sigma.pdf)
: is a three step protocol where a prover and verifier can exchange a commitment and a challenge in order to verify proof of knowledge behind the commitment. [Simple explination here.](https://en.wikipedia.org/wiki/Proof_of_knowledge#Sigma_protocols)

ftp://ftp.inf.ethz.ch/pub/crypto/publications/Maurer09.pdf (ftp link won't embed)

Unifying Zero-Knowledge Proofs of Knowledge: this paper explains zero-knowledge proof of knowledge and provides the foundation on which all our proofs are built upon. 

[zkLedger](https://www.usenix.org/conference/nsdi18/presentation/narula)
: a privacy perserving distributed ledger that allows for verifiiable auditing. (Neat application of NIZKs)

[bulletproofs](https://doc-internal.dalek.rs/bulletproofs/inner_product_proof/index.html): a faster form of rangeproofs that only requres log(n) setps to verify that a commitment is within a given range


## Comparison to zkSNARKS

You cannot use zkSigma to prove general statements.
