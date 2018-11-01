# zkSigma

This is a standalone library for genreating zero-knowledge proofs that can be verified non-interatively known as NIZKs. NIZKs do not require trusted setup and can be verfied without additional communication from the prover, although we do sacrifice the complexity of statements we can prove when comparted to like zkSNARKs for instance.

Features:
- Generating non-interative zero-knowledge proofs for various logical statements
- Simplified elliptic curve operations
- Plug and Play API

Statements that can be proved:
- I know discrete log of commtiment A(=aG) (GSPFS Proof)
- I know that discrete log of A(=xG) and B(=xH) are equal (Equivilance Proof)
- I can open Pedersen Commitment A(= aG + uH) (Open)
- I know either discrete log of A or B (Disjunctive Proof)
- I know that blinding factor of A and B are equal (Consistancy Proof)
- I know that a * b = c in commitments A, B and C (ABC Proof)
- I can show that a != b in commtimetns A and B (InequalityProve -> ABCProof)

Running the tests:
- Run the tests to make sure its building properly
``` 
go test 
```
- Will show debugging messages, good for debugging a proof that is not genrating or verifing
```
go test -debug1
```
- Run benchmarks (all benchmarks, WILL NOT RUN WITH -range OR -bullet)
```
go test -bench=.
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
- lower case variables are known scalars (a, b, c, x,...)
- lower case variables starting with u are randomly generated scalars (ua, ub, u1, u2, ...)
- sk and PK are always secret key and Public Key respectively
- upper case variables are always Elliptic Curve Points (ECPoints) (G, H, A, B,...)
    - A, B, CM, CMTok, etc, are usually of the form vG+uH unless otherwise stated
- Special names:
    - PK = Public Key (sk * H)
    - CM = Commitment of the form (aG + uaH)
    - CMTok = Commitment Token of the form (ua * (sk* H))
    - ZKCurve.C = Elliptic Curve being used (btcec currently)
    - G = Base Point of ZKCurve.C
    - H = Secondry Base Point whose relation to G should not be known

Coming Soon<sup>TM</sup>:
- Rangeproofs (rp.Aggragate currently broken, need to investigate)
- Bulletproofs (inner product proof currently broken, need to investigate)

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


