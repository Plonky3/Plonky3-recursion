# Introduction

[Plonky3](https://github.com/Plonky3/Plonky3) offers a comprehensive toolbox of cryptographic building blocks: hash functions, finite fields, and polynomial commitment schemes, ... to build tailored STARK proof systems. However, its adoption has been limited by the lack of native recursion, to allow arbitrary program execution replication in proof systems and to alleviate proof sizes and related on-chain verification costs. 

This project aims at addressing this limitation, by proposing a minimal, fixed recursive verifier for Plonky3, which conceptual simplicity allows for blazing fast recursion performance. A key distinction with its predecessor [plonky2](https://github.com/0xPolygonZero/plonky2), is that rather than wrapping a STARK proof in a separate plonkish SNARK, the Plonky3 recursion stack itself is built using Plonky3’s STARK primitives.

The source code is open-source, available at [Plonky3 recursion](https://github.com/Plonky3/Plonky3-recursion) and dual-licensed MIT/APACHE-2.

***NOTE***: *This project is under active development, unaudited and as such not ready for production use. We welcome all external contributors who would like to support the development effort.*
