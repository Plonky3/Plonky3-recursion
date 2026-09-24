# Binary Fields and Binary Hashes

Plonky3 0.7 and 0.8 added a native characteristic-2 proving stack alongside the two-adic
prime fields this repository is built on:

- `p3-binary-field`: the tower `GF(2) ⊂ GF(4) ⊂ … ⊂ GF(2^128)` (`Gf2`, `BinaryField8` …
  `BinaryField128`), `GF(2^128)` in the GHASH polynomial basis (`Ghash128`), and
  `BinaryChallenger`, a Fiat-Shamir transcript over a byte hash.
- `p3-binary-dft`, `p3-binary-pcs`, WHIR over binary additive domains, and `p3-multi-stark`:
  multilinear commitments and a SuperSpartan-style prover over those fields.
- Characteristic-2 AIRs for the bit-oriented hashes: `KeccakBinaryAir` (`p3-keccak-air`) and
  `Blake3BinaryAir` (`p3-blake3-air`).

## What this repository supports today

This is groundwork only. Nothing here proves or recursively verifies a binary-field proof.

- **Circuits over binary fields.** The primitive circuit layer (constants, public and private
  inputs, ALU ops, connections, tags) needs only field arithmetic, and runs unchanged over every
  tower level and `Ghash128` (`circuit/tests/binary_fields.rs`). Two things behave differently
  from a prime field:
  - `x - y = x + y` and `2 = 0`. Integer constructors such as `F::from_u64` go through `GF(2)`,
    so they keep only the parity of their argument.
  - Gadgets that read field elements as integers are rejected, not silently wrong.
    `reconstruct_index_from_bits` returns `CircuitBuilderError::CharacteristicTwoUnsupported`
    for a characteristic-2 base field. The decomposition and recomposition gadgets require
    `BF: PrimeField64` with `F: ExtensionField<BF>`, and the binary tower only extends its
    byte-aligned levels, so they cannot be instantiated over it at all.
- **Binary hash configurations.** `p3_test_utils::binary_field_params` provides the
  configuration `p3-binary-pcs` tests with, once per hash (`keccak` and `blake3` submodules
  with identical item names):
  - Merkle commitments over any tower level that serialize rows to bytes, hash with
    Keccak-256 or BLAKE3, and compress node pairs with the same hash;
  - `BinaryChallenger` transcripts over the same byte hash.
- **Binary hash AIRs.** `test-utils/tests/binary_hashes.rs` checks that the Keccak-f and BLAKE3
  AIRs over `GF(2^128)` accept their generated traces and reject a non-bit cell or a flipped
  bit, and that the byte-hash commitments round-trip and reject tampering.

## Not yet supported

- Proving circuits over a binary field. The circuit prover's tables, lookups and Poseidon
  permutations assume a two-adic prime field, as do FRI and the prime-field WHIR.
- Recursively verifying binary-PCS or multi-stark proofs. That needs `GF(2^128)` arithmetic
  inside a prime-field circuit, plus in-circuit Keccak-256 or BLAKE3 for the transcript and
  Merkle paths.
- In-circuit Keccak-256 or BLAKE3 as non-primitive ops. Today only Poseidon1 and Poseidon2
  permutations are native to circuits.
