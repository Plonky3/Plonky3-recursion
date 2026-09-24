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

- **In-circuit Keccak.** Prime-field circuits can call Keccak-f\[1600\] as a non-primitive
  operation (`CircuitBuilder::enable_keccak_f1600` / `add_keccak_f1600`).
  - **State layout:** the state is 100 little-endian 16-bit limbs (limb `4·i + k` is limb `k` of
    lane `i = x + 5·y`), matching `p3-keccak-air`.
  - **Proving:** the `KeccakF1600Air` table runs `KeccakAir` over 24 rows per call and ties the
    input and output limbs to the witness table through `WitnessChecks` lookups. `KeccakAir`'s
    bit decompositions keep every limb below `2^16`.
  - **Registration:** register it with `KeccakF1600Preprocessor`, `KeccakF1600AirBuilder` and
    `KeccakF1600Prover`.
  - **Merkle compression:** `keccak256_compress` builds on it. It computes Keccak-256 of two
    32-byte digests in one call, matching
    `CompressionFunctionFromHasher<Keccak256Hash, 2, 32>`, the node compression of a Keccak
    Merkle tree.
  - **Keccak-256 sponge:** `keccak256_limbs` hashes messages of any even byte length. The first
    block fills the zero state directly; later blocks are XORed in with a bitwise gadget.
  - **Leaf hash:** `keccak256_field_elements` matches `SerializingHasher<Keccak256Hash>`, the
    leaf hash of a Keccak Merkle tree. Elements are serialized exactly as Plonky3 does it
    (Montgomery fields such as BabyBear hash `x·2^32 mod p`). Each serialized value is decomposed
    into canonical bits, so `y + p` cannot stand in for `y`.

## Not yet supported

- Proving circuits over a binary field. The circuit prover's tables, lookups and Poseidon
  permutations assume a two-adic prime field, as do FRI and the prime-field WHIR.
- Recursively verifying binary-PCS or multi-stark proofs. That needs `GF(2^128)` arithmetic
  inside a prime-field circuit, plus in-circuit Keccak-256 or BLAKE3 for the transcript and
  Merkle paths.
- In-circuit BLAKE3.
- A Keccak Merkle path or MMCS verification gadget built from the leaf hash and compression
  above.
- Keccak-f in the recursion backends' table lists, so recursively verifying a proof that
  contains a Keccak-f table is not wired up yet.
