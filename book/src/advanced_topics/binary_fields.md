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

The repository verifies native binary-field proofs inside prime-field recursion circuits.
The supported families include binary PCS and additive WHIR, with product-bus and indexed
lookup variants. `recursion/examples/binary_prover.rs` demonstrates a native binary proof
followed by a prime-field recursion layer. It does not demonstrate binary-in/binary-out recursion.

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
  - The separate `binary_decompose_coordinates` / `binary_recompose_coordinates` APIs
    use the field's raw basis through `BinaryCoordinateField`. Every coordinate is
    constrained Boolean, and requesting fewer than the full width also constrains
    the omitted coordinates to zero. These APIs preserve each field's own basis;
    they do not reinterpret a polynomial element as a tower element.
- **Bit-oriented `BinaryField128` arithmetic.** `BinaryTower128Target` represents the Wiedemann
  tower type `p3_binary_field::BinaryField128` as 128 Boolean coordinates in a prime or binary
  circuit field. It does not use the GHASH polynomial coordinates of `Ghash128`.
  At each level, `a = a0 + a1 X_k` stores the lower coefficient first and uses
  `X_k² + X_(k-1) X_k + 1 = 0`, with `X_(-1) = 1`. Bit 0 is one; bit `j` is the product of
  tower roots selected by the set bits of `j`. Every 128-bit pattern is a valid tower element.
  The raw `u128` coordinates in native code come from `TowerLevel::from_repr` / `to_repr`,
  or from little-endian bytes, **not** `from_u128` (which embeds through `GF(2)`).
  - Import/export uses eight little-endian 16-bit limbs:
    `limb[j] = Σ_(i=0..15) bit[16j+i]·2^i`. The base field must have order above 65535;
    both limb methods also reject characteristic two. Limb import constrains the range and
    base-field embedding, and raw-bit import asserts every input bit is Boolean.
  - `binary128_add`, `binary128_mul`, and `binary128_square` use the existing ALU relations
    for Boolean XOR/AND and recursive tower reduction. `assert_binary128_inverse(value,
    candidate)` constrains their product to tower one; the caller supplies the candidate,
    and zero has no satisfying inverse. There are no new tables, AIRs, or native-field hints.
  - All `ExprId`s passed to these methods must come from the same `CircuitBuilder` expression
    graph. The target's read-only bits do not carry a builder identity. A circuit using this
    arithmetic can be proved with the compact circuit prover and carried into the next
    recursion layer over the supported prime host fields. Bits-only arithmetic also runs
    over binary fields; integer-limb import/export remains prime-only.
- **Native primitive circuit proofs.** `p3_circuit_prover::direct::DirectCircuitAir` freezes
  a circuit's primitive relation and binds public values in caller order. It accepts native
  binary carrier fields without integer witness addresses or count-based lookups.
  `recursion/tests/native_binary_circuit.rs` proves and verifies circuits over both
  `BinaryField128` and `Poly64` (with `Poly192` challenges). The AIR repeats the entire
  assignment on every row, so its width and openings grow with the circuit's witness count.
  It is a non-hiding correctness baseline, rejects custom non-primitive tables, and does
  not yet provide an efficient recursive binary prover.
- **Compact native primitive tables.** `p3_circuit_prover::indexed::IndexedCircuit` stores
  one canonical witness table and proves every gate operand and output with indexed
  reads. Trusted preprocessing pins the graph's positions, constants and selectors;
  public values bind in caller order, including aliases. No field-valued integer read
  counts or creator-role tags are used. Main and preprocessing PCS dimensions are
  computed from their complete stacked layouts. The native tower and polynomial
  tests in `recursion/tests/native_indexed_circuit.rs` exercise real indexed proofs.
  This path remains non-hiding and rejects custom non-primitive tables.
- **Native Keccak circuit tables.** `p3_circuit_prover::native_binary::NativeBinaryCircuit`
  extends the compact indexed relation with the explicitly enabled
  `native_keccak_f1600` operation. `native_keccak256_bytes` accepts checked raw
  eight-coordinate bytes and returns 32 bytes in natural digest order. The
  default upstream binary Keccak AIR retains its Boolean constraints; fixed
  preprocessing pins each permutation's schedule, and indexed reads bind all
  100 input and output limbs to canonical circuit witnesses. Other custom
  operations still fail closed. `recursion/tests/native_keccak_circuit.rs`
  exercises native proof verification and rejection of changed digest values
  and bridge payloads. This is a hash foundation for binary recursion, not yet
  a complete binary-host recursive verifier.
- **Non-native binary byte-hash transcript.** `BinaryTower128Challenger` has a separate,
  fallible inherent API (`new`, `with_initial_limbs`, `observe`, `observe_slice`,
  `observe_digest`, `sample`, `sample_bits`, `check_witness`). It matches native
  `BinaryChallenger<BinaryField128, HashChallenger<u8, H, 32>>` for
  `H = Keccak256Hash` or `p3_blake3::Blake3`, selected by the fixed `ByteHash` passed to
  its constructor. It is separate from the prime-field `RecursiveChallenger` trait.
  - The initial transcript is empty or an even number of raw bytes, supplied as low-byte-first
    16-bit limbs. There is no length prefix or padding. A tower observation appends its eight
    low-first limbs (the raw little-endian Wiedemann coordinates); a digest observation appends
    all sixteen 16-bit limbs in natural byte order. External initial and digest limbs are
    constrained to base-field integers at most 65535. The host base field must be an
    odd-characteristic `PrimeField64` with order above 65535.
  - An observation clears unread output bytes and appends to the next hash input. A refill
    hashes that entire input; the resulting digest becomes both the forward input for the next
    chained hash and the current output. Sampling draws bytes from the **end** of that digest,
    retaining a short remainder across draws and refilling only when it is exhausted. Thus the
    first sample from an empty transcript starts with the last byte of `H([])`, while a refill
    after consuming its digest hashes `H(previous_digest)`; later observations are appended to
    that digest in forward order before hashing. A field sample consumes 16 bytes and interprets
    them as raw little-endian tower coordinates, with no rejection sampling.
  - `sample_bits(bits)` consumes eight bytes even when `bits == 0`, returning Boolean targets
    for the requested low bits; `bits` must be below `usize::BITS`. By contrast,
    `check_witness(0, witness)` leaves the transcript and builder untouched. For nonzero
    difficulty, `check_witness` observes the canonical witness, samples eight bytes and
    constrains the requested low bits to zero. This is witness **checking**; native grinding
    search is outside this API.
  - Every target and `ExprId` used with one challenger must belong to the same
    `CircuitBuilder` graph; expression IDs do not enforce graph ownership. Enable the matching
    Keccak-f or BLAKE3 compression operation before a refill, and register its existing
    preprocessor, AIR builder and prover together with the statement table when proving.
    Bind dynamic transcript limbs, witnesses and returned samples through
    `StatementExport::Base` in an agreed order. An error leaves the challenger's transcript
    state unchanged for retry, although expressions or constraints already added to the
    builder by a fallible gadget may remain.
- **Native binary transcript hosts.** The challenger's `_with_host` methods
  share the same transcript implementation with an explicit
  `BinaryCircuitHost`. `PrimeBinaryEncoding<BF>` preserves integer words;
  `NativeBinaryEncoding` uses checked raw coordinates and native Keccak tables.
  Word packing, digest compression, refill order, partial samples and Poly192
  coefficient serialization are tested across tower and polynomial carriers.
  Native BLAKE3 hashing is not yet available through this host. These APIs do
  not by themselves implement a complete binary-host proof verifier.
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
- **In-circuit BLAKE3.** `enable_blake3_compress` / `add_blake3_compress` expose one BLAKE3
  compression per call.
  - **Limb layout:** 56 input limbs (block, chaining value, counter, block length, flags, each
    32-bit word as a little-endian 16-bit pair) and 32 output limbs.
  - **Proving:** the `Blake3CompressAir` table runs `p3-blake3-air`'s `Blake3Air`, one
    compression per row, with each call's real counter, length and flags. It exposes the limbs
    through dedicated columns tied to `Blake3Air`'s bit columns.
  - **Registration:** register it with `Blake3CompressPreprocessor`, `Blake3CompressAirBuilder`
    and `Blake3CompressProver`.
  - **Gadgets:** built on the compression are `blake3_limbs` (messages of any even byte
    length, through the full chunk tree), `blake3_compress_digests` (`CompressionFunctionFromHasher<Blake3, 2, 32>`) and
    `blake3_field_elements` (`SerializingHasher<Blake3>`).
- **Merkle openings.** `verify_byte_hash_mmcs_opening` constrains an opening of a Keccak-256 or
  BLAKE3 `MerkleTreeMmcs` batch commitment, mirroring the native binary-arity `verify_batch`:
  - **Inputs:** the opened rows of several matrices with their heights, the little-endian index
    bits, the sibling digests (bottom-up) and a cap of any power-of-two root count.
  - **Heights:** as natively, they need not be powers of two, but each must be
    `ceil(max_height / 2^k)`. The index is constrained below the tallest height.
  - **Injection:** shorter matrices' rows are folded in at the level where their height is
    reached.
  - **Cap:** the remaining index bits select the cap root.
  - **Shorthands:** `verify_byte_hash_merkle_path`, `verify_keccak_merkle_path` and
    `verify_blake3_merkle_path` cover the single-matrix, one-root case.
- **Recursion over hash tables.** A batch proof whose circuit used Keccak-f or BLAKE3 can be
  verified by the next recursion layer.
  - **Low-level:** pass `KeccakF1600Prover` / `Blake3CompressProver` among the input table
    provers of `verify_p3_batch_proof_circuit` and `replay_batch_layer_transcript`.
  - **Built-in backends:** `PcsRecursionBackend::input_table_provers` adds these tables to the
    backend's own input provers in the input manifest's order, through
    `with_hash_table_input_provers`. The FRI and WHIR backends use it.
  - **No relaxation:** hash tables are only ever *added*. With its hash entries removed, the
    manifest must still list the backend's own tables exactly, as before.

## Not yet supported

- Full binary-in/binary-out recursion. Binary-proof verification currently runs in a prime
  host circuit; its transcript and serialization gadgets use prime-field integer limbs.
  Native binary primitive circuit proofs and compact indexed wiring are supported above.
  The existing `BatchStarkProver` tables still use prime-field count-based wiring. Native
  binary recursion also requires binary hash tables, a transcript built from the native
  coordinate codecs, and integration of those components with the complete verifier.
- MMCS trees of arity above two.
