## Missing Components for Recursive Proof Verification

### 1. **Recursive Challenger (Fiat-Shamir in-circuit)**
The most critical missing piece. Currently:
- **Problem**: Challenges (alpha, zeta, betas, query indices) are computed externally and passed as public inputs
- **Evidence**: `circuit_verifier.rs:70-76` has TODOs for observing degree bits, local targets, public values, quotient chunks, and random commitments
- **Evidence**: `circuit_fri_verifier.rs:278` states: "Indices should be sampled from a RecursiveChallenger, not passed in"
- **Impact**: The circuit doesn't verify that challenges were correctly derived from the proof transcript

### 2. **MMCS (Merkle Tree) Verification in Circuit**
Multiple locations need Merkle proof verification:
- **FRI commit phase verification** (`circuit_fri_verifier.rs:60-61`): "Add recursive MMCS batch verification for this commit phase: Verify the sibling value against the commitment at the parent index"
- **Input opening verification** (`circuit_fri_verifier.rs:297-298`): "Add recursive MMCS verification here for this batch: Verify batch_openings against _batch_commit at the computed reduced_index"
- **PCS verification** (`circuit_verifier.rs:272`): The `pcs.verify_circuit()` call doesn't actually verify the opening proofs

**Note**: The `mmcs-air` module exists with AIR constraints for MMCS verification, but it's not integrated into the recursive verifier circuit.

### 3. **Hash Function Circuit Operations**
To implement MMCS verification, you need:
- **Poseidon2/hash operations in CircuitBuilder**: Currently `symmetric-air` has AIR definitions but no circuit integration
- **Compression function for Merkle trees**: Needed to compute parent hashes from child hashes
- **Integration** with the circuit builder's operation system

### 4. **Higher-Degree Final Polynomial Support in FRI** ✅ COMPLETED
- **Status**: Fully implemented and tested in `circuit_fri_verifier.rs`
- **Implementation**: Uses Horner's method to evaluate final polynomial at reduced query points
- **Details**: 
  - Added `evaluate_polynomial()` function for efficient polynomial evaluation
  - Added `compute_final_query_point()` to compute evaluation points after all folding rounds
  - Updated `verify_fri_circuit()` to evaluate final polynomial for each query
  - Removed restriction that `log_final_poly_len` must be 0
  - Supports arbitrary degree final polynomials
- **Tests**: 
  - `test_circuit_fri_verifier_degree_1_final_poly` - Linear polynomial (2 coefficients)
  - `test_circuit_fri_verifier_degree_3_final_poly` - Cubic polynomial (4 coefficients)
  - All tests passing ✅

### 5. **Proof-of-Work (PoW) Witness Verification in Circuit**
- **Status**: PoW witness is passed in but not verified in-circuit
- **Location**: `recursive_pcs.rs:69` has a `Witness` type but no circuit constraints checking it
- **Impact**: Can't verify grinding challenges were properly computed

### 6. **Public Values and Constraints Integration**
- **Missing** (`circuit_verifier.rs:71`): Observing local targets in the challenger
- **Missing** (`circuit_verifier.rs:72`): Observing public values in the challenger
- **Impact**: Public inputs aren't part of the Fiat-Shamir transcript in-circuit

### 7. **ZK Randomization Handling**
- The code has placeholders for ZK mode (random commitments) but:
- No in-circuit verification that randomization was done correctly
- The challenger doesn't observe random commitments properly (TODO at line 76)

### 8. **Proper Domain and Degree Observations**
- **Missing** (`circuit_verifier.rs:70`): "Observe degree bits and degree_bits - is_zk"
- **Missing** (`circuit_verifier.rs:643`): "Might be best practice to include other instance data here"
- **Impact**: Instance parameters aren't bound to the proof

## Summary of Work Required

To achieve full recursive verification, you need to implement (in order of dependency):

1. **Hash operations in CircuitBuilder** (Poseidon2/compression functions)
2. **MMCS verification circuit** (using the hash operations)
3. **Recursive Challenger** (Fiat-Shamir transcript management in-circuit)
4. **Integrate MMCS verification** into FRI and PCS verifier circuits
5. **PoW verification constraints** in the circuit
6. ✅ ~~**Higher-degree final polynomial evaluation** for FRI~~ **COMPLETED**
7. **Complete Fiat-Shamir transcript** (all observations listed in TODOs)

**Current Status**: The codebase has the arithmetic verification fully working, including:
- ✅ Constraint checking and quotient verification
- ✅ FRI folding with roll-ins
- ✅ Higher-degree final polynomial evaluation
- ✅ Type-safe public input construction helpers
- ✅ Challenge ordering documentation

**Improvements Made (Hash-Independent)**:
- ✅ `public_inputs.rs` module with `PublicInputBuilder`, `FriVerifierInputs`, `StarkVerifierInputs`
- ✅ `challenge_builder.rs` module with `ChallengeBuilder` and `StarkChallenges`  
- ✅ Updated `circuit_verifier.rs` with better challenge documentation
- ✅ Test helpers refactored for reusability
- ✅ Comprehensive tests for polynomial degrees 0, 1, and 3

**Still missing** (requires Poseidon2 implementation):
- ❌ Cryptographic commitment verification (MMCS)
- ❌ Fiat-Shamir challenge generation (Recursive Challenger)


[1 tool called]

Based on the analysis, here's what **can be done** without fully implementing Poseidon2 sponge/compression in the circuit:

## ✅ Work That Doesn't Require Hash Functions

### 2. **Better Public Input Handling** 
**Improvements possible**:
- Create helper functions to properly construct public inputs
- Add validation functions that check public input shapes
- Document the exact ordering of public inputs
- Add test utilities for different proof shapes

### 3. **Code Organization & Refactoring**
**Actionable items**:
- Move `ProofTargets`, `CommitmentTargets`, `OpenedValuesTargets` to their respective crates (noted in TODO at `recursive_traits.rs:36`)
- Clean up the `lens` pattern - could be more ergonomic
- Better error messages in `VerificationError` and `GenerationError`
- Add more comprehensive documentation

### 4. **Testing & Validation**
**What can be tested now**:
- More AIR varieties (different constraint degrees, public values, etc.)
- Edge cases: zero-degree polynomials, single-column traces
- Proof shape mismatches
- Different FRI parameters (blowup factors, number of queries)
- ZK mode (randomization)
- Multi-matrix batching scenarios

### 5. **Utility Functions & Helpers**
**Pure arithmetic helpers**:
- Domain manipulation utilities in `RecursivePcs`
- Selector computation helpers
- Lagrange interpolation functions
- Quotient degree calculations

### 6. **Non-Hash-Dependent Circuit Operations**
**Already in circuit builder**:
- Field extension operations
- Polynomial evaluations
- Quotient computations
- All the FRI folding arithmetic (already working!)

### 7. **Documentation & Examples**
**Can be written now**:
- Architecture documentation explaining the verification flow
- Examples of using the current arithmetic-only verifier
- API documentation for `Recursive` trait
- Tutorial on creating custom `RecursivePcs` implementations

## ❌ What Definitely Requires Hash Functions

1. **Recursive Challenger** - fundamentally needs sponge construction
2. **MMCS/Merkle verification** - needs compression function
3. **PoW witness verification** - likely needs grinding check with hash
4. **Complete end-to-end security** - needs cryptographic commitments

## 🎯 Recommended Priority (Hash-Independent Work)

1. **Higher-degree final polynomial** - High impact, pure arithmetic
2. **Better testing** - Validate what works, find edge cases
3. **Public input helpers** - Make the API more ergonomic
4. **Documentation** - Help future developers understand the system
5. **Code cleanup** - Move structures to appropriate crates, improve error messages

The key insight is: **The arithmetic verification core is complete and working**. Without hash functions, you can't achieve cryptographic security, but you can:
- Improve robustness and flexibility
- Better test coverage
- Cleaner APIs
- Better documentation
- Preparation for when hash functions arrive
