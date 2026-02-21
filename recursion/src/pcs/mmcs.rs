use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;

use p3_circuit::op::{NonPrimitiveOpPrivateData, Poseidon2Config};
use p3_circuit::ops::poseidon2_perm::Poseidon2PermOps;
use p3_circuit::ops::{Poseidon2PermCall, Poseidon2PermPrivateData};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitRunner, NonPrimitiveOpId};
use p3_commit::BatchOpening;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField64, TwoAdicField};
use p3_fri::FriProof;
use p3_matrix::Dimensions;

use crate::Target;

/// Hash base field coefficients using overwrite-mode sponge (matching native PaddingFreeSponge).
///
/// Native `PaddingFreeSponge` uses "overwrite mode": when absorbing a partial chunk,
/// only the absorbed positions are overwritten; the remaining rate positions keep their
/// values from the previous permutation output.
///
/// This function implements the same behavior in the circuit by:
/// 1. Processing base coefficients in chunks of `rate` (8 for BabyBear)
/// 2. For partial chunks, mixing absorbed values with previous output for remaining positions
/// 3. Using proper chaining for the capacity portion
///
/// # Parameters
/// - `circuit`: Circuit builder
/// - `permutation_config`: Poseidon2 configuration
/// - `base_coeffs`: Base field coefficient targets (in lifted representation)
/// - `reset`: If true, starts a new hash chain (initial state = zeros)
fn add_hash_base_coeffs_overwrite<F, EF>(
    circuit: &mut CircuitBuilder<EF>,
    permutation_config: &Poseidon2Config,
    base_coeffs: &[Target],
    reset: bool,
) -> Result<Vec<Target>, CircuitBuilderError>
where
    F: Field + PrimeField64,
    EF: ExtensionField<F>,
{
    if base_coeffs.is_empty() {
        // Return zeros for empty input (shouldn't happen in practice)
        let zero = circuit.add_const(EF::ZERO);
        return Ok(vec![zero, zero]);
    }

    let ext_degree = <EF as BasedVectorSpace<F>>::DIMENSION;
    let rate = permutation_config.rate(); // Base field rate (8 for BabyBear)
    let rate_ext = permutation_config.rate_ext(); // Extension rate (2 for D=4)

    // Process in chunks of `rate` base field values
    let num_chunks = base_coeffs.len().div_ceil(rate);
    // Only store rate outputs (0-1) for overwrite mode chaining
    let mut last_rate_outputs: Option<[Target; 2]> = None;
    let mut final_outputs = [None, None, None, None];

    for (chunk_idx, chunk) in base_coeffs.chunks(rate).enumerate() {
        let is_first = chunk_idx == 0;
        let is_last = chunk_idx == num_chunks - 1;

        // Build inputs for this permutation
        // Rate portion (inputs[0..rate_ext]): absorbed values with overwrite semantics
        // Capacity portion (inputs[rate_ext..4]): None for chaining
        let mut inputs: [Option<Target>; 4] = [None; 4];

        for ext_idx in 0..rate_ext {
            let base_start = ext_idx * ext_degree;
            let num_values_in_ext = min(ext_degree, chunk.len().saturating_sub(base_start));

            if num_values_in_ext == 0 {
                // No values for this extension position - use None for chaining
                // This keeps the previous output (overwrite mode)
                inputs[ext_idx] = None;
            } else if num_values_in_ext == ext_degree {
                // Full extension element - just recompose our values
                let ext_coeffs: Vec<_> = (0..ext_degree).map(|i| chunk[base_start + i]).collect();
                inputs[ext_idx] = Some(circuit.recompose_base_coeffs_to_ext::<F>(&ext_coeffs)?);
            } else {
                // Partial extension element - mix with previous output (overwrite mode)
                // This is the key fix: unused positions keep previous permutation output
                let prev_coeffs: Option<Vec<Target>> = if !is_first {
                    if let Some(ref prev_rate) = last_rate_outputs {
                        Some(circuit.decompose_ext_to_base_coeffs::<F>(prev_rate[ext_idx])?)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mut ext_coeffs = Vec::with_capacity(ext_degree);
                for coeff_idx in 0..ext_degree {
                    if coeff_idx < num_values_in_ext {
                        // Use our absorbed value
                        ext_coeffs.push(chunk[base_start + coeff_idx]);
                    } else if let Some(ref prev) = prev_coeffs {
                        // Overwrite mode: keep previous output for this position
                        ext_coeffs.push(prev[coeff_idx]);
                    } else {
                        // First permutation with new_start, use zero
                        ext_coeffs.push(circuit.add_const(EF::ZERO));
                    }
                }

                inputs[ext_idx] = Some(circuit.recompose_base_coeffs_to_ext::<F>(&ext_coeffs)?);
            }
        }

        // Capacity positions (rate_ext..4) are None for chaining from previous permutation

        // Add permutation
        // Always get rate outputs (0-1) for potential chaining; capacity outputs not needed
        let (_, maybe_outputs) = circuit.add_poseidon2_perm(Poseidon2PermCall {
            config: *permutation_config,
            new_start: if is_first { reset } else { false },
            merkle_path: false,
            mmcs_bit: None,
            inputs,
            out_ctl: [true, true],     // Always expose rate outputs
            return_all_outputs: false, // Don't need capacity outputs
            mmcs_index_sum: None,
        })?;

        // Store rate outputs for next iteration (for overwrite mode chaining)
        if !is_last {
            // Only need rate outputs (0-1) for overwrite mode - capacity is handled by chaining
            last_rate_outputs = Some([
                maybe_outputs[0].ok_or(CircuitBuilderError::MissingOutput)?,
                maybe_outputs[1].ok_or(CircuitBuilderError::MissingOutput)?,
            ]);
        }

        final_outputs = maybe_outputs;
    }

    // Return rate outputs (0-1) as the hash digest
    [final_outputs[0], final_outputs[1]]
        .into_iter()
        .map(|o| o.ok_or(CircuitBuilderError::MissingOutput))
        .collect()
}

/// Hash extension field elements directly (no recompose). Use when values are already
/// extension elements (e.g. FRI commit-phase evals). Absorbs in chunks of `rate_ext`.
fn add_hash_extension_elements<F, EF>(
    circuit: &mut CircuitBuilder<EF>,
    permutation_config: &Poseidon2Config,
    ext_elements: &[Target],
    reset: bool,
) -> Result<Vec<Target>, CircuitBuilderError>
where
    F: Field + PrimeField64,
    EF: ExtensionField<F>,
{
    let rate_ext = permutation_config.rate_ext();
    if ext_elements.is_empty() {
        let zero = circuit.add_const(EF::ZERO);
        return Ok(vec![zero, zero]);
    }

    let zero = circuit.add_const(EF::ZERO);
    let mut last_rate_outputs: Option<[Target; 2]> = None;
    let mut final_outputs = [None, None, None, None];

    for (i, chunk) in ext_elements.chunks(rate_ext).enumerate() {
        let is_first = i == 0;
        let mut inputs: [Option<Target>; 4] = [None; 4];
        for (j, &t) in chunk.iter().enumerate() {
            inputs[j] = Some(t);
        }
        for j in chunk.len()..rate_ext {
            inputs[j] = Some(if is_first {
                zero
            } else {
                last_rate_outputs.map(|o| o[j]).unwrap_or(zero)
            });
        }

        let (_, maybe_outputs) = circuit.add_poseidon2_perm(Poseidon2PermCall {
            config: *permutation_config,
            new_start: is_first && reset,
            merkle_path: false,
            mmcs_bit: None,
            inputs,
            out_ctl: [true, true],
            return_all_outputs: false,
            mmcs_index_sum: None,
        })?;

        if chunk.len() == rate_ext {
            last_rate_outputs = Some([
                maybe_outputs[0].ok_or(CircuitBuilderError::MissingOutput)?,
                maybe_outputs[1].ok_or(CircuitBuilderError::MissingOutput)?,
            ]);
        }
        final_outputs = maybe_outputs;
    }

    [final_outputs[0], final_outputs[1]]
        .into_iter()
        .map(|o| o.ok_or(CircuitBuilderError::MissingOutput))
        .collect()
}

/// Recursive version of `MerkleTreeMmcs::verify_batch`. Adds a circuit that verifies an opened
/// batch of rows with respect to a given commitment (Merkle cap).
///
/// - `circuit`: The circuit builder to which we add the verify_batch circuit
/// - `commitment_cap`: The Merkle cap entries. Each inner slice has `rate_ext` packed extension
///   targets representing one cap entry. A single-element cap (`cap_height = 0`) corresponds to
///   the traditional single root.
/// - `dimensions`: A vector of the dimensions of the matrices committed to.
/// - `index_bits`: The little-endian binary decomposition of the index of a leaf in the tree.
///   Length must equal `log2_ceil(max_height)`.
/// - `opened_values`: A vector of matrix rows (packed extension field targets).
///
/// Returns the list of permutation operations requiring private data, otherwise returns an error.
///
/// # Merkle Cap Support
///
/// The Merkle cap of height `h` is the `h`-th layer from the root. A cap of height 0 is the root
/// itself. When `cap_height > 0`, the opening proof is `cap_height` elements shorter and the
/// remaining upper index bits select the correct cap entry to verify against.
///
/// # Parameters
/// - `circuit`: The circuit builder
/// - `permutation_config`: Poseidon2 configuration
/// - `commitment_cap`: Merkle cap entries, each with `rate_ext` packed extension targets
/// - `dimensions`: Matrix dimensions (height used for tree structure)
/// - `index_bits`: All Merkle path direction bits (length = `log_max_height`)
/// - `opened_base_coeffs`: Base field coefficients per matrix (already decomposed)
pub fn verify_batch_circuit<F, EF>(
    circuit: &mut CircuitBuilder<EF>,
    permutation_config: Poseidon2Config,
    commitment_cap: &[Vec<Target>],
    dimensions: &[Dimensions],
    index_bits: &[Target],
    opened_base_coeffs: &[Vec<Target>],
) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError>
where
    F: Field + TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
{
    use p3_circuit::ops::mmcs::add_mmcs_verify;
    use p3_util::log2_strict_usize;

    if dimensions.len() != opened_base_coeffs.len() {
        return Err(CircuitBuilderError::WrongBatchSize {
            expected: dimensions.len(),
            got: opened_base_coeffs.len(),
        });
    }

    assert!(
        !commitment_cap.is_empty(),
        "commitment cap must have at least one entry"
    );

    use core::cmp::Reverse;

    use itertools::Itertools;

    // Derive cap_height from commitment size: cap has 2^cap_height entries
    let cap_height = if commitment_cap.len() == 1 {
        0
    } else {
        log2_strict_usize(commitment_cap.len())
    };

    let max_height_log = index_bits.len();
    let path_depth = max_height_log - cap_height;

    // Split index_bits into path bits (for Merkle traversal) and cap index bits
    let path_bits = &index_bits[..path_depth];
    let cap_index_bits = &index_bits[path_depth..];

    // Select the correct cap entry using a multiplexer
    let selected_root = select_cap_entry(circuit, commitment_cap, cap_index_bits);

    // Group matrices by height level (matching format_openings logic)
    // Native MMCS combines all matrices at the same height THEN hashes them together
    let mut heights_tallest_first = dimensions
        .iter()
        .enumerate()
        .sorted_by_key(|(_, dims)| Reverse(dims.height))
        .peekable();

    // Build digests for path_depth levels (the Merkle path below the cap) plus one
    // extra level for matrices whose heights match the cap level. In the native MMCS,
    // these cap-level rows are injected after the last sibling compression.
    let digest_levels = path_depth + 1;
    let mut formatted_digests = vec![vec![]; digest_levels];
    for (i, digest) in formatted_digests.iter_mut().enumerate() {
        let curr_height = 1 << (max_height_log - i);

        // Collect all base coefficients from matrices at this height level
        let all_base_coeffs: Vec<Target> = heights_tallest_first
            .peeking_take_while(|(_, dims)| dims.height.next_power_of_two() == curr_height)
            .flat_map(|(mat_idx, _)| opened_base_coeffs[mat_idx].clone())
            .collect();

        if all_base_coeffs.is_empty() {
            continue;
        }

        // Hash using overwrite-mode sponge (matching native PaddingFreeSponge)
        *digest = add_hash_base_coeffs_overwrite::<F, EF>(
            circuit,
            &permutation_config,
            &all_base_coeffs,
            true,
        )?;
    }

    let op_vals_digests = formatted_digests;

    add_mmcs_verify(
        circuit,
        permutation_config,
        &op_vals_digests,
        path_bits,
        &selected_root,
    )
}

/// Like `verify_batch_circuit` but opened values are already extension elements (no decompose).
/// Use for FRI commit-phase where evals are extension and only the challenger needs base form.
pub fn verify_batch_circuit_from_extension_opened<F, EF>(
    circuit: &mut CircuitBuilder<EF>,
    permutation_config: Poseidon2Config,
    commitment_cap: &[Vec<Target>],
    dimensions: &[Dimensions],
    index_bits: &[Target],
    opened_extension_values: &[Vec<Target>],
) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError>
where
    F: Field + TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
{
    use core::cmp::Reverse;

    use itertools::Itertools;
    use p3_circuit::ops::mmcs::add_mmcs_verify;
    use p3_util::log2_strict_usize;

    if dimensions.len() != opened_extension_values.len() {
        return Err(CircuitBuilderError::WrongBatchSize {
            expected: dimensions.len(),
            got: opened_extension_values.len(),
        });
    }

    assert!(
        !commitment_cap.is_empty(),
        "commitment cap must have at least one entry"
    );

    let cap_height = if commitment_cap.len() == 1 {
        0
    } else {
        log2_strict_usize(commitment_cap.len())
    };

    let max_height_log = index_bits.len();
    let path_depth = max_height_log - cap_height;
    let path_bits = &index_bits[..path_depth];
    let cap_index_bits = &index_bits[path_depth..];

    let selected_root = select_cap_entry(circuit, commitment_cap, cap_index_bits);

    let mut heights_tallest_first = dimensions
        .iter()
        .enumerate()
        .sorted_by_key(|(_, dims)| Reverse(dims.height))
        .peekable();

    let digest_levels = path_depth + 1;
    let mut formatted_digests = vec![vec![]; digest_levels];
    for (i, digest) in formatted_digests.iter_mut().enumerate() {
        let curr_height = 1 << (max_height_log - i);

        let all_ext: Vec<Target> = heights_tallest_first
            .peeking_take_while(|(_, dims)| dims.height.next_power_of_two() == curr_height)
            .flat_map(|(mat_idx, _)| opened_extension_values[mat_idx].clone())
            .collect();

        if all_ext.is_empty() {
            continue;
        }

        *digest =
            add_hash_extension_elements::<F, EF>(circuit, &permutation_config, &all_ext, true)?;
    }

    add_mmcs_verify(
        circuit,
        permutation_config,
        &formatted_digests,
        path_bits,
        &selected_root,
    )
}

/// Select one cap entry from a Merkle cap using a binary tree multiplexer.
///
/// For `cap_height = 0` (single entry), returns the entry directly.
/// For `cap_height > 0`, progressively halves the candidates using one index bit
/// at each level. Each selection step computes `left + bit * (right - left)` per
/// component, requiring only one multiplication per component per level.
///
/// Total cost: `rate_ext * (2^cap_height - 1)` multiplications, compared to
/// `(cap_height + rate_ext) * 2^cap_height` for the one-hot + dot-product approach.
fn select_cap_entry<EF: Field>(
    circuit: &mut CircuitBuilder<EF>,
    cap: &[Vec<Target>],
    index_bits: &[Target],
) -> Vec<Target> {
    if cap.len() == 1 {
        return cap[0].clone();
    }

    debug_assert_eq!(cap.len(), 1 << index_bits.len());

    let rate_ext = cap[0].len();

    // Binary tree selection: each bit halves the number of candidates.
    // bit[0] (LSB) selects between adjacent pairs, bit[1] between groups of 4, etc.
    let mut current: Vec<Vec<Target>> = cap.to_vec();

    for &bit in index_bits {
        let half = current.len() / 2;
        let mut next = Vec::with_capacity(half);
        for i in 0..half {
            let left = &current[2 * i];
            let right = &current[2 * i + 1];
            let mut selected = Vec::with_capacity(rate_ext);
            for j in 0..rate_ext {
                // left[j] + bit * (right[j] - left[j])
                let diff = circuit.sub(right[j], left[j]);
                let term = circuit.mul(bit, diff);
                let val = circuit.add(left[j], term);
                selected.push(val);
            }
            next.push(selected);
        }
        current = next;
    }

    debug_assert_eq!(current.len(), 1);
    current.into_iter().next().unwrap()
}

/// Convert a base field Merkle proof to extension field sibling values.
///
/// Each sibling hash in the proof has `DIGEST_ELEMS` base field elements.
/// These are packed into extension field elements (EF::DIMENSION base elements per extension element).
/// The result is `rate_ext` extension field elements per sibling.
fn convert_merkle_proof_to_siblings<F, EF, const DIGEST_ELEMS: usize>(
    opening_proof: &[[F; DIGEST_ELEMS]],
) -> Vec<[EF; 2]>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
{
    opening_proof
        .iter()
        .map(|digest| {
            // Pack base field elements into extension field elements
            let ext_elements: Vec<EF> = digest
                .chunks(EF::DIMENSION)
                .map(|chunk| {
                    EF::from_basis_coefficients_slice(chunk)
                        .expect("chunk size should match extension degree")
                })
                .collect();
            // For Poseidon2 MMCS, we expect exactly 2 extension elements per sibling
            debug_assert_eq!(
                ext_elements.len(),
                2,
                "Expected 2 extension elements per sibling, got {}",
                ext_elements.len()
            );
            [ext_elements[0], ext_elements[1]]
        })
        .collect()
}

/// Set private data for FRI MMCS verification operations.
///
/// This function extracts Merkle sibling values from a FRI proof and sets them
/// as private data for the circuit operations returned by `verify_fri_circuit`.
///
/// # Parameters
/// - `runner`: The circuit runner to set private data on
/// - `op_ids`: Operation IDs returned by `verify_fri_circuit`
/// - `fri_proof`: The FRI proof containing Merkle proofs
///
/// # Returns
/// `Ok(())` if all private data was set successfully, or an error if there was a mismatch.
///
/// # Operation ID Order
/// The `op_ids` are expected in the following order (matching `verify_fri_circuit`):
/// 1. For each query:
///    - Input batch MMCS ops (one per batch, each with `path_depth` siblings)
///    - Commit-phase MMCS ops (one per phase, each with `phase_depth` siblings)
pub fn set_fri_mmcs_private_data<F, EF, FriMmcs, InputMmcs, H, C, const DIGEST_ELEMS: usize>(
    runner: &mut CircuitRunner<EF>,
    op_ids: &[NonPrimitiveOpId],
    fri_proof: &FriProof<EF, FriMmcs, F, Vec<BatchOpening<F, InputMmcs>>>,
) -> Result<(), &'static str>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    FriMmcs: p3_commit::Mmcs<EF, Proof = Vec<[F; DIGEST_ELEMS]>>,
    InputMmcs: p3_commit::Mmcs<F, Proof = Vec<[F; DIGEST_ELEMS]>>,
    H: p3_symmetric::CryptographicHasher<F, [F; DIGEST_ELEMS]>
        + p3_symmetric::CryptographicHasher<F::Packing, [F::Packing; DIGEST_ELEMS]>
        + Sync,
    C: p3_symmetric::PseudoCompressionFunction<[F; DIGEST_ELEMS], 2>
        + p3_symmetric::PseudoCompressionFunction<[F::Packing; DIGEST_ELEMS], 2>
        + Sync,
{
    let mut op_idx = 0;

    for query_proof in &fri_proof.query_proofs {
        // Input batch MMCS proofs
        for batch_opening in &query_proof.input_proof {
            let siblings = convert_merkle_proof_to_siblings::<F, EF, DIGEST_ELEMS>(
                &batch_opening.opening_proof,
            );
            for sibling in siblings {
                if op_idx >= op_ids.len() {
                    return Err("More siblings in proof than op_ids provided");
                }
                runner
                    .set_private_data(
                        op_ids[op_idx],
                        NonPrimitiveOpPrivateData::Poseidon2Perm(Poseidon2PermPrivateData {
                            sibling,
                        }),
                    )
                    .map_err(|_| "Failed to set private data for input batch MMCS")?;
                op_idx += 1;
            }
        }

        // Commit-phase MMCS proofs
        for phase_opening in &query_proof.commit_phase_openings {
            let siblings = convert_merkle_proof_to_siblings::<F, EF, DIGEST_ELEMS>(
                &phase_opening.opening_proof,
            );
            for sibling in siblings {
                if op_idx >= op_ids.len() {
                    return Err("More siblings in proof than op_ids provided");
                }
                runner
                    .set_private_data(
                        op_ids[op_idx],
                        NonPrimitiveOpPrivateData::Poseidon2Perm(Poseidon2PermPrivateData {
                            sibling,
                        }),
                    )
                    .map_err(|_| "Failed to set private data for commit-phase MMCS")?;
                op_idx += 1;
            }
        }
    }

    if op_idx != op_ids.len() {
        return Err("Fewer siblings in proof than op_ids provided");
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cmp::Reverse;

    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_circuit::op::Poseidon2Config;
    use p3_circuit::ops::mmcs::{add_mmcs_verify, format_openings};
    use p3_circuit::ops::{Poseidon2PermPrivateData, generate_poseidon2_trace};
    use p3_circuit::{CircuitBuilder, CircuitError, NonPrimitiveOpPrivateData};
    use p3_commit::Mmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing};
    use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
    use p3_matrix::{Dimensions, Matrix};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_poseidon2_circuit_air::BabyBearD4Width16;
    use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, TruncatedPermutation};
    use p3_util::log2_ceil_usize;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;
    use tracing_forest::ForestLayer;
    use tracing_forest::util::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Registry};

    use crate::pcs::verify_batch_circuit;

    type F = BabyBear;
    type CF = BinomialExtensionField<F, 4>;

    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type MyMmcs =
        MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;

    fn base_digest_to_ext(digest: &[F], permutation_config: Poseidon2Config) -> Vec<CF> {
        assert_eq!(
            digest.len(),
            permutation_config.rate(),
            "unexpected base digest length"
        );
        digest
            .chunks(<CF as BasedVectorSpace<F>>::DIMENSION)
            .map(|chunk| {
                let mut coeffs = [F::ZERO; 4];
                for (i, &val) in chunk.iter().enumerate() {
                    coeffs[i] = val;
                }
                CF::from_basis_coefficients_slice(&coeffs).expect("packed base digest")
            })
            .collect()
    }

    fn test_all_openings(mats: Vec<RowMajorMatrix<F>>) {
        test_all_openings_with_cap_height(mats, 0);
    }

    fn test_all_openings_with_cap_height(mats: Vec<RowMajorMatrix<F>>, cap_height: usize) {
        let perm = default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let mmcs = MyMmcs::new(hash, compress, cap_height);

        let dimensions = mats.iter().map(DenseMatrix::dimensions).collect_vec();

        let mut heights_tallest_first = dimensions
            .iter()
            .enumerate()
            .sorted_by_key(|(_, dims)| Reverse(dims.height))
            .peekable();

        let max_height = heights_tallest_first.peek().unwrap().1.height;

        let (commit, prover_data) = mmcs.commit(mats);

        let log_max_height = log2_ceil_usize(max_height);
        for index in 0..max_height {
            let mut builder = CircuitBuilder::<CF>::new();
            let permutation_config = Poseidon2Config::BabyBearD4Width16;
            builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
                generate_poseidon2_trace::<CF, BabyBearD4Width16>,
                perm.clone(),
            );

            let batch_opening = mmcs.open_batch(index, &prover_data);

            let directions = (0..log_max_height)
                .map(|k| index >> k & 1 == 1)
                .collect_vec();

            let openings: Vec<Vec<_>> = batch_opening
                .opened_values
                .iter()
                .map(|opening| {
                    (0..opening.len())
                        .map(|_| builder.add_public_input())
                        .collect_vec()
                })
                .collect_vec();

            let directions_expr = builder.alloc_public_inputs(log_max_height, "directions");

            // Allocate cap entries: each entry has rate_ext extension targets
            let cap_len = commit.num_roots();
            let rate_ext = permutation_config.rate_ext();
            let cap_exprs: Vec<Vec<_>> = (0..cap_len)
                .map(|_| builder.alloc_public_inputs(rate_ext, "cap entry").to_vec())
                .collect();

            let permutation_mmcs_ops = verify_batch_circuit::<F, CF>(
                &mut builder,
                permutation_config,
                &cap_exprs,
                &dimensions,
                &directions_expr,
                &openings,
            )
            .unwrap();

            let circuit = builder.build().unwrap();
            let mut runner = circuit.runner();

            let directions_expr_vals = directions
                .iter()
                .map(|&bit| CF::from_bool(bit))
                .collect_vec();

            let mut public_inputs: Vec<CF> = batch_opening
                .opened_values
                .iter()
                .flat_map(|values| values.iter().map(|&v| CF::from(v)))
                .collect();
            public_inputs.extend(directions_expr_vals.iter());
            // Pack each cap entry to extension field and add as public inputs
            for entry in commit.roots() {
                let commit_ext = base_digest_to_ext(entry, permutation_config);
                debug_assert_eq!(rate_ext, commit_ext.len());
                public_inputs.extend(commit_ext);
            }

            runner.set_public_inputs(&public_inputs).unwrap();

            let siblings = batch_opening
                .opening_proof
                .iter()
                .map(|digest| {
                    digest
                        .chunks(4)
                        .map(CF::from_basis_coefficients_slice)
                        .collect::<Option<Vec<_>>>()
                        .unwrap()
                })
                .collect_vec();

            for (&op_id, sibling) in permutation_mmcs_ops.iter().zip(siblings) {
                runner
                    .set_private_data(
                        op_id,
                        NonPrimitiveOpPrivateData::Poseidon2Perm(Poseidon2PermPrivateData {
                            sibling: sibling.try_into().unwrap(),
                        }),
                    )
                    .unwrap();
            }

            let _ = runner.run().unwrap();
        }
    }

    fn init_logger() {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        // Use try_init to avoid panic if logger is already initialized
        let _ = Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .try_init();
    }

    #[test]
    fn commit_single_1x8() {
        init_logger();
        // v = [0, 1, 2, 3, 4, 5, 6, 7]
        let v = vec![
            F::from_u32(0),
            F::from_u32(1),
            F::from_u32(2),
            F::from_u32(3),
            F::from_u32(4),
            F::from_u32(5),
            F::from_u32(6),
            F::from_u32(7),
        ];

        test_all_openings(vec![RowMajorMatrix::new_col(v)]);
    }

    #[test]
    fn commit_single_2x2() {
        let mat = RowMajorMatrix::new(vec![F::ZERO, F::ONE, F::TWO, F::ONE], 2);
        test_all_openings(vec![mat]);
    }

    #[test]
    fn commit_single_2x3() {
        // mat = [
        //   0 1
        //   2 1
        //   2 2
        // ]
        let mat = RowMajorMatrix::new(vec![F::ZERO, F::ONE, F::TWO, F::ONE, F::TWO, F::TWO], 2);
        test_all_openings(vec![mat]);
    }

    #[test]
    fn commit_mixed() {
        // mat_1 = [
        //   0 1
        //   2 3
        //   4 5
        //   6 7
        //   8 9
        // ]
        let mat_1 = RowMajorMatrix::new(
            vec![
                F::from_usize(0),
                F::from_usize(1),
                F::from_usize(2),
                F::from_usize(3),
                F::from_usize(4),
                F::from_usize(5),
                F::from_usize(6),
                F::from_usize(7),
                F::from_usize(8),
                F::from_usize(9),
            ],
            2,
        );
        // mat_2 = [
        //   10 11 12
        //   13 14 15
        //   16 17 18
        // ]
        let mat_2 = RowMajorMatrix::new(
            vec![
                F::from_usize(10),
                F::from_usize(11),
                F::from_usize(12),
                F::from_usize(13),
                F::from_usize(14),
                F::from_usize(15),
                F::from_usize(16),
                F::from_usize(17),
                F::from_usize(18),
            ],
            3,
        );
        test_all_openings(vec![mat_1, mat_2]);
    }

    #[test]
    fn commit_either_order() {
        let mut rng = SmallRng::seed_from_u64(1);
        let input_1 = RowMajorMatrix::<F>::rand(&mut rng, 5, 8);
        let input_2 = RowMajorMatrix::<F>::rand(&mut rng, 3, 16);

        test_all_openings(vec![input_1.clone(), input_2.clone()]);
        test_all_openings(vec![input_2, input_1]);
    }

    /// Test with batch STARK's exact height configuration: [512, 8, 4, 128, 4]
    /// This replicates the multi-instance batch STARK trace commitment structure.
    #[test]
    fn commit_batch_stark_heights() {
        init_logger();
        let mut rng = SmallRng::seed_from_u64(42);

        // Heights matching batch STARK degree_bits [7, 1, 0, 5, 0] with log_blowup=2
        // heights = [2^(7+2), 2^(1+2), 2^(0+2), 2^(5+2), 2^(0+2)] = [512, 8, 4, 128, 4]
        // Widths matching trace batch: [1, 1, 1, 12, 3]
        let mat_0 = RowMajorMatrix::<F>::rand(&mut rng, 512, 1);
        let mat_1 = RowMajorMatrix::<F>::rand(&mut rng, 8, 1);
        let mat_2 = RowMajorMatrix::<F>::rand(&mut rng, 4, 1);
        let mat_3 = RowMajorMatrix::<F>::rand(&mut rng, 128, 12);
        let mat_4 = RowMajorMatrix::<F>::rand(&mut rng, 4, 3);

        test_all_openings(vec![mat_0, mat_1, mat_2, mat_3, mat_4]);
    }

    /// Test with multiple matrices at the same height (4) - potential edge case
    #[test]
    fn commit_same_height_matrices() {
        init_logger();
        let mut rng = SmallRng::seed_from_u64(123);

        // Two matrices with same height should be combined at the same level
        let mat_0 = RowMajorMatrix::<F>::rand(&mut rng, 8, 4);
        let mat_1 = RowMajorMatrix::<F>::rand(&mut rng, 4, 2);
        let mat_2 = RowMajorMatrix::<F>::rand(&mut rng, 4, 3);

        test_all_openings(vec![mat_0, mat_1, mat_2]);
    }

    #[test]
    fn commit_with_cap_height_1() {
        init_logger();
        let mut rng = SmallRng::seed_from_u64(99);
        let mat = RowMajorMatrix::<F>::rand(&mut rng, 8, 3);
        test_all_openings_with_cap_height(vec![mat], 1);
    }

    #[test]
    fn commit_with_cap_height_2() {
        init_logger();
        let mut rng = SmallRng::seed_from_u64(99);
        let mat_0 = RowMajorMatrix::<F>::rand(&mut rng, 16, 2);
        let mat_1 = RowMajorMatrix::<F>::rand(&mut rng, 4, 3);
        test_all_openings_with_cap_height(vec![mat_0, mat_1], 2);
    }

    #[test]
    fn commit_batch_stark_with_cap_height() {
        init_logger();
        let mut rng = SmallRng::seed_from_u64(42);
        let mat_0 = RowMajorMatrix::<F>::rand(&mut rng, 512, 1);
        let mat_1 = RowMajorMatrix::<F>::rand(&mut rng, 8, 1);
        let mat_2 = RowMajorMatrix::<F>::rand(&mut rng, 4, 1);
        let mat_3 = RowMajorMatrix::<F>::rand(&mut rng, 128, 12);
        let mat_4 = RowMajorMatrix::<F>::rand(&mut rng, 4, 3);
        test_all_openings_with_cap_height(vec![mat_0, mat_1, mat_2, mat_3, mat_4], 2);
    }

    #[test]
    fn lifted_verify_with_cap_height() {
        init_logger();
        let mut rng = SmallRng::seed_from_u64(99);
        let mat = RowMajorMatrix::<F>::rand(&mut rng, 8, 3);
        test_lifted_openings_with_cap_height(vec![mat], 1);
    }

    #[test]
    fn verify_tampered_proof_fails() {
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);
        let mmcs = MyMmcs::new(hash.clone(), compress, 0);

        // 4 8x1 matrixes, 4 8x2 matrixes
        let mut mats = (0..4)
            .map(|_| RowMajorMatrix::<F>::rand(&mut rng, 8, 1))
            .collect_vec();
        let large_mat_dims = (0..4).map(|_| Dimensions {
            height: 8,
            width: 1,
        });
        mats.extend((0..4).map(|_| RowMajorMatrix::<F>::rand(&mut rng, 8, 2)));
        let small_mat_dims = (0..4).map(|_| Dimensions {
            height: 8,
            width: 2,
        });
        let dimensions = &large_mat_dims.chain(small_mat_dims).collect_vec();

        let (commit, prover_data) = mmcs.commit(mats);

        let mut builder = CircuitBuilder::<CF>::new();
        let permutation_config = Poseidon2Config::BabyBearD4Width16;
        let perm = default_babybear_poseidon2_16();
        builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<CF, BabyBearD4Width16>,
            perm,
        );

        // open the 3rd row of each matrix, mess with proof, and verify
        let index = 3;
        let path_depth = 3;
        let mut batch_opening = mmcs.open_batch(index, &prover_data);
        batch_opening.opening_proof[0][0] += F::ONE;

        let openings_digests = batch_opening
            .opened_values
            .iter()
            .zip(dimensions)
            .chunk_by(|(_, dimensions)| dimensions.height)
            .into_iter()
            .map(|(_, group)| hash.hash_iter(group.flat_map(|(x, _)| x.clone())))
            .collect_vec();
        let dimensions = dimensions
            .iter()
            .chunk_by(|dimensions| dimensions.height)
            .into_iter()
            .map(|(height, _)| Dimensions { width: 0, height })
            .collect_vec();

        let openings = openings_digests
            .iter()
            .map(|mat_hash| {
                mat_hash
                    .iter()
                    .map(|_| builder.add_public_input())
                    .collect_vec()
            })
            .collect_vec();
        let openings =
            format_openings(&openings, &dimensions, path_depth, permutation_config).unwrap();
        let directions_expr = builder.alloc_public_inputs(path_depth, "directions");
        let root_exprs = builder.alloc_public_inputs(permutation_config.rate_ext(), "root");

        let permutation_mmcs_ops = add_mmcs_verify(
            &mut builder,
            permutation_config,
            &openings,
            &directions_expr,
            &root_exprs,
        )
        .unwrap();
        let circuit = builder.build().unwrap();
        let root_widx0 = circuit.expr_to_widx[&root_exprs[0]];
        let mut runner = circuit.runner();

        let directions = (0..path_depth)
            .map(|k| CF::from_bool(index >> k & 1 == 1))
            .collect_vec();

        let mut public_inputs = vec![];
        public_inputs.extend(
            openings_digests
                .iter()
                .flat_map(|digest| digest.map(CF::from)),
        );
        public_inputs.extend(directions.iter());
        // For cap_height=0, commit has 1 entry
        let commit_entry = &commit.roots()[0];
        let commit_ext = base_digest_to_ext(commit_entry, permutation_config);
        debug_assert_eq!(permutation_config.rate_ext(), commit_ext.len());
        public_inputs.extend(commit_ext);

        runner.set_public_inputs(&public_inputs).unwrap();

        let siblings = batch_opening
            .opening_proof
            .iter()
            .map(|digest| {
                digest
                    .chunks(4)
                    .map(CF::from_basis_coefficients_slice)
                    .collect::<Option<Vec<_>>>()
                    .unwrap()
            })
            .collect_vec();

        for (&op_id, sibling) in permutation_mmcs_ops.iter().zip(siblings) {
            let sibling: [CF; 2] = sibling.try_into().unwrap();
            runner
                .set_private_data(
                    op_id,
                    NonPrimitiveOpPrivateData::Poseidon2Perm(Poseidon2PermPrivateData { sibling }),
                )
                .unwrap();
        }

        // When we run the runner and the MMCS trace is generated, it will be checked that
        // the root computed by the MmcsVerify gate does not match the one given as input.
        let result = runner.run();

        match result {
            Err(CircuitError::WitnessConflict { witness_id, .. }) => {
                assert_eq!(witness_id, root_widx0, "expected root witness mismatch");
            }
            _ => panic!("The test was suppose to fail with a root mismatch!"),
        }
    }

    /// Test MMCS verification using lifted representation (like FRI verifier does).
    /// This tests that `pack_lifted_to_ext` + `verify_batch_circuit` produces correct results.
    ///
    /// The FRI verifier stores opened values as "lifted" targets (one ext target per base field value,
    /// where the ext value is `[base_val, 0, 0, 0]`), then packs them before MMCS verification.
    #[test]
    fn verify_batch_with_lifted_representation() {
        init_logger();

        let perm = default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let mmcs = MyMmcs::new(hash, compress, 0);

        // Create a small matrix (similar to small FRI proofs)
        let mat = RowMajorMatrix::new(
            vec![
                F::from_u32(1),
                F::from_u32(2),
                F::from_u32(3),
                F::from_u32(4),
                F::from_u32(5),
                F::from_u32(6),
                F::from_u32(7),
                F::from_u32(8),
            ],
            4, // 2 rows, 4 columns
        );

        let dimensions = vec![mat.dimensions()];
        let max_height = mat.height();
        let log_max_height = log2_ceil_usize(max_height);

        let (commit, prover_data) = mmcs.commit(vec![mat]);

        for index in 0..max_height {
            let mut builder = CircuitBuilder::<CF>::new();
            let permutation_config = Poseidon2Config::BabyBearD4Width16;
            builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
                generate_poseidon2_trace::<CF, BabyBearD4Width16>,
                perm.clone(),
            );

            let batch_opening = mmcs.open_batch(index, &prover_data);

            let directions = (0..log_max_height)
                .map(|k| index >> k & 1 == 1)
                .collect_vec();

            let lifted_openings: Vec<Vec<_>> = batch_opening
                .opened_values
                .iter()
                .map(|values| {
                    values
                        .iter()
                        .map(|_| builder.add_public_input())
                        .collect_vec()
                })
                .collect();

            let directions_expr = builder.alloc_public_inputs(log_max_height, "directions");

            // Allocate cap entries as LIFTED targets, then pack
            let cap_len = commit.num_roots();
            let mut cap_exprs = Vec::with_capacity(cap_len);
            for _ in 0..cap_len {
                let lifted: Vec<_> = (0..permutation_config.rate())
                    .map(|_| builder.add_public_input())
                    .collect();
                let packed = pack_lifted_targets::<F, CF>(&mut builder, &lifted);
                cap_exprs.push(packed);
            }

            let _permutation_mmcs_ops = verify_batch_circuit::<F, CF>(
                &mut builder,
                permutation_config,
                &cap_exprs,
                &dimensions,
                &directions_expr,
                &lifted_openings,
            )
            .unwrap();

            let circuit = builder.build().unwrap();
            let mut runner = circuit.runner();

            // Set public inputs using LIFTED representation
            let mut public_inputs: Vec<CF> = batch_opening
                .opened_values
                .iter()
                .flat_map(|values| values.iter().map(|&v| CF::from(v)))
                .collect();

            // Then: direction bits
            public_inputs.extend(directions.iter().map(|&bit| CF::from_bool(bit)));

            // Then: lifted cap entries (one EF per base field digest element per entry)
            for entry in commit.roots() {
                public_inputs.extend(entry.iter().map(|&v| CF::from(v)));
            }

            runner.set_public_inputs(&public_inputs).unwrap();

            // Set private data for siblings
            let siblings = batch_opening
                .opening_proof
                .iter()
                .map(|digest| {
                    digest
                        .chunks(4)
                        .map(CF::from_basis_coefficients_slice)
                        .collect::<Option<Vec<_>>>()
                        .unwrap()
                })
                .collect_vec();

            for (&op_id, sibling) in _permutation_mmcs_ops.iter().zip(siblings) {
                runner
                    .set_private_data(
                        op_id,
                        NonPrimitiveOpPrivateData::Poseidon2Perm(Poseidon2PermPrivateData {
                            sibling: sibling.try_into().unwrap(),
                        }),
                    )
                    .unwrap();
            }

            let result = runner.run();
            assert!(
                result.is_ok(),
                "MMCS verification with lifted representation failed at index {}: {:?}",
                index,
                result.err()
            );
        }
    }

    /// Helper function to pack lifted targets into extension targets.
    /// Mimics `pack_lifted_to_ext` from FRI verifier.
    fn pack_lifted_targets<BF, EF>(
        builder: &mut CircuitBuilder<EF>,
        lifted: &[crate::Target],
    ) -> Vec<crate::Target>
    where
        BF: Field,
        EF: ExtensionField<BF> + BasedVectorSpace<BF>,
    {
        if lifted.is_empty() {
            return Vec::new();
        }

        let d = EF::DIMENSION;
        let basis: Vec<EF> = (0..d)
            .map(|i| {
                let mut coeffs = vec![BF::ZERO; d];
                coeffs[i] = BF::ONE;
                EF::from_basis_coefficients_slice(&coeffs).expect("valid basis")
            })
            .collect();

        lifted
            .chunks(d)
            .map(|chunk| {
                let mut acc = builder.add_const(EF::ZERO);
                for (i, &target) in chunk.iter().enumerate() {
                    let basis_const = builder.add_const(basis[i]);
                    let term = builder.mul(target, basis_const);
                    acc = builder.add(acc, term);
                }
                acc
            })
            .collect()
    }

    /// Test helper that runs MMCS verification using lifted representation for various matrix configs.
    fn test_lifted_openings(mats: Vec<RowMajorMatrix<F>>) {
        test_lifted_openings_with_cap_height(mats, 0);
    }

    fn test_lifted_openings_with_cap_height(mats: Vec<RowMajorMatrix<F>>, cap_height: usize) {
        let perm = default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let mmcs = MyMmcs::new(hash, compress, cap_height);

        let dimensions = mats.iter().map(DenseMatrix::dimensions).collect_vec();

        let mut heights_tallest_first = dimensions
            .iter()
            .enumerate()
            .sorted_by_key(|(_, dims)| Reverse(dims.height))
            .peekable();

        let max_height = heights_tallest_first.peek().unwrap().1.height;

        let (commit, prover_data) = mmcs.commit(mats);

        let log_max_height = log2_ceil_usize(max_height);
        for index in 0..max_height {
            let mut builder = CircuitBuilder::<CF>::new();
            let permutation_config = Poseidon2Config::BabyBearD4Width16;
            builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
                generate_poseidon2_trace::<CF, BabyBearD4Width16>,
                perm.clone(),
            );

            let batch_opening = mmcs.open_batch(index, &prover_data);

            let directions = (0..log_max_height)
                .map(|k| index >> k & 1 == 1)
                .collect_vec();

            let lifted_openings: Vec<Vec<_>> = batch_opening
                .opened_values
                .iter()
                .map(|values| {
                    values
                        .iter()
                        .map(|_| builder.add_public_input())
                        .collect_vec()
                })
                .collect();

            let directions_expr = builder.alloc_public_inputs(log_max_height, "directions");

            // Allocate cap entries as LIFTED, then pack
            let cap_len = commit.num_roots();
            let mut cap_exprs = Vec::with_capacity(cap_len);
            for _ in 0..cap_len {
                let lifted: Vec<_> = (0..permutation_config.rate())
                    .map(|_| builder.add_public_input())
                    .collect();
                let packed = pack_lifted_targets::<F, CF>(&mut builder, &lifted);
                cap_exprs.push(packed);
            }

            let permutation_mmcs_ops = verify_batch_circuit::<F, CF>(
                &mut builder,
                permutation_config,
                &cap_exprs,
                &dimensions,
                &directions_expr,
                &lifted_openings,
            )
            .unwrap();

            let circuit = builder.build().unwrap();
            let mut runner = circuit.runner();

            // Set public inputs using LIFTED representation
            let mut public_inputs: Vec<CF> = batch_opening
                .opened_values
                .iter()
                .flat_map(|values| values.iter().map(|&v| CF::from(v)))
                .collect();

            public_inputs.extend(directions.iter().map(|&bit| CF::from_bool(bit)));

            // Lifted cap entries
            for entry in commit.roots() {
                public_inputs.extend(entry.iter().map(|&v| CF::from(v)));
            }

            runner.set_public_inputs(&public_inputs).unwrap();

            // Set private data for siblings
            let siblings = batch_opening
                .opening_proof
                .iter()
                .map(|digest| {
                    digest
                        .chunks(4)
                        .map(CF::from_basis_coefficients_slice)
                        .collect::<Option<Vec<_>>>()
                        .unwrap()
                })
                .collect_vec();

            for (&op_id, sibling) in permutation_mmcs_ops.iter().zip(siblings) {
                runner
                    .set_private_data(
                        op_id,
                        NonPrimitiveOpPrivateData::Poseidon2Perm(Poseidon2PermPrivateData {
                            sibling: sibling.try_into().unwrap(),
                        }),
                    )
                    .unwrap();
            }

            let _ = runner.run().unwrap();
        }
    }

    /// Test with very small matrix (height=2, minimal Merkle tree depth=1)
    #[test]
    fn lifted_verify_small_2x4() {
        init_logger();
        let mat = RowMajorMatrix::new(
            (0..8).map(|i| F::from_u32(i as u32)).collect_vec(),
            4, // 2 rows, 4 columns
        );
        test_lifted_openings(vec![mat]);
    }

    /// Test with non-power-of-4 width (tests truncation)
    #[test]
    fn lifted_verify_small_2x5() {
        init_logger();
        let mat = RowMajorMatrix::new(
            (0..10).map(|i| F::from_u32(i as u32)).collect_vec(),
            5, // 2 rows, 5 columns
        );
        test_lifted_openings(vec![mat]);
    }

    /// Test with multiple matrices at different heights (like FRI batches)
    #[test]
    fn lifted_verify_multi_height() {
        init_logger();
        // Two matrices: 8 rows and 4 rows (different heights)
        let mat1 = RowMajorMatrix::new(
            (0..16).map(|i| F::from_u32(i as u32)).collect_vec(),
            2, // 8 rows, 2 columns
        );
        let mat2 = RowMajorMatrix::new(
            (20..32).map(|i| F::from_u32(i as u32)).collect_vec(),
            3, // 4 rows, 3 columns
        );
        test_lifted_openings(vec![mat1, mat2]);
    }

    /// Test with matrices at same height (combined at same level)
    #[test]
    fn lifted_verify_same_height() {
        init_logger();
        // Two matrices with same height
        let mat1 = RowMajorMatrix::new(
            (0..8).map(|i| F::from_u32(i as u32)).collect_vec(),
            2, // 4 rows, 2 columns
        );
        let mat2 = RowMajorMatrix::new(
            (10..22).map(|i| F::from_u32(i as u32)).collect_vec(),
            3, // 4 rows, 3 columns
        );
        test_lifted_openings(vec![mat1, mat2]);
    }

    /// Test with very small column widths (1 column) - edge case from recursive_fibonacci -n 1
    /// This tests base_widths=[1, 1, 1, 3, 3] configuration
    ///
    /// This test verifies that `verify_batch_circuit` correctly handles non-aligned
    /// base field widths by using overwrite-mode hashing (matching native PaddingFreeSponge).
    #[test]
    fn lifted_verify_single_column_matrices() {
        init_logger();
        // Simulate batch 0 from fibonacci -n 1: base_widths=[1, 1, 1, 3, 3], 5 matrices
        // With log_max_height=3, so 8 rows for the tallest matrix
        let mat0 = RowMajorMatrix::new(
            (0..8).map(|i| F::from_u32(i as u32)).collect_vec(),
            1, // 8 rows, 1 column
        );
        let mat1 = RowMajorMatrix::new(
            (10..18).map(|i| F::from_u32(i as u32)).collect_vec(),
            1, // 8 rows, 1 column
        );
        let mat2 = RowMajorMatrix::new(
            (20..28).map(|i| F::from_u32(i as u32)).collect_vec(),
            1, // 8 rows, 1 column
        );
        let mat3 = RowMajorMatrix::new(
            (30..54).map(|i| F::from_u32(i as u32)).collect_vec(),
            3, // 8 rows, 3 columns
        );
        let mat4 = RowMajorMatrix::new(
            (60..84).map(|i| F::from_u32(i as u32)).collect_vec(),
            3, // 8 rows, 3 columns
        );
        test_lifted_openings(vec![mat0, mat1, mat2, mat3, mat4]);
    }

    /// Test with mixed heights matching fibonacci -n 1's batch 0 (with log_blowup applied)
    /// This specifically tests the height grouping logic
    #[test]
    fn lifted_verify_fibonacci_batch0_config() {
        init_logger();
        // From fibonacci -n 1: batch 0 has 5 matrices with base_widths=[1, 1, 1, 3, 3]
        // heights depend on domain sizes and log_blowup
        // Let's test with different heights to trigger height grouping
        let mat0 = RowMajorMatrix::new(
            (0..8).map(|i| F::from_u32(i as u32)).collect_vec(),
            1, // 8 rows, 1 column
        );
        let mat1 = RowMajorMatrix::new(
            (10..14).map(|i| F::from_u32(i as u32)).collect_vec(),
            1, // 4 rows, 1 column
        );
        let mat2 = RowMajorMatrix::new(
            (20..24).map(|i| F::from_u32(i as u32)).collect_vec(),
            1, // 4 rows, 1 column
        );
        let mat3 = RowMajorMatrix::new(
            (30..54).map(|i| F::from_u32(i as u32)).collect_vec(),
            3, // 8 rows, 3 columns
        );
        let mat4 = RowMajorMatrix::new(
            (60..72).map(|i| F::from_u32(i as u32)).collect_vec(),
            3, // 4 rows, 3 columns
        );
        test_lifted_openings(vec![mat0, mat1, mat2, mat3, mat4]);
    }
}
