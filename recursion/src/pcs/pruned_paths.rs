//! Reconstruct full per-query Merkle authentication paths from a pruned multiproof.
//!
//! `p3_merkle_tree` 0.7 batches all queries into one commitment into a single
//! [`p3_merkle_tree::PrunedMerklePaths`]: sibling digests shared by more than one query's
//! path are sent once — a digest is omitted whenever another query's own leaf lies under it,
//! since the amortized verifier recomputes it by hashing rather than reading it explicitly.
//! For any single-root commitment (`cap_height == 0`, the standard FRI/WHIR configuration)
//! opened at 2 or more indices, this is not a rare case: every query's path is guaranteed to
//! converge with another's by the time it nears the root (there are only 2 possible nodes at
//! the level below the root), so a real multi-query proof always omits at least one digest
//! near the top.
//!
//! The in-circuit MMCS gadget (`add_mmcs_verify`) is single-path per query and has no notion
//! of shared digests, so before it can consume this proof we must restore each query's
//! individual, full sibling chain (one digest per tree level, leaf-adjacent first) —
//! including the omitted positions, which this module recomputes by replaying the same
//! bottom-up, per-parent-group frontier walk `MerkleTreeMmcs::verify_batch_pruned` uses
//! (`p3_merkle_tree::pruning`'s `walk_frontier`/`restore_paths`, `pub(crate)` there and so not
//! reusable directly). The wire order and grouping rules must match that implementation
//! exactly, or honestly-generated proofs will fail to restore.

use alloc::vec;
use alloc::vec::Vec;

/// Number of siblings a full path holds across the given number of levels.
///
/// Mirrors `p3_merkle_tree::pruning::total_siblings_for_levels`: each level contributes
/// `arity - 1` siblings (one child is the path's own).
fn total_siblings_for_levels(num_levels: usize, arity_schedule: &[usize]) -> usize {
    arity_schedule[..num_levels].iter().map(|&a| a - 1).sum()
}

/// Offset of a child inside a lead path's flat sibling chunk for one level.
///
/// Mirrors `p3_merkle_tree::pruning::sibling_offset`.
const fn sibling_offset(k: usize, lead_pos: usize) -> usize {
    if k < lead_pos { k } else { k - 1 }
}

/// Reconstructs each query's full, per-level sibling chain from a pruned multiproof,
/// recomputing (via `compress`) any position the pruned proof omitted because another
/// query's own path already covers it.
///
/// `query_indices` is the original (possibly duplicated, original-order) list of leaf
/// indices opened by this MMCS call. `query_leaf_digests` is each query's own leaf digest
/// (already hashed by the caller — leaf hashing differs by MMCS variant, e.g. base vs
/// extension elements, salted vs not, so this module doesn't do it), same order and length
/// as `query_indices`. `arity_schedule` gives the per-level arity, leaf level first, matching
/// what the prover used (derived from verifier-known dimensions and cap height, never from
/// the proof). `pruned_sibling_hashes` is `PrunedMerklePaths::sibling_hashes`. `compress`
/// combines one level's `arity`-many child digests (in child-position order) into their
/// parent digest, mirroring the MMCS's own compression function; it receives the level index
/// (in case a variable-arity schedule uses a different function per arity) and the group's
/// index at the *next* level (`this level's shared index / arity`) — the same reduced index
/// a mixed-height MMCS uses to place an injected matrix's row. This module has no notion of
/// injection itself (an injected digest never appears in `pruned_sibling_hashes`, since the
/// in-circuit gadget wires it in directly rather than through per-query private data — see
/// `p3_merkle_tree`'s own `verify_batch`, which computes an injected digest locally rather
/// than reading it from the proof); a caller whose tree injects mid-path folds that in from
/// within `compress` using the supplied group index, transparently to this walk.
///
/// This replays the same bottom-up, per-parent-group walk `MerkleTreeMmcs::verify_batch_pruned`
/// uses to amortize verification across queries (see the `p3_merkle_tree::mmcs` and
/// `p3_merkle_tree::pruning` source): at each level, a group of queries sharing a parent is
/// compressed exactly once, using each covered child position's already-computed digest and
/// each boundary position's pruned digest. Unlike that verifier, this function does not stop
/// at checking equality with the commitment — it retains every level's per-query view of
/// "the other children" so the (unchanged, single-path) in-circuit MMCS gadget can later
/// authenticate each query independently, exactly like a pre-0.7 per-query proof.
///
/// Returns one entry per entry of `query_indices` (preserving order and duplicates), each a
/// flat, level-major `Vec<D>` of length `total_siblings_for_levels(arity_schedule.len(),
/// arity_schedule)` — the same shape the pre-0.7 per-query `Mmcs::Proof` used to hand back
/// directly.
///
/// Returns `Err` if the supplied digest count doesn't match what the frontier walk expects,
/// if two occurrences of the same leaf index carry different leaf digests (a malformed
/// proof), or if `query_indices`/`query_leaf_digests` have mismatched lengths.
pub fn restore_and_recompute_paths<D: Clone + PartialEq>(
    pruned_sibling_hashes: &[D],
    query_indices: &[usize],
    query_leaf_digests: &[D],
    arity_schedule: &[usize],
    mut compress: impl FnMut(usize, usize, &[D]) -> D,
) -> Result<Vec<Vec<D>>, &'static str> {
    if query_indices.len() != query_leaf_digests.len() {
        return Err("query_indices and query_leaf_digests must have the same length");
    }
    if query_indices.is_empty() {
        return if pruned_sibling_hashes.is_empty() {
            Ok(Vec::new())
        } else {
            Err("pruned proof carries sibling digests but no queries were supplied")
        };
    }

    // Sort+dedup, mirroring the prover's `order.sort_unstable_by_key`/`dedup_by_key`, but
    // additionally checking (as native does for opened values) that every occurrence of a
    // repeated leaf index carries the same leaf digest.
    let mut order: Vec<usize> = (0..query_indices.len()).collect();
    order.sort_unstable_by_key(|&i| query_indices[i]);
    let mut sorted_unique_order: Vec<usize> = Vec::with_capacity(order.len());
    for &i in &order {
        if let Some(&last) = sorted_unique_order.last()
            && query_indices[last] == query_indices[i]
        {
            if query_leaf_digests[last] != query_leaf_digests[i] {
                return Err("two occurrences of the same query index carry different leaf digests");
            }
            continue;
        }
        sorted_unique_order.push(i);
    }
    let sorted_unique: Vec<usize> = sorted_unique_order
        .iter()
        .map(|&i| query_indices[i])
        .collect();

    let full_sibling_count = total_siblings_for_levels(arity_schedule.len(), arity_schedule);
    let chunk_base: Vec<usize> = (0..=arity_schedule.len())
        .map(|l| total_siblings_for_levels(l, arity_schedule))
        .collect();

    let mut restored: Vec<Vec<Option<D>>> = sorted_unique
        .iter()
        .map(|_| vec![None; full_sibling_count])
        .collect();

    // Once two leads' paths merge into the same node, they share every subsequent level's
    // "other children" identically — so a merged node carries *every* lead that has joined it
    // so far (not just one representative), or later levels would silently skip writing
    // `restored` for the leads left behind.
    struct FrontierNode<D> {
        index: usize,
        leads: Vec<usize>,
        digest: D,
    }
    let mut nodes: Vec<FrontierNode<D>> = sorted_unique_order
        .iter()
        .zip(sorted_unique.iter())
        .enumerate()
        .map(|(slot, (&i, &index))| FrontierNode {
            index,
            leads: vec![slot],
            digest: query_leaf_digests[i].clone(),
        })
        .collect();
    let mut parents: Vec<FrontierNode<D>> = Vec::with_capacity(nodes.len());

    let mut cursor = 0usize;
    for (level, &arity) in arity_schedule.iter().enumerate() {
        parents.clear();

        let mut i = 0;
        while i < nodes.len() {
            let group = nodes[i].index / arity;
            let group_start = group * arity;

            // Collect this group's `arity` child digests: a member's own current digest
            // where a query covers that position, else the next pruned boundary digest, in
            // canonical (ascending, skip-covered) order — the same order the prover pruned in.
            let mut member = i;
            let mut children: Vec<D> = Vec::with_capacity(arity);
            for k in 0..arity {
                if member < nodes.len() && nodes[member].index == group_start + k {
                    children.push(nodes[member].digest.clone());
                    member += 1;
                } else {
                    let d = pruned_sibling_hashes
                        .get(cursor)
                        .ok_or("pruned proof has fewer sibling digests than the frontier expects")?
                        .clone();
                    cursor += 1;
                    children.push(d);
                }
            }

            // Every member of this group now has the full `arity`-length children list: fill
            // in every merged lead's "other children" (its own position stays unfilled — it
            // isn't one of its own siblings — and gets read from leaf/prior-level data by the
            // circuit gadget separately).
            let mut merged_leads = Vec::new();
            for member_idx in i..member {
                let own_pos = nodes[member_idx].index - group_start;
                for &lead in &nodes[member_idx].leads {
                    for (k, child) in children.iter().enumerate() {
                        if k != own_pos {
                            restored[lead][chunk_base[level] + sibling_offset(k, own_pos)] =
                                Some(child.clone());
                        }
                    }
                }
                merged_leads.extend(nodes[member_idx].leads.iter().copied());
            }

            let parent_digest = compress(level, group, &children);
            parents.push(FrontierNode {
                index: group,
                leads: merged_leads,
                digest: parent_digest,
            });
            i = member;
        }

        core::mem::swap(&mut nodes, &mut parents);
    }

    if cursor != pruned_sibling_hashes.len() {
        return Err("pruned proof has more sibling digests than the frontier expects");
    }

    let restored: Vec<Vec<D>> = restored
        .into_iter()
        .map(|path| path.into_iter().collect::<Option<Vec<D>>>())
        .collect::<Option<Vec<Vec<D>>>>()
        .ok_or("internal error: a path position was neither a boundary digest nor covered by another query")?;

    // Map back from sorted-unique order to the caller's original (possibly duplicated) order.
    let mut result = Vec::with_capacity(query_indices.len());
    for &leaf_index in query_indices {
        let pos = sorted_unique
            .binary_search(&leaf_index)
            .map_err(|_| "internal error: query index missing from restored set")?;
        result.push(restored[pos].clone());
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_commit::Mmcs;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::{Dimensions, Matrix};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{
        CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation,
    };
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::*;

    const DIGEST_ELEMS: usize = 8;

    type Digest = [BabyBear; DIGEST_ELEMS];
    type Perm = Poseidon2BabyBear<16>;
    type Hash = PaddingFreeSponge<Perm, 16, 8, DIGEST_ELEMS>;
    type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
    type Mmcs2 = MerkleTreeMmcs<BabyBear, BabyBear, Hash, Compress, 2, DIGEST_ELEMS>;

    /// Commit a single power-of-two-height matrix, so the tree's arity schedule is uniform
    /// binary compression with no matrix-injection bridging — isolating this module's own
    /// restoration logic from that (separately covered) grouping concern.
    #[allow(clippy::type_complexity)]
    fn commit_test_matrix() -> (
        Mmcs2,
        Hash,
        Compress,
        RowMajorMatrix<BabyBear>,
        Vec<Dimensions>,
        <Mmcs2 as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>,
    ) {
        let perm = default_babybear_poseidon2_16();
        let hash = Hash::new(perm.clone());
        let compress = Compress::new(perm);
        let mmcs = MerkleTreeMmcs::new(hash.clone(), compress.clone(), 0);

        let mut rng = SmallRng::seed_from_u64(2);
        let matrix = RowMajorMatrix::rand(&mut rng, 64, 3);
        let dimensions = vec![Dimensions {
            width: matrix.width(),
            height: matrix.height(),
        }];

        let (_commit, prover_data) = mmcs.commit(vec![matrix.clone()]);
        (mmcs, hash, compress, matrix, dimensions, prover_data)
    }

    /// Cross-checks `restore_and_recompute_paths` against `open_batch`-produced single-query
    /// proofs for an overlapping, duplicated query set — the case a pruned multiproof always
    /// hits for any single-root tree (see the module doc): some sibling digests are omitted
    /// because another query's own path already covers them, and this function must recompute
    /// those instead of erroring.
    #[test]
    fn restores_and_recomputes_paths_for_overlapping_queries() {
        let (mmcs, hash, compress, matrix, dimensions, prover_data) = commit_test_matrix();

        let query_indices = vec![3usize, 61, 3, 40, 61, 0];

        let expected_paths: Vec<Vec<Digest>> = query_indices
            .iter()
            .map(|&idx| mmcs.open_batch(idx, &prover_data).unpack().1)
            .collect();

        let (_opened, multiproof) = mmcs.open_multi_batch(&query_indices, &prover_data);
        let arity_schedule = mmcs
            .proof_arity_schedule(&dimensions)
            .expect("valid dimensions");

        let leaf_digests: Vec<Digest> = query_indices
            .iter()
            .map(|&idx| hash.hash_slice(&matrix.row_slice(idx).unwrap()))
            .collect();

        let restored = restore_and_recompute_paths(
            &multiproof.sibling_hashes,
            &query_indices,
            &leaf_digests,
            &arity_schedule,
            |_level, _group, children: &[Digest]| {
                let inputs: [Digest; 2] = children.try_into().expect("binary tree, arity 2");
                compress.compress(inputs)
            },
        )
        .expect("restoration succeeds for overlapping queries");

        assert_eq!(restored, expected_paths);
    }

    #[test]
    fn empty_query_set_requires_empty_proof() {
        let restored = restore_and_recompute_paths::<Digest>(
            &[],
            &[],
            &[],
            &[2, 2, 2],
            |_, _, _| unreachable!(),
        )
        .expect("empty inputs succeed");
        assert!(restored.is_empty());

        let err = restore_and_recompute_paths::<Digest>(
            &[[BabyBear::ZERO; DIGEST_ELEMS]],
            &[],
            &[],
            &[2, 2, 2],
            |_, _, _| unreachable!(),
        );
        assert!(err.is_err());
    }
}
