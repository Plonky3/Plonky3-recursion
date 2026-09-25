//! Byte-hash tables in recursion inputs.
//!
//! A circuit that calls Keccak-f\[1600\] or the BLAKE3 compression proves those calls in their own
//! non-primitive tables. To verify such a proof, a recursion layer needs the table provers that
//! rebuild those tables' AIRs, listed in the input proof's manifest order. The built-in backends
//! know only their own Poseidon and recompose tables, so they pass their provers through
//! [`with_hash_table_input_provers`], which adds the hash tables an input manifest names.

use alloc::boxed::Box;
use alloc::vec::Vec;

use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::batch_stark_prover::{Blake3CompressProver, KeccakF1600Prover, TableProver};
use p3_circuit_prover::config::StarkField;
use p3_field::Algebra;
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};

/// The hash-table prover for `op_type` at trace extension degree `ext_degree`, if any.
fn hash_table_prover<SC>(op_type: &NpoTypeId, ext_degree: usize) -> Option<Box<dyn TableProver<SC>>>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    macro_rules! by_degree {
        ($prover:ident) => {
            match ext_degree {
                1 => Some(Box::new($prover::<1>) as Box<dyn TableProver<SC>>),
                2 => Some(Box::new($prover::<2>)),
                4 => Some(Box::new($prover::<4>)),
                5 => Some(Box::new($prover::<5>)),
                8 => Some(Box::new($prover::<8>)),
                _ => None,
            }
        };
    }
    if *op_type == NpoTypeId::keccak_f1600() {
        by_degree!(KeccakF1600Prover)
    } else if *op_type == NpoTypeId::blake3_compress() {
        by_degree!(Blake3CompressProver)
    } else {
        None
    }
}

/// Adds the hash-table provers an input manifest names to a backend's input provers.
///
/// `op_types` is the input proof's manifest, in order. When it names no hash table, `provers` is
/// returned unchanged. Otherwise the hash tables may only be *added*: once its hash entries are
/// removed, the manifest must list exactly the tables `provers` rebuilds, in the same order, as
/// before. Then each hash table's prover is placed at its manifest position. If the rest of the
/// manifest differs, the hash provers are appended instead, and reconstruction reports the
/// mismatch exactly as it would without them.
pub fn with_hash_table_input_provers<SC>(
    ext_degree: usize,
    op_types: &[NpoTypeId],
    provers: Vec<Box<dyn TableProver<SC>>>,
) -> Vec<Box<dyn TableProver<SC>>>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let is_hash =
        |op: &NpoTypeId| *op == NpoTypeId::keccak_f1600() || *op == NpoTypeId::blake3_compress();
    if !op_types.iter().any(is_hash) {
        return provers;
    }

    let backend_types: Vec<NpoTypeId> = provers
        .iter()
        .map(|p| TableProver::op_type(p.as_ref()))
        .collect();
    let rest_matches = op_types
        .iter()
        .filter(|op| !is_hash(op))
        .eq(backend_types.iter());
    let mut backend = provers.into_iter();
    let mut out = Vec::with_capacity(op_types.len());
    if !rest_matches {
        out.extend(backend);
        out.extend(
            op_types
                .iter()
                .filter(|op| is_hash(op))
                .filter_map(|op| hash_table_prover::<SC>(op, ext_degree)),
        );
        return out;
    }
    for op in op_types {
        if !is_hash(op) {
            out.extend(backend.next());
            continue;
        }
        match hash_table_prover::<SC>(op, ext_degree) {
            Some(prover) => out.push(prover),
            None => return out.into_iter().chain(backend).collect(),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_circuit_prover::batch_stark_prover::RecomposeProver;
    use p3_test_utils::koala_bear_params::MyConfig;

    use super::*;

    fn backend() -> Vec<Box<dyn TableProver<MyConfig>>> {
        vec![
            Box::new(RecomposeProver::<4>::new(1, false)),
            Box::new(RecomposeProver::<4>::new(1, true)),
        ]
    }

    fn types(provers: &[Box<dyn TableProver<MyConfig>>]) -> Vec<NpoTypeId> {
        provers
            .iter()
            .map(|p| TableProver::op_type(p.as_ref()))
            .collect()
    }

    #[test]
    fn a_manifest_without_hash_tables_keeps_the_backend_list() {
        let manifest = vec![NpoTypeId::recompose()];
        let provers = with_hash_table_input_provers(4, &manifest, backend());
        assert_eq!(types(&provers), types(&backend()));
    }

    #[test]
    fn hash_tables_are_placed_at_their_manifest_positions() {
        let manifest = vec![
            NpoTypeId::blake3_compress(),
            NpoTypeId::recompose(),
            NpoTypeId::keccak_f1600(),
            NpoTypeId::recompose_with_coeff_lookups(),
        ];
        let provers = with_hash_table_input_provers(4, &manifest, backend());
        assert_eq!(types(&provers), manifest);
    }

    /// Hash tables never let a manifest drop or reorder the backend's own tables: the hash
    /// provers are appended instead, so reconstruction still sees the mismatch.
    #[test]
    fn a_manifest_that_changes_the_backend_tables_is_not_realigned() {
        let manifest = vec![NpoTypeId::keccak_f1600(), NpoTypeId::recompose()];
        let provers = with_hash_table_input_provers(4, &manifest, backend());
        let mut expected = types(&backend());
        expected.push(NpoTypeId::keccak_f1600());
        assert_eq!(types(&provers), expected);
        assert_ne!(types(&provers), manifest);
    }
}
