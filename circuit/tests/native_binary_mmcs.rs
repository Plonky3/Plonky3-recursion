//! Native binary carriers authenticate the same mixed-height byte Merkle trees.

use p3_binary_field::{BinaryField8, BinaryField128, Poly64, TowerLevel};
use p3_circuit::{
    CircuitBuilder, ExprId,
    ops::{
        ByteHash,
        binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding},
        binary_native::BinaryCoordinateField,
        bytes_to_limbs,
    },
};
use p3_commit::Mmcs;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_test_utils::binary_field_params::keccak;

fn check<F: BinaryCoordinateField>(heights: &[usize], cap_height: usize, index: usize) {
    let mmcs = keccak::LevelMmcs::<BinaryField8>::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        cap_height,
    );
    let matrices: Vec<_> = heights
        .iter()
        .enumerate()
        .map(|(m, &height)| {
            RowMajorMatrix::new(
                (0..height * (2 * m + 1))
                    .map(|i| BinaryField8::from_repr((i * 37 + m * 19 + 129) as u8))
                    .collect(),
                2 * m + 1,
            )
        })
        .collect();
    let dims: Vec<_> = matrices.iter().map(Matrix::dimensions).collect();
    let (commitment, data) = mmcs.commit(matrices);
    let opening = mmcs.open_batch(index, &data);
    mmcs.verify_batch(&commitment, &dims, index, (&opening).into())
        .unwrap();
    let log_height = heights
        .iter()
        .copied()
        .max()
        .unwrap()
        .next_power_of_two()
        .ilog2() as usize;
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let mut inputs = |count| (0..count).map(|_| b.public_input()).collect();
    let rows: Vec<_> = dims.iter().map(|d| inputs(d.width)).collect();
    let bits = inputs(log_height);
    let siblings: Vec<_> = (0..log_height - cap_height).map(|_| inputs(16)).collect();
    let cap: Vec<_> = (0..1 << cap_height).map(|_| inputs(16)).collect();
    b.verify_byte_hash_mmcs_opening_bytes_with_host::<NativeBinaryEncoding>(
        ByteHash::Keccak256,
        &rows,
        heights,
        &bits,
        &siblings,
        &cap,
    )
    .unwrap();
    let circuit = b.build().unwrap();
    let mut public: Vec<F> = opening
        .opened_values
        .iter()
        .flatten()
        .map(|x| NativeBinaryEncoding::encode_u16(u16::from(x.to_repr())).unwrap())
        .collect();
    let row_width = public.len();
    public.extend((0..log_height).map(|bit| F::from_bool(index >> bit & 1 != 0)));
    for digest in opening.opening_proof.iter().chain(commitment.roots()) {
        public.extend(
            bytes_to_limbs(digest)
                .into_iter()
                .map(|word| -> F { NativeBinaryEncoding::encode_u16(word).unwrap() }),
        );
    }
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    // Distinct leaf, smaller injected row, index, path and cap bindings.
    let cap_start = row_width + log_height + 16 * siblings.len();
    let cap_index = index >> (log_height - cap_height);
    for changed in [0, row_width - 1, row_width, cap_start + 16 * cap_index + 15] {
        let mut wrong = public.clone();
        wrong[changed] += F::ONE;
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&wrong)
                .and_then(|()| runner.run())
                .is_err(),
            "cap height {cap_height}, index {index}, changed input {changed}"
        );
    }
    if !siblings.is_empty() {
        public[row_width + log_height] += F::ONE;
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&public)
                .and_then(|()| runner.run())
                .is_err()
        );
    }
}

#[test]
fn native_tower_and_polynomial_mmcs_match_mixed_height_caps_and_zero_depth() {
    for cap_height in [0, 1] {
        for index in 0..3 {
            check::<BinaryField128>(&[3, 2], cap_height, index);
            check::<Poly64>(&[3, 2], cap_height, index);
        }
    }
    check::<BinaryField128>(&[4], 2, 3);
    check::<Poly64>(&[4], 2, 3);
}

#[test]
fn unrepresentable_index_width_is_rejected_before_builder_mutation() {
    let mut b = CircuitBuilder::<BinaryField128>::new();
    let input = b.public_input();
    assert!(
        b.verify_byte_hash_mmcs_opening_bytes_with_host::<NativeBinaryEncoding>(
            ByteHash::Keccak256,
            &[vec![input]],
            &[usize::MAX],
            &vec![ExprId::ZERO; usize::BITS as usize],
            &[],
            &[vec![ExprId::ZERO; 16]],
        )
        .is_err()
    );
    let rejected = b.build().unwrap();
    let mut control = CircuitBuilder::<BinaryField128>::new();
    control.public_input();
    let control = control.build().unwrap();
    assert_eq!(rejected.witness_count, control.witness_count);
    assert_eq!(rejected.expr_to_widx, control.expr_to_widx);
    assert_eq!(format!("{:?}", rejected.ops), format!("{:?}", control.ops));
}
