//! Native binary carriers authenticate the same mixed-height byte Merkle trees.

use p3_binary_field::{BinaryField8, BinaryField128, Poly64, TowerLevel};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_commit::Mmcs;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_test_utils::binary_field_params::keccak;

/// Word rows have an even byte width and are given as low-first sixteen-bit
/// words.
fn check<F: BinaryCoordinateField>(
    heights: &[usize],
    cap_height: usize,
    index: usize,
    words: bool,
) {
    let mmcs = keccak::LevelMmcs::<BinaryField8>::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        cap_height,
    );
    let width = |m: usize| if words { 2 * m + 2 } else { 2 * m + 1 };
    let matrices: Vec<_> = heights
        .iter()
        .enumerate()
        .map(|(m, &height)| {
            RowMajorMatrix::new(
                (0..height * width(m))
                    .map(|i| BinaryField8::from_repr((i * 37 + m * 19 + 129) as u8))
                    .collect(),
                width(m),
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
    let rows: Vec<_> = dims
        .iter()
        .map(|d| inputs(if words { d.width / 2 } else { d.width }))
        .collect();
    let bits = inputs(log_height);
    let siblings: Vec<_> = (0..log_height - cap_height).map(|_| inputs(16)).collect();
    let cap: Vec<_> = (0..1 << cap_height).map(|_| inputs(16)).collect();
    if words {
        b.verify_byte_hash_mmcs_opening_words_with_host::<NativeBinaryEncoding>(
            ByteHash::Keccak256,
            &rows,
            heights,
            &bits,
            &siblings,
            &cap,
        )
    } else {
        b.verify_byte_hash_mmcs_opening_bytes_with_host::<NativeBinaryEncoding>(
            ByteHash::Keccak256,
            &rows,
            heights,
            &bits,
            &siblings,
            &cap,
        )
    }
    .unwrap();
    let circuit = b.build().unwrap();
    let encode = |word: u16| -> F { NativeBinaryEncoding::encode_u16(word).unwrap() };
    let mut public: Vec<F> = Vec::new();
    for row in &opening.opened_values {
        let row: Vec<u8> = row.iter().map(|x| x.to_repr()).collect();
        if words {
            public.extend(bytes_to_limbs(&row).into_iter().map(encode));
        } else {
            public.extend(row.into_iter().map(|byte| encode(u16::from(byte))));
        }
    }
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
    if words {
        // A word with a seventeenth coordinate serializes no row.
        let mut wide = public.clone();
        wide[0] += F::from_raw_coordinates(1 << 16).unwrap();
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&wide)
                .and_then(|()| runner.run())
                .is_err()
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

/// Opens the `2^arity` rows of the aligned subtree at `upper` in a native tree
/// and checks that the subtree gadget alone binds every leaf, their order,
/// the upper index bits, every sibling above the subtree and the cap root.
fn check_subtree<F: BinaryCoordinateField>(
    log_height: usize,
    arity: usize,
    cap_height: usize,
    upper: usize,
) {
    let mmcs = keccak::LevelMmcs::<BinaryField8>::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        cap_height,
    );
    let matrix = RowMajorMatrix::new(
        (0..3 << log_height)
            .map(|i| BinaryField8::from_repr((i * 37 + 129) as u8))
            .collect(),
        3,
    );
    let (commitment, data) = mmcs.commit(vec![matrix]);
    let size = 1 << arity;
    let openings: Vec<_> = (0..size)
        .map(|offset| mmcs.open_batch(upper << arity | offset, &data))
        .collect();
    let upper_bits = log_height - arity;
    let depth = upper_bits - cap_height;
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let mut inputs = |count| (0..count).map(|_| b.public_input()).collect::<Vec<_>>();
    let leaves: Vec<_> = (0..size).map(|_| inputs(3)).collect();
    let bits = inputs(upper_bits);
    let siblings: Vec<_> = (0..depth).map(|_| inputs(16)).collect();
    let cap: Vec<_> = (0..1 << cap_height).map(|_| inputs(16)).collect();
    b.verify_byte_hash_mmcs_subtree_bytes_with_host::<NativeBinaryEncoding>(
        ByteHash::Keccak256,
        &leaves,
        1 << log_height,
        &bits,
        &siblings,
        &cap,
    )
    .unwrap();
    let circuit = b.build().unwrap();
    let encode = |word: u16| -> F { NativeBinaryEncoding::encode_u16(word).unwrap() };
    let mut public: Vec<F> = openings
        .iter()
        .flat_map(|opening| &opening.opened_values[0])
        .map(|x| encode(u16::from(x.to_repr())))
        .collect();
    public.extend((0..upper_bits).map(|bit| F::from_bool(upper >> bit & 1 != 0)));
    for digest in openings[0].opening_proof[arity..]
        .iter()
        .chain(commitment.roots())
    {
        public.extend(bytes_to_limbs(digest).into_iter().map(encode));
    }
    let runs = |public: &[F]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    assert!(runs(&public), "honest subtree");
    let bits_start = 3 * size;
    let siblings_start = bits_start + upper_bits;
    let root = siblings_start + 16 * depth + 16 * (upper >> depth);
    let changed = (0..size)
        .map(|offset| 3 * offset + 2)
        .chain(bits_start..siblings_start)
        .chain((0..depth).map(|level| siblings_start + 16 * level + 7))
        .chain([root]);
    for changed in changed {
        let mut wrong = public.clone();
        wrong[changed] += F::ONE;
        assert!(
            !runs(&wrong),
            "log height {log_height}, arity {arity}, input {changed}"
        );
    }
    for (a, c) in [(0, 1), (size - 2, size - 1)] {
        let mut swapped = public.clone();
        for i in 0..3 {
            swapped.swap(3 * a + i, 3 * c + i);
        }
        assert!(!runs(&swapped), "leaves {a} and {c} swapped");
    }
}

#[test]
fn native_subtree_binds_every_leaf_its_order_and_the_upper_path() {
    for (log_height, arity, cap_height, upper) in
        [(5, 2, 1, 5), (4, 1, 0, 6), (3, 3, 0, 0), (4, 2, 2, 3)]
    {
        check_subtree::<BinaryField128>(log_height, arity, cap_height, upper);
        check_subtree::<Poly64>(log_height, arity, cap_height, upper);
    }
}

#[test]
fn native_tower_and_polynomial_mmcs_match_mixed_height_caps_and_zero_depth() {
    for words in [false, true] {
        for cap_height in [0, 1] {
            for index in 0..3 {
                check::<BinaryField128>(&[3, 2], cap_height, index, words);
                check::<Poly64>(&[3, 2], cap_height, index, words);
            }
        }
        check::<BinaryField128>(&[4], 2, 3, words);
        check::<Poly64>(&[4], 2, 3, words);
    }
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
