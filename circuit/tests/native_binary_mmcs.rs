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
/// Word leaves are four-byte rows given as two low-first sixteen-bit words.
fn check_subtree<F: BinaryCoordinateField>(
    log_height: usize,
    arity: usize,
    cap_height: usize,
    upper: usize,
    words: bool,
) {
    let mmcs = keccak::LevelMmcs::<BinaryField8>::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        cap_height,
    );
    let row_bytes = if words { 4 } else { 3 };
    let leaf_inputs = if words { 2 } else { 3 };
    let matrix = RowMajorMatrix::new(
        (0..row_bytes << log_height)
            .map(|i| BinaryField8::from_repr((i * 37 + 129) as u8))
            .collect(),
        row_bytes,
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
    let leaves: Vec<_> = (0..size).map(|_| inputs(leaf_inputs)).collect();
    let bits = inputs(upper_bits);
    let siblings: Vec<_> = (0..depth).map(|_| inputs(16)).collect();
    let cap: Vec<_> = (0..1 << cap_height).map(|_| inputs(16)).collect();
    if words {
        b.verify_byte_hash_mmcs_subtree_words_with_host::<NativeBinaryEncoding>(
            ByteHash::Keccak256,
            &leaves,
            1 << log_height,
            &bits,
            &siblings,
            &cap,
        )
    } else {
        b.verify_byte_hash_mmcs_subtree_bytes_with_host::<NativeBinaryEncoding>(
            ByteHash::Keccak256,
            &leaves,
            1 << log_height,
            &bits,
            &siblings,
            &cap,
        )
    }
    .unwrap();
    let circuit = b.build().unwrap();
    let encode = |word: u16| -> F { NativeBinaryEncoding::encode_u16(word).unwrap() };
    let mut public: Vec<F> = Vec::new();
    for opening in &openings {
        let row: Vec<u8> = opening.opened_values[0]
            .iter()
            .map(|x| x.to_repr())
            .collect();
        if words {
            public.extend(bytes_to_limbs(&row).into_iter().map(encode));
        } else {
            public.extend(row.into_iter().map(|byte| encode(u16::from(byte))));
        }
    }
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
    let bits_start = leaf_inputs * size;
    let siblings_start = bits_start + upper_bits;
    let root = siblings_start + 16 * depth + 16 * (upper >> depth);
    let changed = (0..size)
        .map(|offset| leaf_inputs * offset + leaf_inputs - 1)
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
        for i in 0..leaf_inputs {
            swapped.swap(leaf_inputs * a + i, leaf_inputs * c + i);
        }
        assert!(!runs(&swapped), "leaves {a} and {c} swapped");
    }
    if words {
        // A word with a seventeenth coordinate is not a leaf serialization.
        let mut wide = public.clone();
        wide[0] += F::from_raw_coordinates(1 << 16).unwrap();
        assert!(!runs(&wide), "leaf word above sixteen coordinates");
    }
}

#[test]
fn native_subtree_binds_every_leaf_its_order_and_the_upper_path() {
    for (log_height, arity, cap_height, upper) in
        [(5, 2, 1, 5), (4, 1, 0, 6), (3, 3, 0, 0), (4, 2, 2, 3)]
    {
        for words in [false, true] {
            check_subtree::<BinaryField128>(log_height, arity, cap_height, upper, words);
            check_subtree::<Poly64>(log_height, arity, cap_height, upper, words);
        }
    }
}

/// Authenticates row `index` of a width-16 `BinaryField128` p3 tree as one
/// word leaf: the 256 bytes of a Tower128 fold coset, 128 words absorbed over
/// two Keccak-f calls. Lanes are given in ascending order, as p3 serializes
/// the row, and the reversed order must be rejected. With an empty path the
/// index bits only drive the cap multiplexer, so every flipped bit and a
/// tampered selected root must be rejected while a tampered unselected root
/// must still be accepted.
fn check_coset_leaf<F: BinaryCoordinateField>(log_height: usize, cap_height: usize, index: usize) {
    const LANES: usize = 16;
    const WORDS: usize = LANES * 8;
    let mmcs = keccak::LevelMmcs::<BinaryField128>::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        cap_height,
    );
    let matrix = RowMajorMatrix::new(
        (0..LANES << log_height)
            .map(|i| {
                BinaryField128::from_repr(
                    (i as u128 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835),
                )
            })
            .collect(),
        LANES,
    );
    let (commitment, data) = mmcs.commit(vec![matrix]);
    let opening = mmcs.open_batch(index, &data);
    let depth = log_height - cap_height;
    assert_eq!(opening.opening_proof.len(), depth);
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let mut inputs = |count| (0..count).map(|_| b.public_input()).collect::<Vec<_>>();
    let leaf = inputs(WORDS);
    let bits = inputs(log_height);
    let siblings: Vec<_> = (0..depth).map(|_| inputs(16)).collect();
    let cap: Vec<_> = (0..1 << cap_height).map(|_| inputs(16)).collect();
    b.verify_byte_hash_mmcs_subtree_words_with_host::<NativeBinaryEncoding>(
        ByteHash::Keccak256,
        &[leaf],
        1 << log_height,
        &bits,
        &siblings,
        &cap,
    )
    .unwrap();
    let circuit = b.build().unwrap();
    let encode = |word: u16| -> F { NativeBinaryEncoding::encode_u16(word).unwrap() };
    let lane_words = |lanes: &mut dyn Iterator<Item = &BinaryField128>| -> Vec<F> {
        let bytes: Vec<u8> = lanes.flat_map(|x| x.to_repr().to_le_bytes()).collect();
        bytes_to_limbs(&bytes).into_iter().map(encode).collect()
    };
    let lanes = &opening.opened_values[0];
    let mut public = lane_words(&mut lanes.iter());
    public.extend((0..log_height).map(|bit| F::from_bool(index >> bit & 1 != 0)));
    for digest in opening.opening_proof.iter().chain(commitment.roots()) {
        public.extend(bytes_to_limbs(digest).into_iter().map(encode));
    }
    let runs = |public: &[F]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    let label = format!("log height {log_height}, cap height {cap_height}, index {index}");
    assert!(runs(&public), "honest coset leaf, {label}");
    let mut reversed = lane_words(&mut lanes.iter().rev());
    reversed.extend_from_slice(&public[WORDS..]);
    assert!(!runs(&reversed), "reversed lanes, {label}");
    if depth > 0 {
        return;
    }
    for bit in 0..log_height {
        let mut wrong = public.clone();
        wrong[WORDS + bit] += F::ONE;
        assert!(!runs(&wrong), "flipped index bit {bit}, {label}");
    }
    let cap_start = WORDS + log_height;
    for root in 0..1 << cap_height {
        let mut wrong = public.clone();
        wrong[cap_start + 16 * root + 5] += F::ONE;
        assert_eq!(
            runs(&wrong),
            root != index,
            "tampered cap root {root}, {label}"
        );
    }
}

#[test]
fn single_coset_leaf_layout_matches_a_p3_tree_through_the_cap_multiplexer() {
    for (log_height, cap_height, index) in [(3, 3, 5), (2, 2, 2), (3, 0, 5)] {
        check_coset_leaf::<BinaryField128>(log_height, cap_height, index);
        check_coset_leaf::<Poly64>(log_height, cap_height, index);
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
fn malformed_subtree_leaf_counts_return_errors_without_panicking() {
    // Three leaves under a 4-root cap, and four leaves over six rows: every
    // other shape fits the reduced tree, so only the leaf-count check rejects.
    for (count, height, bits, roots) in [(3, 12, 2, 4), (4, 6, 0, 1)] {
        let mut b = CircuitBuilder::<BinaryField128>::new();
        b.enable_native_keccak_f1600().unwrap();
        let leaves: Vec<_> = (0..count).map(|_| vec![b.public_input()]).collect();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b.verify_byte_hash_mmcs_subtree_bytes_with_host::<NativeBinaryEncoding>(
                ByteHash::Keccak256,
                &leaves,
                height,
                &vec![ExprId::ZERO; bits],
                &[],
                &vec![vec![ExprId::ZERO; 16]; roots],
            )
        }));
        assert!(
            result.is_ok(),
            "{count} leaves of {height} rows must not panic"
        );
        assert!(result.unwrap().is_err(), "{count} leaves of {height} rows");
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
