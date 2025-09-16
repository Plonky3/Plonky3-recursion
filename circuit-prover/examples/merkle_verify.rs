use std::env;

/// Fake Merkle verification circuit: Prove knowledge of a leaf in a Merkle tree
/// Public inputs: leaf_hash, expected_root
/// Private inputs: merkle path (siblings + directions)
use p3_baby_bear::BabyBear;
use p3_circuit::NonPrimitiveOpPrivateData;
use p3_circuit::builder::CircuitBuilder;
use p3_circuit_prover::MultiTableProver;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_keccak::KeccakF;
use p3_merkle_tree_air::cols::MerklePrivateData;
use p3_merkle_tree_air::compress::FieldCompression;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge};

type F = BinomialExtensionField<BabyBear, 4>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
    type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;

    let u64_hash = U64Hash::new(KeccakF {});

    let compress = MyCompress::new(u64_hash);

    let depth = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);

    let mut builder = CircuitBuilder::<F>::new();

    // Public inputs: leaf hash and expected root hash
    let leaf_hash = builder.add_public_input();
    let expected_root = builder.add_public_input();

    // Add fake Merkle verification operation
    // This declares that leaf_hash and expected_root are connected to witness bus
    // The AIR constraints will verify the Merkle path is valid
    let merkle_op_id = builder.add_merkle_verify(leaf_hash, expected_root);

    let circuit = builder.build();
    let mut runner = circuit.runner();

    // Set public inputs
    let leaf_value = F::from_u64(42); // Our leaf value
    let siblings: Vec<(Vec<F>, Option<Vec<F>>)> = (0..depth)
        .map(|i| {
            (
                vec![F::from_u64((i + 1) * 10)],
                if i % 2 == 0 {
                    None
                } else {
                    Some(vec![F::from_u64(i + 1)])
                },
            )
        })
        .collect();
    let directions: Vec<bool> = (0..depth).map(|i| i % 2 == 0).collect();
    let expected_root_value =
        compute_merkle_root(&compress, &vec![leaf_value], &siblings, &directions);
    runner.set_public_inputs(&[leaf_value, expected_root_value[0]])?;

    // Set private Merkle path data
    runner.set_complex_op_private_data(
        merkle_op_id,
        NonPrimitiveOpPrivateData::MerkleVerify(MerklePrivateData {
            path_siblings: siblings,
            path_directions: directions,
        }),
    )?;

    let traces = runner.run()?;
    let multi_prover = MultiTableProver::new();
    let proof = multi_prover.prove_all_tables(&traces)?;
    multi_prover.verify_all_tables(&proof)?;

    println!(
        "✅ Verified Merkle path for leaf {leaf_value} with depth {depth} → root {:?}",
        expected_root_value[0]
    );

    Ok(())
}

pub type Hash = [BabyBear; 4];
pub type EF = BinomialExtensionField<BabyBear, 4>;

/// Simulate classical Merkle root computation for testing
fn compute_merkle_root<C: FieldCompression<BabyBear, EF, 4, 2, 1>>(
    compress: &C,
    leaf: &Vec<F>,
    siblings: &Vec<(Vec<F>, Option<Vec<F>>)>,
    directions: &Vec<bool>,
) -> Vec<EF> {
    directions.iter().zip(siblings.iter()).fold(
        leaf.clone(),
        |state, (direction, (sibling, other_sibling))| {
            let (left, right) = if *direction {
                (state.clone(), sibling.clone())
            } else {
                (sibling.clone(), state.clone())
            };
            let mut new_state = compress.compress_field([
                left.try_into().expect("Size is 1"),
                right.try_into().expect("Size is 1"),
            ]);
            if let Some(other_sibling) = other_sibling {
                new_state = compress.compress_field([
                    state.try_into().expect("Size is one"),
                    other_sibling.clone().try_into().expect("Size is one"),
                ]);
            }
            new_state.to_vec()
        },
    )
}
