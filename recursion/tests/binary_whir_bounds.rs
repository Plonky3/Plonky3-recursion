//! Native binary grinding ceilings apply to derived WHIR difficulties.

use p3_binary_field::{BinaryField32, BinaryField128};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_circuit::ops::ByteHash;
use p3_recursion::pcs::binary::BinaryWhirVerifier;
use p3_recursion::verifier::VerificationError;
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_test_utils::binary_field_params::keccak;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};

#[test]
fn native_grinding_boundaries_use_the_base_alphabet_width() {
    macro_rules! check {
        ($field:ty, $limit:expr) => {{
            let make_config = |difficulty| {
                let config = WhirConfig::<BinaryField128, $field, keccak::LevelChallenger<$field>>::new_with_domain(
                        2,
                        ProtocolParameters {
                            security_level: 125 + difficulty, pow_bits: difficulty, round_log_inv_rates: vec![],
                            folding_factor: FoldingFactor::Constant(1),
                            soundness_type: SecurityAssumption::UniqueDecoding,
                            starting_log_inv_rate: 1,
                        },
                        &BinaryWhirDomain::<$field>::default(),
                    ).unwrap();
                assert_eq!(config.max_pow_bits(), difficulty);
                config
            };
            let protocol = OpeningProtocol::new(vec![TableSpec::new(
                TableShape::new(2, 1), vec![OpeningBatch::new(vec![0], vec![])],
            )]);
            let boundary = make_config($limit);
            BinaryWhirVerifier::<$field>::new(&boundary, protocol.clone(), VariableOrder::Prefix, ByteHash::Keccak256, 0).unwrap();
            let above = make_config($limit + 1);
            assert!(matches!(
                BinaryWhirVerifier::<$field>::new(&above, protocol, VariableOrder::Prefix, ByteHash::Keccak256, 0),
                Err(VerificationError::ResourceLimitExceeded {
                    component: "binary WHIR native grinding bits", actual, limit,
                }) if actual == $limit + 1 && limit == $limit
            ));
        }};
    }
    check!(BinaryField32, 24);
    check!(BinaryField128, 56);
}
