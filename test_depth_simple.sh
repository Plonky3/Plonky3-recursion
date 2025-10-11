#!/bin/bash
depth=$1
cat > /tmp/test_mmcs_trace.rs << 'EORUST'
use p3_baby_bear::BabyBear;
use p3_circuit::op::MmcsVerifyConfig;
use p3_circuit::tables::{MmcsPrivateData, MmcsTrace};
use p3_field::extension::BinomialExtensionField;
use p3_symmetric::PseudoCompressionFunction;
use p3_circuit::WitnessId;
use p3_mmcs_air::air::MmcsVerifyAir;

type F = BinomialExtensionField<BabyBear, 4>;

#[derive(Clone)]
struct MockCompression {}

impl PseudoCompressionFunction<[BabyBear; 8], 2> for MockCompression {
    fn compress(&self, input: [[BabyBear; 8]; 2]) -> [BabyBear; 8] {
        input[0]
    }
}

fn main() {
    let depth_str = std::env::args().nth(1).unwrap_or("6".to_string());
    let depth: usize = depth_str.parse().unwrap();
    
    let mmcs_config = MmcsVerifyConfig::babybear_quartic_extension_default();
    let compress = MockCompression {};

    let leaf_value = [F::ZERO; 8];
    let siblings: Vec<(Vec<F>, Option<Vec<F>>)> = (0..depth)
        .map(|i| {
            (
                vec![F::from_u64((i + 1) * 10); 8],
                if i % 2 == 0 {
                    None
                } else {
                    Some(vec![F::from_u64(i + 1); 8])
                },
            )
        })
        .collect();
    let directions: Vec<bool> = (0..depth).map(|i| i % 2 == 0).collect();

    let private_data = MmcsPrivateData::new(&compress, &mmcs_config, &leaf_value, &siblings, &directions).unwrap();
    let trace = private_data.to_trace(
        &mmcs_config,
        &[WitnessId(0); 8],
        &[WitnessId(0); 8],
        0,
    ).unwrap();
    
    println!("Depth: {}", depth);
    println!("Number of trace rows: {}", trace.left_values.len());
    println!("is_extra: {:?}", trace.is_extra);
    
    let mmcs_trace = MmcsTrace {
        mmcs_paths: vec![trace.clone()],
    };
    
    let config = mmcs_config.into();
    let matrix = MmcsVerifyAir::<BabyBear>::trace_to_matrix(&config, &mmcs_trace);
    println!("Matrix height: {}", matrix.height());
    println!("Expected rows (from trace): {} + 1 final = {}", trace.left_values.len(), trace.left_values.len() + 1);
}
EORUST

rustc --edition 2021 /tmp/test_mmcs_trace.rs -L target/release/deps \
    --extern p3_baby_bear=$(ls target/release/deps/libp3_baby_bear-*.rlib | head -1) \
    --extern p3_circuit=$(ls target/release/deps/libp3_circuit-*.rlib | head -1) \
    --extern p3_field=$(ls target/release/deps/libp3_field-*.rlib | head -1) \
    --extern p3_symmetric=$(ls target/release/deps/libp3_symmetric-*.rlib | head -1) \
    --extern p3_mmcs_air=$(ls target/release/deps/libp3_mmcs_air-*.rlib | head -1) \
    -o /tmp/test_mmcs_trace 2>/dev/null && /tmp/test_mmcs_trace $depth
