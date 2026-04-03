//! Debug helper — run with: cargo test -p p3-circuit-prover --test koala_poseidon_witness_debug -- --nocapture

use p3_circuit::builder::CircuitBuilder;
use p3_circuit::ops::poseidon2_perm::Poseidon2PermCallBase;
use p3_circuit::ops::{KoalaBearD1Width16, NpoTypeId, Poseidon2Config, generate_poseidon2_trace};
use p3_circuit::{Op, PreprocessedColumns};
use p3_circuit_prover::ConstraintProfile;
use p3_circuit_prover::batch_stark_prover::{Poseidon2Preprocessor, poseidon2_air_builders_d5};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::KoalaBearConfig;
use p3_field::extension::QuinticTrinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_koala_bear::KoalaBear;
use p3_symmetric::Permutation;

type EF5 = QuinticTrinomialExtensionField<KoalaBear>;

#[derive(Clone)]
struct LiftKoalaPermForQuinticCircuit(p3_koala_bear::Poseidon2KoalaBear<16>);

impl Permutation<[EF5; 16]> for LiftKoalaPermForQuinticCircuit {
    fn permute(&self, input: [EF5; 16]) -> [EF5; 16] {
        let bases = core::array::from_fn(|i| input[i].as_basis_coefficients_slice()[0]);
        let out_b = self.0.permute(bases);
        core::array::from_fn(|i| {
            EF5::from_basis_coefficients_slice(&[
                out_b[i],
                KoalaBear::ZERO,
                KoalaBear::ZERO,
                KoalaBear::ZERO,
                KoalaBear::ZERO,
            ])
            .expect("lift to EF5")
        })
    }
}

fn koala_ef5_lift(b: KoalaBear) -> EF5 {
    QuinticTrinomialExtensionField::<KoalaBear>::from_basis_coefficients_slice(&[
        b,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
    ])
    .expect("basis slice")
}

#[test]
fn debug_koala_quintic_poseidon_witness_ids() {
    const D: usize = 5;

    let inner_perm = p3_koala_bear::default_koalabear_poseidon2_16();
    let lift_perm = LiftKoalaPermForQuinticCircuit(inner_perm.clone());

    let mut sponge0 = [KoalaBear::ZERO; 16];
    sponge0[0] = KoalaBear::from_u64(11);
    sponge0[1] = KoalaBear::from_u64(13);
    let sponge_out = inner_perm.permute(sponge0);

    let mut builder = CircuitBuilder::<EF5>::new();
    builder.enable_poseidon2_perm_base::<KoalaBearD1Width16, _>(
        generate_poseidon2_trace::<EF5, KoalaBearD1Width16>,
        lift_perm,
    );

    let in_a = builder.public_input();
    let in_b = builder.public_input();
    let mut perm_inputs: [Option<_>; 16] = [None; 16];
    perm_inputs[0] = Some(in_a);
    perm_inputs[1] = Some(in_b);
    let (_pid, hash_outputs) = builder
        .add_poseidon2_perm_base(&Poseidon2PermCallBase {
            config: Poseidon2Config::KoalaBearD1Width16,
            new_start: true,
            inputs: perm_inputs,
            out_ctl: [true; 8],
            return_all_outputs: false,
        })
        .unwrap();
    let e0 = builder.public_input();
    let e1 = builder.public_input();
    let h0_diff = builder.sub(hash_outputs[0].unwrap(), e0);
    let h1_diff = builder.sub(hash_outputs[1].unwrap(), e1);
    builder.assert_zero(h0_diff);
    builder.assert_zero(h1_diff);

    let circuit = builder.build().unwrap();

    println!("--- ALU ops ---");
    for op in &circuit.ops {
        if let Op::Alu {
            kind, a, b, c, out, ..
        } = op
        {
            println!(
                "ALU {:?} a={} b={} c={:?} out={}",
                kind,
                a.0,
                b.0,
                c.map(|x| x.0),
                out.0
            );
        }
    }

    let npo_prep: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> = vec![Box::new(Poseidon2Preprocessor)];
    let air_builders = poseidon2_air_builders_d5::<KoalaBearConfig>();
    let (_, _primitive_columns, non_primitive_flat) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, D>(
            &circuit,
            &p3_circuit_prover::batch_stark_prover::TablePacking::default(),
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();

    let preprocessed_columns: PreprocessedColumns<EF5, D> =
        circuit.generate_preprocessed_columns::<D>().unwrap();

    println!("ext_reads (len {}):", preprocessed_columns.ext_reads.len());
    for (i, &c) in preprocessed_columns.ext_reads.iter().enumerate() {
        if c != 0 {
            println!("  wid {i}: {c}");
        }
    }

    let op_type = NpoTypeId::poseidon2_perm(Poseidon2Config::KoalaBearD1Width16);
    if let Some(flat) = non_primitive_flat.get(&op_type) {
        let row_w = p3_poseidon2_circuit_air::poseidon2_preprocessed_row_width(16, 8);
        println!(
            "poseidon committed prep: {} vals, row_w={row_w}",
            flat.len()
        );
        if flat.len() >= row_w {
            let o0_idx = 16 * 4;
            println!(
                "row0 output limb0 idx (base) = {:?}",
                flat[o0_idx].as_canonical_u64()
            );
            println!(
                "row0 output limb0 out_mult (base) = {:?}",
                flat[o0_idx + 1].as_canonical_u64()
            );
        }
    }

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[
            koala_ef5_lift(KoalaBear::from_u64(11)),
            koala_ef5_lift(KoalaBear::from_u64(13)),
            koala_ef5_lift(sponge_out[0]),
            koala_ef5_lift(sponge_out[1]),
        ])
        .unwrap();
    let traces = runner.run().unwrap();
    if let Some(pt) = traces
        .non_primitive_trace::<p3_circuit::ops::poseidon2_perm::trace::Poseidon2Trace<KoalaBear>>(
            &op_type,
        )
    {
        for (ri, row) in pt.operations.iter().enumerate() {
            println!("poseidon row {ri}: in_ctl={:?}", row.in_ctl);
            println!("  input_indices={:?}", row.input_indices);
            println!("  out_ctl={:?}", row.out_ctl);
            println!("  output_indices={:?}", row.output_indices);
        }
    }
}
