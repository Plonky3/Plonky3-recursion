//! A forged sixteen-bit limb with its seventeenth coordinate lifted into a BLAKE3 block word.

use core::borrow::Borrow;

use p3_binary_pcs::BooleanTraceCommitmentError;
use p3_blake3::Blake3;
use p3_blake3_air::{Blake3BinaryCols, NUM_BLAKE3_BINARY_COLS};
use p3_circuit_prover::native_bus::KeccakCommitment;
use p3_multi_stark::ProvingError;
use p3_multi_stark::zerocheck::ZerocheckError;
use p3_symmetric::CryptographicHasher;
use p3_whir::WhirConfigError;

use super::blake3_chain::raw;
use super::forged_limb::{patch_witness_cells, replay};
use super::keccak_chain::native_bus;
use super::*;
use crate::artifact::binary_native::MixedWhirError;

const LIMBS: usize = 40;
/// The forged limb is limb 3 of the second block, which holds limbs 32 to 39.
const FORGED_LIMB: usize = 35;
const SECOND_BLOCK: usize = 1;

/// The column of `cell` in a row of the BLAKE3 table.
fn column(cell: impl Fn(&Blake3BinaryCols<usize>) -> usize) -> usize {
    let indices: Vec<usize> = (0..NUM_BLAKE3_BINARY_COLS).collect();
    cell(indices.as_slice().borrow())
}

/// The bit `t` of limb `FORGED_LIMB`, a bit of the second block's word 1 above its low half.
fn forged_bit(t: usize) -> usize {
    column(|cols| cols.block[(FORGED_LIMB - 32) / 2][16 + t])
}

/// A message limb is a block input, read by no gate. A limb with a seventeenth coordinate
/// passes the fanout rows. The BLAKE3 table's bits cannot carry it, so the witness bus refuses
/// the traces in both modes. Lifting the limb's lowest bit to carry it balances the bus and
/// leaves a cell outside {0, 1}: under the dense commitment the traces prove and the zerocheck
/// refuses the proof; under the bit commitment the commitment refuses the cell before the
/// transcript moves.
#[test]
fn forged_sixteen_bit_limb_is_refused_in_both_modes() {
    let limbs: Vec<u16> = (0..LIMBS as u16)
        .map(|i| i.wrapping_mul(0x9e37) ^ 0x5a5a)
        .collect();
    let bytes: Vec<u8> = limbs.iter().flat_map(|limb| limb.to_le_bytes()).collect();
    let digest = Blake3.hash_iter(bytes.iter().copied());

    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let expected = b.alloc_public_input_array::<16>("digest");
    let message = b.alloc_private_inputs(LIMBS, "message limbs");
    let actual = b.native_blake3_words(&message).unwrap();
    for (&limb, &expected) in actual.iter().zip(&expected) {
        b.connect(limb, expected);
    }
    let circuit = b.build().unwrap();
    let statement: Vec<F> = bytes_to_limbs(&digest).into_iter().map(raw).collect();
    let private: Vec<F> = limbs.iter().map(|&limb| raw(limb)).collect();

    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&private).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest: Vec<F> = witness
        .index
        .iter()
        .map(|&id| *witness.get_value(id).unwrap())
        .collect();
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    let mut forged_private = private.clone();
    forged_private[FORGED_LIMB] += wide;
    let mut refusing = circuit.runner();
    refusing.set_public_inputs(&statement).unwrap();
    refusing.set_private_inputs(&forged_private).unwrap();
    assert!(refusing.run().is_err(), "the runner refuses a wide limb");
    let forged = replay(&circuit, &honest, &statement, &forged_private);

    let bits = native_bus(&circuit, KeccakCommitment::Bits);
    let dense = native_bus(&circuit, KeccakCommitment::Dense);
    let table = bits.packed_table_index().unwrap();
    let public = bits.public_values(&statement).unwrap();
    let mut traces = bits.traces(&witness).unwrap();
    let [fanout, gates, bridge] = patch_witness_cells(bits.airs(), &mut traces, &honest, &forged);
    assert!(fanout > 0 && gates == 0 && bridge == 0);
    assert_eq!(traces[table].width, NUM_BLAKE3_BINARY_COLS);
    let forged_tables = |traces: &[RowMajorMatrix<F>]| {
        traces
            .iter()
            .map(|trace| Table::new(trace.clone().transpose()))
            .collect::<Vec<_>>()
    };
    // The dense proof of `traces`: the prover's refusal, or the verifier's verdict.
    let dense_attempt = |traces: &[RowMajorMatrix<F>]| {
        let config = Parameters::new(dense.airs(), dense.log_heights(), None).config();
        let airs = dense.airs().iter().collect::<Vec<_>>();
        let (proving, verifying) = setup(&config, &airs, &mut challenger()).unwrap();
        let proof = prove(
            &config,
            ProverInstances::new(
                airs.iter()
                    .zip(forged_tables(traces))
                    .zip(&public)
                    .map(|((air, table), public)| {
                        ProverInstance::new(*air, table, &proving, public)
                    })
                    .collect(),
            ),
            0,
            &mut challenger(),
        )?;
        Ok::<_, ProvingError<_>>(verify(
            &config,
            VerifierInstances::new(
                airs.iter()
                    .zip(dense.log_heights())
                    .zip(&public)
                    .map(|((air, &height), public)| {
                        VerifierInstance::new(*air, &verifying, height, public)
                    })
                    .collect(),
            ),
            &proof,
            0,
            &mut challenger(),
        ))
    };

    // The honest table cannot carry the wide limb: the prover refuses the unbalanced bus.
    assert!(dense_attempt(&traces).is_err());

    // Lifting the limb's lowest bit balances the bus, and the cell is no longer a bit.
    let cell = SECOND_BLOCK * NUM_BLAKE3_BINARY_COLS + forged_bit(0);
    let packed = (0..16).fold(F::ZERO, |sum, t| {
        let bit = traces[table].values[SECOND_BLOCK * NUM_BLAKE3_BINARY_COLS + forged_bit(t)];
        assert!(bit == F::ZERO || bit == F::ONE);
        sum + bit * raw(1 << t)
    });
    assert_eq!(packed, raw(limbs[FORGED_LIMB]));
    traces[table].values[cell] += wide;
    let verified = dense_attempt(&traces);
    assert!(
        matches!(
            verified,
            Ok(Err(p3_multi_stark::VerificationError::Zerocheck(
                ZerocheckError::FinalSumMismatch
            )))
        ),
        "{verified:?}"
    );

    let config = Parameters::new(bits.airs(), bits.log_heights(), Some(table)).config();
    let refused = |error: &MixedWhirError<WhirConfigError>| {
        matches!(
            error,
            MixedWhirError::Packed(BooleanTraceCommitmentError::NonBooleanCell { table: t, column: c })
                if *t == table && *c == forged_bit(0)
        )
    };
    let mut moved = challenger();
    let mut untouched = moved.clone();
    assert!(refused(
        &config
            .main
            .commit(forged_tables(&traces), &mut moved)
            .err()
            .unwrap()
    ));
    assert_eq!(
        moved.sample_algebra_element::<F>(),
        untouched.sample_algebra_element::<F>()
    );
    let airs = bits.airs().iter().collect::<Vec<_>>();
    let (proving, _) = setup(&config, &airs, &mut challenger()).unwrap();
    let proven = prove(
        &config,
        ProverInstances::new(
            airs.iter()
                .zip(forged_tables(&traces))
                .zip(&public)
                .map(|((air, table), public)| ProverInstance::new(*air, table, &proving, public))
                .collect(),
        ),
        0,
        &mut challenger(),
    );
    assert!(matches!(proven, Err(ProvingError::Pcs { ref source, .. }) if refused(source)));
}
