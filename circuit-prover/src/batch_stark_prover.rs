//! Multi-STARK table prover and verifier that unifies all circuit tables
//! into a single multi-proof using `p3-multi-stark`.
//!
//! API mirrors `MultiTableProver` with `prove_all_tables` and `verify_all_tables`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::Traces;
use p3_field::{BasedVectorSpace, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_mmcs_air::air::{MmcsTableConfig, MmcsVerifyAir};
use p3_multi_stark::{MultiProof, StarkGenericConfig as MSGC, StarkInstance, Val as MVal};
use thiserror::Error;
use tracing::instrument;

use crate::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
use crate::config::StarkField;
use crate::field_params::ExtractBinomialW;
use crate::prover::TablePacking;

/// Proof bundle and metadata for the unified multi-STARK proof across all circuit tables.
pub struct BatchStarkProof<SC>
where
    SC: MSGC,
{
    pub proof: MultiProof<SC>,
    // Metadata to re-construct AIRs on verifier side.
    pub table_packing: TablePacking,
    pub witness_rows: usize,
    pub constants_rows: usize,
    pub public_rows: usize,
    pub add_rows: usize,
    pub mul_rows: usize,
    pub mmcs_rows: usize,
    pub ext_degree: usize,
    pub w_binomial: Option<MVal<SC>>,
}

/// New prover that produces a single multi-STARK proof covering all circuit tables.
pub struct BatchStarkProver<SC>
where
    SC: MSGC,
{
    config: SC,
    table_packing: TablePacking,
    mmcs_config: MmcsTableConfig,
}

/// Errors for multi-stark table prover.
#[derive(Debug, Error)]
pub enum MultiStarkProverError {
    #[error("unsupported extension degree: {0} (supported: 1,2,4,6,8)")]
    UnsupportedDegree(usize),

    #[error("missing binomial parameter W for extension-field multiplication")]
    MissingWForExtension,

    #[error("verification failed: {0}")]
    Verify(String),
}

// Enum wrapper to allow heterogeneous table AIRs in a single multi-stark batch.
enum CircuitTableAir<F: Field, const D: usize> {
    Witness(WitnessAir<F, D>),
    Const(ConstAir<F, D>),
    Public(PublicAir<F, D>),
    Add(AddAir<F, D>),
    Mul(MulAir<F, D>),
    Mmcs(MmcsVerifyAir<F>),
}

impl<F: Field, const D: usize> BaseAir<F> for CircuitTableAir<F, D> {
    fn width(&self) -> usize {
        match self {
            Self::Witness(a) => a.width(),
            Self::Const(a) => a.width(),
            Self::Public(a) => a.width(),
            Self::Add(a) => a.width(),
            Self::Mul(a) => a.width(),
            Self::Mmcs(a) => a.width(),
        }
    }
}

impl<AB, const D: usize> Air<AB> for CircuitTableAir<AB::F, D>
where
    AB: AirBuilder,
    AB::F: p3_field::PrimeField,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Witness(a) => a.eval(builder),
            Self::Const(a) => a.eval(builder),
            Self::Public(a) => a.eval(builder),
            Self::Add(a) => a.eval(builder),
            Self::Mul(a) => a.eval(builder),
            Self::Mmcs(a) => a.eval(builder),
        }
    }
}

impl<SC> BatchStarkProver<SC>
where
    SC: MSGC,
    MVal<SC>: StarkField,
{
    pub fn new(config: SC) -> Self {
        Self {
            config,
            table_packing: TablePacking::default(),
            mmcs_config: MmcsTableConfig::default(),
        }
    }

    pub fn with_table_packing(mut self, table_packing: TablePacking) -> Self {
        self.table_packing = table_packing;
        self
    }

    pub fn with_mmcs_table(mut self, mmcs_config: MmcsTableConfig) -> Self {
        self.mmcs_config = mmcs_config;
        self
    }

    pub fn set_table_packing(&mut self, table_packing: TablePacking) {
        self.table_packing = table_packing;
    }

    pub const fn table_packing(&self) -> TablePacking {
        self.table_packing
    }

    /// Generate a unified multi-STARK proof for all circuit tables.
    #[instrument(skip_all)]
    pub fn prove_all_tables<EF>(
        &self,
        traces: &Traces<EF>,
    ) -> Result<BatchStarkProof<SC>, MultiStarkProverError>
    where
        EF: Field + BasedVectorSpace<MVal<SC>> + ExtractBinomialW<MVal<SC>>,
    {
        let w_opt = EF::extract_w();
        match EF::DIMENSION {
            1 => self.prove_for_degree::<EF, 1>(traces, None),
            2 => self.prove_for_degree::<EF, 2>(traces, w_opt),
            4 => self.prove_for_degree::<EF, 4>(traces, w_opt),
            6 => self.prove_for_degree::<EF, 6>(traces, w_opt),
            8 => self.prove_for_degree::<EF, 8>(traces, w_opt),
            d => Err(MultiStarkProverError::UnsupportedDegree(d)),
        }
    }

    /// Verify the unified multi-STARK proof against all tables.
    pub fn verify_all_tables(
        &self,
        proof: &BatchStarkProof<SC>,
    ) -> Result<(), MultiStarkProverError> {
        match proof.ext_degree {
            1 => self.verify_for_degree::<1>(proof, None),
            2 => self.verify_for_degree::<2>(proof, proof.w_binomial),
            4 => self.verify_for_degree::<4>(proof, proof.w_binomial),
            6 => self.verify_for_degree::<6>(proof, proof.w_binomial),
            8 => self.verify_for_degree::<8>(proof, proof.w_binomial),
            d => Err(MultiStarkProverError::UnsupportedDegree(d)),
        }
    }

    fn prove_for_degree<EF, const D: usize>(
        &self,
        traces: &Traces<EF>,
        w_binomial: Option<MVal<SC>>,
    ) -> Result<BatchStarkProof<SC>, MultiStarkProverError>
    where
        EF: Field + BasedVectorSpace<MVal<SC>>,
    {
        // Build matrices and AIRs per table.
        let packing = self.table_packing;
        let add_lanes = packing.add_lanes();
        let mul_lanes = packing.mul_lanes();

        // Witness
        let witness_rows = traces.witness_trace.values.len();
        let witness_air = WitnessAir::<MVal<SC>, D>::new(witness_rows);
        let witness_matrix: RowMajorMatrix<MVal<SC>> =
            WitnessAir::<MVal<SC>, D>::trace_to_matrix(&traces.witness_trace);

        // Const
        let constants_rows = traces.const_trace.values.len();
        let const_air = ConstAir::<MVal<SC>, D>::new(constants_rows);
        let const_matrix: RowMajorMatrix<MVal<SC>> =
            ConstAir::<MVal<SC>, D>::trace_to_matrix(&traces.const_trace);

        // Public
        let public_rows = traces.public_trace.values.len();
        let public_air = PublicAir::<MVal<SC>, D>::new(public_rows);
        let public_matrix: RowMajorMatrix<MVal<SC>> =
            PublicAir::<MVal<SC>, D>::trace_to_matrix(&traces.public_trace);

        // Add
        let add_rows = traces.add_trace.lhs_values.len();
        let add_air = AddAir::<MVal<SC>, D>::new(add_rows, add_lanes);
        let add_matrix: RowMajorMatrix<MVal<SC>> =
            AddAir::<MVal<SC>, D>::trace_to_matrix(&traces.add_trace, add_lanes);

        // Mul
        let mul_rows = traces.mul_trace.lhs_values.len();
        let mul_air: MulAir<MVal<SC>, D> = if D == 1 {
            MulAir::<MVal<SC>, D>::new(mul_rows, mul_lanes)
        } else {
            let w = w_binomial.ok_or(MultiStarkProverError::MissingWForExtension)?;
            MulAir::<MVal<SC>, D>::new_binomial(mul_rows, mul_lanes, w)
        };
        let mul_matrix: RowMajorMatrix<MVal<SC>> =
            MulAir::<MVal<SC>, D>::trace_to_matrix(&traces.mul_trace, mul_lanes);

        // Mmcs
        let mmcs_air = MmcsVerifyAir::<MVal<SC>>::new(self.mmcs_config);
        let mmcs_matrix: RowMajorMatrix<MVal<SC>> =
            MmcsVerifyAir::trace_to_matrix(&self.mmcs_config, &traces.mmcs_trace);
        let mmcs_rows: usize = mmcs_matrix.height();

        // Wrap AIRs in enum for heterogenous batching and build instances in fixed order.
        let air_witness = CircuitTableAir::Witness(witness_air);
        let air_const = CircuitTableAir::Const(const_air);
        let air_public = CircuitTableAir::Public(public_air);
        let air_add = CircuitTableAir::Add(add_air);
        let air_mul = CircuitTableAir::Mul(mul_air);
        let air_mmcs = CircuitTableAir::Mmcs(mmcs_air);

        let instances: Vec<StarkInstance<'_, SC, CircuitTableAir<MVal<SC>, D>>> = vec![
            StarkInstance {
                air: &air_witness,
                trace: witness_matrix,
                public_values: vec![],
            },
            StarkInstance {
                air: &air_const,
                trace: const_matrix,
                public_values: vec![],
            },
            StarkInstance {
                air: &air_public,
                trace: public_matrix,
                public_values: vec![],
            },
            StarkInstance {
                air: &air_add,
                trace: add_matrix,
                public_values: vec![],
            },
            StarkInstance {
                air: &air_mul,
                trace: mul_matrix,
                public_values: vec![],
            },
            StarkInstance {
                air: &air_mmcs,
                trace: mmcs_matrix,
                public_values: vec![],
            },
        ];

        let proof = p3_multi_stark::prove_multi(&self.config, instances);

        Ok(BatchStarkProof {
            proof,
            table_packing: packing,
            witness_rows,
            constants_rows,
            public_rows,
            add_rows,
            mul_rows,
            mmcs_rows,
            ext_degree: D,
            w_binomial: if D > 1 { w_binomial } else { None },
        })
    }

    fn verify_for_degree<const D: usize>(
        &self,
        proof: &BatchStarkProof<SC>,
        w_binomial: Option<MVal<SC>>,
    ) -> Result<(), MultiStarkProverError> {
        // Rebuild AIRs in the same order as prove.
        let packing = proof.table_packing;
        let add_lanes = packing.add_lanes();
        let mul_lanes = packing.mul_lanes();

        let witness_air =
            CircuitTableAir::Witness(WitnessAir::<MVal<SC>, D>::new(proof.witness_rows));
        let const_air = CircuitTableAir::Const(ConstAir::<MVal<SC>, D>::new(proof.constants_rows));
        let public_air = CircuitTableAir::Public(PublicAir::<MVal<SC>, D>::new(proof.public_rows));
        let add_air = CircuitTableAir::Add(AddAir::<MVal<SC>, D>::new(proof.add_rows, add_lanes));
        let mul_air: CircuitTableAir<MVal<SC>, D> = if D == 1 {
            CircuitTableAir::Mul(MulAir::<MVal<SC>, D>::new(proof.mul_rows, mul_lanes))
        } else {
            let w = w_binomial.ok_or(MultiStarkProverError::MissingWForExtension)?;
            CircuitTableAir::Mul(MulAir::<MVal<SC>, D>::new_binomial(
                proof.mul_rows,
                mul_lanes,
                w,
            ))
        };
        let mmcs_air = CircuitTableAir::Mmcs(MmcsVerifyAir::<MVal<SC>>::new(self.mmcs_config));

        let airs = vec![
            witness_air,
            const_air,
            public_air,
            add_air,
            mul_air,
            mmcs_air,
        ];
        // All instances use empty public values in this design.
        let pvs: Vec<Vec<MVal<SC>>> = vec![Vec::new(); airs.len()];

        p3_multi_stark::verify_multi(&self.config, &airs, &proof.proof, &pvs)
            .map_err(|e| MultiStarkProverError::Verify(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_circuit::builder::CircuitBuilder;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_goldilocks::Goldilocks;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::config;

    #[test]
    fn test_babybear_multi_stark_base_field() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // x + 5*2 - 3 + (-1) == expected
        let x = builder.add_public_input();
        let expected = builder.add_public_input();
        let c5 = builder.add_const(BabyBear::from_u64(5));
        let c2 = builder.add_const(BabyBear::from_u64(2));
        let c3 = builder.add_const(BabyBear::from_u64(3));
        let neg_one = builder.add_const(BabyBear::NEG_ONE);

        let mul_result = builder.mul(c5, c2); // 10
        let add_result = builder.add(x, mul_result); // x + 10
        let sub_result = builder.sub(add_result, c3); // x + 7
        let final_result = builder.add(sub_result, neg_one); // x + 6

        let diff = builder.sub(final_result, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        let x_val = BabyBear::from_u64(7);
        let expected_val = BabyBear::from_u64(13); // 7 + 10 - 3 - 1 = 13
        runner.set_public_inputs(&[x_val, expected_val]).unwrap();
        let traces = runner.run().unwrap();

        let cfg = config::baby_bear().build();
        let prover = BatchStarkProver::new(cfg);
        let proof = prover.prove_all_tables(&traces).unwrap();
        assert_eq!(proof.ext_degree, 1);
        assert!(proof.w_binomial.is_none());
        prover.verify_all_tables(&proof).unwrap();
    }

    #[test]
    fn test_extension_field_multi_stark() {
        type Ext4 = BinomialExtensionField<BabyBear, 4>;
        let mut builder = CircuitBuilder::<Ext4>::new();
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();
        let expected = builder.add_public_input();
        let xy = builder.mul(x, y);
        let res = builder.add(xy, z);
        let diff = builder.sub(res, expected);
        builder.assert_zero(diff);
        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        let xv = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(2),
            BabyBear::from_u64(3),
            BabyBear::from_u64(5),
            BabyBear::from_u64(7),
        ])
        .unwrap();
        let yv = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(11),
            BabyBear::from_u64(13),
            BabyBear::from_u64(17),
            BabyBear::from_u64(19),
        ])
        .unwrap();
        let zv = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(23),
            BabyBear::from_u64(29),
            BabyBear::from_u64(31),
            BabyBear::from_u64(37),
        ])
        .unwrap();
        let expected_v = xv * yv + zv;
        runner.set_public_inputs(&[xv, yv, zv, expected_v]).unwrap();
        let traces = runner.run().unwrap();

        let cfg = config::baby_bear().build();
        let prover = BatchStarkProver::new(cfg);
        let proof = prover.prove_all_tables(&traces).unwrap();
        assert_eq!(proof.ext_degree, 4);
        // Ensure W was captured
        let expected_w = <Ext4 as ExtractBinomialW<BabyBear>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));
        prover.verify_all_tables(&proof).unwrap();
    }

    #[test]
    fn test_koalabear_multi_stark_base_field() {
        let mut builder = CircuitBuilder::<KoalaBear>::new();

        // a * b + 100 - (-1) == expected
        let a = builder.add_public_input();
        let b = builder.add_public_input();
        let expected = builder.add_public_input();
        let c = builder.add_const(KoalaBear::from_u64(100));
        let d = builder.add_const(KoalaBear::NEG_ONE);

        let ab = builder.mul(a, b);
        let add = builder.add(ab, c);
        let final_res = builder.sub(add, d);
        let diff = builder.sub(final_res, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        let a_val = KoalaBear::from_u64(42);
        let b_val = KoalaBear::from_u64(13);
        let expected_val = KoalaBear::from_u64(647); // 42*13 + 100 - (-1)
        runner
            .set_public_inputs(&[a_val, b_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        let cfg = config::koala_bear().build();
        let prover = BatchStarkProver::new(cfg);
        let proof = prover.prove_all_tables(&traces).unwrap();
        assert_eq!(proof.ext_degree, 1);
        assert!(proof.w_binomial.is_none());
        prover.verify_all_tables(&proof).unwrap();
    }

    #[test]
    fn test_koalabear_multi_stark_extension_field_d8() {
        type KBExtField = BinomialExtensionField<KoalaBear, 8>;
        let mut builder = CircuitBuilder::<KBExtField>::new();

        // x * y * z == expected
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let expected = builder.add_public_input();
        let z = builder.add_const(
            KBExtField::from_basis_coefficients_slice(&[
                KoalaBear::from_u64(1),
                KoalaBear::NEG_ONE,
                KoalaBear::from_u64(2),
                KoalaBear::from_u64(3),
                KoalaBear::from_u64(4),
                KoalaBear::from_u64(5),
                KoalaBear::from_u64(6),
                KoalaBear::from_u64(7),
            ])
            .unwrap(),
        );

        let xy = builder.mul(x, y);
        let xyz = builder.mul(xy, z);
        let diff = builder.sub(xyz, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        let x_val = KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(4),
            KoalaBear::from_u64(6),
            KoalaBear::from_u64(8),
            KoalaBear::from_u64(10),
            KoalaBear::from_u64(12),
            KoalaBear::from_u64(14),
            KoalaBear::from_u64(16),
            KoalaBear::from_u64(18),
        ])
        .unwrap();
        let y_val = KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(12),
            KoalaBear::from_u64(14),
            KoalaBear::from_u64(16),
            KoalaBear::from_u64(18),
            KoalaBear::from_u64(20),
            KoalaBear::from_u64(22),
            KoalaBear::from_u64(24),
            KoalaBear::from_u64(26),
        ])
        .unwrap();
        let z_val = KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(1),
            KoalaBear::NEG_ONE,
            KoalaBear::from_u64(2),
            KoalaBear::from_u64(3),
            KoalaBear::from_u64(4),
            KoalaBear::from_u64(5),
            KoalaBear::from_u64(6),
            KoalaBear::from_u64(7),
        ])
        .unwrap();

        let expected_val = x_val * y_val * z_val;
        runner
            .set_public_inputs(&[x_val, y_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        let cfg = config::koala_bear().build();
        let prover = BatchStarkProver::new(cfg);
        let proof = prover.prove_all_tables(&traces).unwrap();
        assert_eq!(proof.ext_degree, 8);
        let expected_w = <KBExtField as ExtractBinomialW<KoalaBear>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));
        prover.verify_all_tables(&proof).unwrap();
    }

    #[test]
    fn test_goldilocks_multi_stark_extension_field_d2() {
        type Ext2 = BinomialExtensionField<Goldilocks, 2>;
        let mut builder = CircuitBuilder::<Ext2>::new();

        // x * y + z == expected
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();
        let expected = builder.add_public_input();

        let xy = builder.mul(x, y);
        let res = builder.add(xy, z);
        let diff = builder.sub(res, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        let x_val =
            Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(3), Goldilocks::NEG_ONE])
                .unwrap();
        let y_val = Ext2::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(7),
            Goldilocks::from_u64(11),
        ])
        .unwrap();
        let z_val = Ext2::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(13),
            Goldilocks::from_u64(17),
        ])
        .unwrap();
        let expected_val = x_val * y_val + z_val;

        runner
            .set_public_inputs(&[x_val, y_val, z_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        let cfg = config::goldilocks().build();
        let prover = BatchStarkProver::new(cfg);
        let proof = prover.prove_all_tables(&traces).unwrap();
        assert_eq!(proof.ext_degree, 2);
        let expected_w = <Ext2 as ExtractBinomialW<Goldilocks>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));
        prover.verify_all_tables(&proof).unwrap();
    }
}
