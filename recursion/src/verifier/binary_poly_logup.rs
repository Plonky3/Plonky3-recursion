//! Trusted Poly64/Poly192 indexed-lookup reductions with unauthenticated PCS claims.

use alloc::vec::Vec;
use core::cmp::Reverse;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::BinaryPoly192Target;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_multi_stark::logup_star::transcript::{LogupStarShape, LogupStarTableShape};
use p3_multi_stark::logup_star::{LogupStarOutput, LogupStarProof, TableLookup, TableOutput};
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;

use super::{
    BinaryPolyFractionGkrInputShape, BinaryPolyFractionGkrProofTargets,
    BinaryPolyFractionGkrVerifier, InputResourceUsage, NativeBinaryPolyFractionGkrInput,
    VerificationError, VerifierLimits,
};
use crate::BinaryTower128Challenger;
use crate::pcs::binary::{
    BinaryPolyGenericSumcheckInputShape, BinaryPolyGenericSumcheckProofTargets,
    BinaryPolyGenericSumcheckVerifier, BinaryPolyNonzeroChallengePlan,
    NativeBinaryPolyGenericSumcheckInput, poly_assert_equal, poly_eval_multilinear,
    poly_observe_seed, poly_observe_values, poly192_eq_eval,
};
use crate::transcript::domain_separator_seed;

/// The surrounding protocol must derive each point after committing the
/// reader's trace and authenticate these payload claims at that point.
#[derive(Clone, Debug)]
pub struct BinaryPolyLogupStarReaderTargets {
    pub point: Vec<BinaryPoly192Target>,
    pub claims: Vec<BinaryPoly192Target>,
}

#[derive(Clone, Debug)]
pub struct BinaryPolyLogupStarProofTargets {
    pub pushforwards: Vec<Vec<BinaryPoly192Target>>,
    pub fraction_gkr: BinaryPolyFractionGkrProofTargets,
    pub position_claims: Vec<BinaryPoly192Target>,
    pub product: BinaryPolyGenericSumcheckProofTargets,
    pub column_claims: Vec<Vec<BinaryPoly192Target>>,
}

#[derive(Clone, Debug)]
pub struct BinaryPolyLogupStarTableOutput {
    pub column_claims: Vec<BinaryPoly192Target>,
    pub position_claims: Vec<BinaryPoly192Target>,
}

/// Reader payloads, returned positions, and returned provider columns still
/// require authentication by the surrounding commitment protocol.
#[must_use = "indexed lookup claims must be authenticated by the surrounding PCS"]
#[derive(Clone, Debug)]
pub struct BinaryPolyLogupStarOutput {
    pub position_point: Vec<BinaryPoly192Target>,
    pub table_point: Vec<BinaryPoly192Target>,
    pub tables: Vec<BinaryPolyLogupStarTableOutput>,
    pub challenger: BinaryTower128Challenger,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Block {
    table: usize,
    reader: Option<usize>,
    height: usize,
    offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyLogupStarInputShape {
    seed: Vec<Poly64>,
    native: LogupStarShape,
    blocks: Vec<Block>,
    reader_offsets: Vec<usize>,
    max_reader: usize,
    max_table: usize,
    max_nonzero_draws: usize,
    fraction: BinaryPolyFractionGkrInputShape,
    product: BinaryPolyGenericSumcheckInputShape,
}

impl BinaryPolyLogupStarInputShape {
    fn reader_count(&self) -> usize {
        self.native
            .tables
            .iter()
            .map(|table| table.readers.len())
            .sum()
    }

    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryPolyLogupStarProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let pushforwards = self
            .native
            .tables
            .iter()
            .map(|table| fields::<BF, EF>(b, 1usize << table.num_variables))
            .collect::<Result<_, _>>()?;
        let fraction_gkr = self.fraction.allocate_targets::<BF, EF>(b)?;
        let position_claims = fields::<BF, EF>(b, self.reader_count())?;
        let product = self.product.allocate_targets::<BF, EF>(b)?;
        let column_claims = self
            .native
            .tables
            .iter()
            .map(|table| fields::<BF, EF>(b, table.width))
            .collect::<Result<_, _>>()?;
        Ok(BinaryPolyLogupStarProofTargets {
            pushforwards,
            fraction_gkr,
            position_claims,
            product,
            column_claims,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NativeBinaryPolyLogupStarInput {
    shape: BinaryPolyLogupStarInputShape,
    pushforwards: Vec<Poly192>,
    fraction: NativeBinaryPolyFractionGkrInput,
    positions: Vec<Poly192>,
    product: NativeBinaryPolyGenericSumcheckInput,
    columns: Vec<Poly192>,
}

impl NativeBinaryPolyLogupStarInput {
    pub fn shape(&self) -> &BinaryPolyLogupStarInputShape {
        &self.shape
    }
    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryPolyLogupStarInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary indexed input belongs to another verifier"));
        }
        let mut values = pack(&self.pushforwards);
        values.extend(self.fraction.private_values::<EF>(&expected.fraction)?);
        values.extend(pack::<EF>(&self.positions));
        values.extend(self.product.private_values::<EF>(&expected.product)?);
        values.extend(pack::<EF>(&self.columns));
        Ok(values)
    }
}

/// Released Poly64/Poly192 LogUpStar with finite rejection sampling.
/// Statement shapes come from trusted declarations, independently of proofs.
#[derive(Clone, Debug)]
pub struct BinaryPolyLogupStarVerifier {
    input: BinaryPolyLogupStarInputShape,
    entries: BinaryPolyNonzeroChallengePlan,
    fraction: BinaryPolyFractionGkrVerifier,
    product: BinaryPolyGenericSumcheckVerifier,
    usage: InputResourceUsage,
}

impl BinaryPolyLogupStarVerifier {
    pub fn new(
        tables: &[LogupStarTableShape],
        max_nonzero_draws: usize,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(tables, max_nonzero_draws, &VerifierLimits::default())
    }

    pub fn with_limits(
        tables: &[LogupStarTableShape],
        max_nonzero_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        if tables.is_empty() {
            return Err(invalid("binary indexed reduction requires a table"));
        }
        let mut usage = InputResourceUsage::default();
        usage.add_instances(limits, tables.len())?;
        let overflow = || VerificationError::ResourceArithmeticOverflow {
            component: "binary indexed geometry",
        };
        let mut leaves = 0usize;
        let mut proof_fields = 0usize;
        let mut reader_count = 0usize;
        let mut statement_fields = 0usize;
        let mut max_reader = 0;
        let mut max_table = 0;
        for table in tables {
            if table.num_variables == 0
                || table.num_variables >= 64
                || table.num_variables >= usize::BITS as usize
                || table.width == 0
                || table.readers.is_empty()
            {
                return Err(invalid("binary indexed table geometry is invalid"));
            }
            usage.check_log_degree(limits, table.num_variables)?;
            usage.check_matrix_width(limits, table.width)?;
            usage.add_instances(limits, table.readers.len())?;
            reader_count = reader_count
                .checked_add(table.readers.len())
                .ok_or_else(overflow)?;
            let entries = 1usize << table.num_variables;
            usage.add_final_poly_evaluations(limits, entries)?;
            leaves = leaves.checked_add(entries).ok_or_else(overflow)?;
            proof_fields = proof_fields
                .checked_add(entries)
                .and_then(|n| n.checked_add(table.width))
                .and_then(|n| n.checked_add(table.readers.len()))
                .ok_or_else(overflow)?;
            max_table = max_table.max(table.num_variables);
            usage.add_metadata_entries(
                limits,
                table.num_variables.checked_add(3).ok_or_else(overflow)?,
            )?;
            for &height in &table.readers {
                if height >= usize::BITS as usize {
                    return Err(invalid("binary indexed reader height is invalid"));
                }
                usage.check_log_degree(limits, height)?;
                leaves = leaves.checked_add(1usize << height).ok_or_else(overflow)?;
                max_reader = max_reader.max(height);
                statement_fields = statement_fields
                    .checked_add(height)
                    .and_then(|n| n.checked_add(table.width))
                    .ok_or_else(overflow)?;
                usage.add_metadata_entries(
                    limits,
                    height
                        .checked_add(table.width)
                        .and_then(|n| n.checked_add(1))
                        .ok_or_else(overflow)?,
                )?;
            }
        }
        // Native transcript lengths count all three base-field coefficients. Reader
        // claims repeat provider widths, so proof-limb accounting alone does
        // not bound these multiplications in the public native shape builder.
        let dimension = 3;
        let statement_coordinates = statement_fields.checked_mul(dimension).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "binary indexed native statement coordinates",
            },
        )?;
        proof_fields.checked_mul(dimension).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "binary indexed native proof coordinates",
            },
        )?;
        usage.add_metadata_entries(limits, statement_coordinates)?;
        let height = p3_util::log2_ceil_usize(leaves);
        if height >= usize::BITS as usize {
            return Err(invalid("binary indexed padded height is invalid"));
        }
        usage.check_log_degree(limits, height)?;
        usage.add_scalar_elements(limits, proof_fields.checked_mul(12).ok_or_else(overflow)?)?;
        usage.add_metadata_entries(
            limits,
            reader_count
                .checked_add(tables.len())
                .and_then(|n| n.checked_mul(5))
                .ok_or_else(overflow)?,
        )?;
        usage.add_rounds(limits, 2)?; // Reader and column batching.
        usage.add_query_round(limits, 1)?;
        usage.add_query_round(limits, 1)?;
        usage.add_metadata_entries(limits, 2 * 192)?;
        let entries =
            BinaryPolyNonzeroChallengePlan::with_limits(tables.len(), max_nonzero_draws, limits)?;
        usage.merge(limits, entries.input_resource_usage())?;
        let fraction =
            BinaryPolyFractionGkrVerifier::with_limits(height, max_nonzero_draws, limits)?;
        usage.merge(limits, fraction.input_resource_usage())?;
        let product = BinaryPolyGenericSumcheckVerifier::with_limits(max_table, 2, 0, limits)?;
        usage.merge(limits, product.input_resource_usage())?;
        let mut blocks = Vec::with_capacity(reader_count + tables.len());
        let mut reader_offsets = Vec::with_capacity(tables.len());
        let mut offset = 0;
        for (index, table) in tables.iter().enumerate() {
            reader_offsets.push(offset);
            offset += table.readers.len();
            for (reader, &height) in table.readers.iter().enumerate() {
                blocks.push(Block {
                    table: index,
                    reader: Some(reader),
                    height,
                    offset: 0,
                });
            }
            blocks.push(Block {
                table: index,
                reader: None,
                height: table.num_variables,
                offset: 0,
            });
        }
        blocks.sort_by_key(|block| Reverse(block.height));
        offset = 0;
        for block in &mut blocks {
            block.offset = offset;
            offset += 1usize << block.height;
        }
        let native = LogupStarShape {
            tables: tables.to_vec(),
            num_variables: height,
        };
        let seed = domain_separator_seed(&native.domain_separator::<Poly64, Poly192>());
        usage.add_metadata_entries(limits, seed.len())?;
        Ok(Self {
            input: BinaryPolyLogupStarInputShape {
                seed,
                native,
                blocks,
                reader_offsets,
                max_reader,
                max_table,
                max_nonzero_draws,
                fraction: fraction.input_shape(),
                product: product.input_shape(),
            },
            entries,
            fraction,
            product,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryPolyLogupStarInputShape {
        self.input.clone()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Reduces the caller's transcript-derived reader claims to position and
    /// provider-column claims. All three families require PCS authentication.
    pub fn verify_reduction<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        readers: &[Vec<BinaryPolyLogupStarReaderTargets>],
        proof: &BinaryPolyLogupStarProofTargets,
    ) -> Result<BinaryPolyLogupStarOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(readers, proof)?;
        poly_observe_seed::<BF, EF>(b, &mut ch, &self.input.seed)?;
        let statement = readers
            .iter()
            .flatten()
            .flat_map(|reader| reader.point.iter().chain(&reader.claims))
            .cloned()
            .collect::<Vec<_>>();
        poly_observe_values::<BF, EF>(b, &mut ch, &statement, 192)?;
        let rho = ch.sample_poly192::<BF, EF>(b)?;
        let pushforwards = proof
            .pushforwards
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        poly_observe_values::<BF, EF>(b, &mut ch, &pushforwards, 192)?;
        let entries = self.entries.sample::<BF, EF>(b, ch)?;
        let fraction = self.fraction.verify_reduction_after_queries::<BF, EF>(
            b,
            entries.continuation,
            &proof.fraction_gkr,
        )?;
        let powers = reader_powers(b, &rho, &self.input.native.tables)?;
        let (numerator, denominator) =
            self.rebuild_fraction(b, readers, proof, &fraction.point, &powers, &entries.values)?;
        poly_assert_equal(b, &fraction.numerator, &numerator);
        poly_assert_equal(b, &fraction.denominator, &denominator);
        let bytes = proof
            .position_claims
            .iter()
            .flat_map(|value| {
                value
                    .coefficients()
                    .iter()
                    .flat_map(|c| c.bits().chunks_exact(8))
            })
            .map(|bits| b.reconstruct_index_from_bits::<BF>(bits))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ch = fraction
            .continuation
            .resume_with_observation::<BF, EF>(b, &bytes)?;
        let gamma = ch.sample_poly192::<BF, EF>(b)?;
        let initial = self.initial_claim(b, readers, &powers, &gamma)?;
        let product = self
            .product
            .verify_reduction::<BF, EF>(b, ch, &initial, &proof.product)?;
        let terminal = self.product_claim(b, proof, &product.point, &gamma)?;
        poly_assert_equal(b, &product.claim, &terminal);
        let mut ch = product.challenger;
        let columns = proof
            .column_claims
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        poly_observe_values::<BF, EF>(b, &mut ch, &columns, 192)?;
        let tables = self
            .input
            .native
            .tables
            .iter()
            .enumerate()
            .map(|(index, table)| {
                let start = self.input.reader_offsets[index];
                BinaryPolyLogupStarTableOutput {
                    column_claims: proof.column_claims[index].clone(),
                    position_claims: proof.position_claims[start..start + table.readers.len()]
                        .to_vec(),
                }
            })
            .collect();
        Ok(BinaryPolyLogupStarOutput {
            position_point: fraction.point[fraction.point.len() - self.input.max_reader..].to_vec(),
            table_point: product.point,
            tables,
            challenger: ch,
        })
    }

    pub(crate) fn check_targets(
        &self,
        readers: &[Vec<BinaryPolyLogupStarReaderTargets>],
        proof: &BinaryPolyLogupStarProofTargets,
    ) -> Result<(), VerificationError> {
        if readers.len() != self.input.native.tables.len()
            || proof.pushforwards.len() != readers.len()
            || proof.column_claims.len() != readers.len()
            || proof.position_claims.len() != self.input.reader_count()
        {
            return Err(invalid("binary indexed target count mismatch"));
        }
        for (index, table) in self.input.native.tables.iter().enumerate() {
            if readers[index].len() != table.readers.len()
                || proof.pushforwards[index].len() != 1usize << table.num_variables
                || proof.column_claims[index].len() != table.width
                || readers[index]
                    .iter()
                    .zip(&table.readers)
                    .any(|(reader, &height)| {
                        reader.point.len() != height || reader.claims.len() != table.width
                    })
            {
                return Err(invalid("binary indexed target table mismatch"));
            }
        }
        self.fraction.check_targets(&proof.fraction_gkr)?;
        self.product.check_targets(&proof.product)?;
        Ok(())
    }

    fn rebuild_fraction<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        readers: &[Vec<BinaryPolyLogupStarReaderTargets>],
        proof: &BinaryPolyLogupStarProofTargets,
        point: &[BinaryPoly192Target],
        powers: &[Vec<BinaryPoly192Target>],
        entries: &[BinaryPoly192Target],
    ) -> Result<(BinaryPoly192Target, BinaryPoly192Target), VerificationError> {
        let mut numerator = b.binary_poly192_constant([0; 3])?;
        let mut denominator = numerator.clone();
        let mut covered = numerator.clone();
        for block in &self.input.blocks {
            let prefix = point.len() - block.height;
            let weight = block_weight(b, &point[..prefix], block.offset >> block.height)?;
            let own = &point[prefix..];
            covered = b.binary_poly192_add(&covered, &weight);
            let (n, d) = if let Some(reader) = block.reader {
                let equality = poly192_eq_eval(b, &readers[block.table][reader].point, own)?;
                let n = b.binary_poly192_mul(&powers[block.table][reader], &equality);
                let position =
                    &proof.position_claims[self.input.reader_offsets[block.table] + reader];
                (n, b.binary_poly192_add(&entries[block.table], position))
            } else {
                let n = poly_eval_multilinear(b, &proof.pushforwards[block.table], own)?;
                let mut position = b.binary_poly192_constant([0; 3])?;
                for (index, coordinate) in own.iter().enumerate() {
                    let basis = Poly64::interpolation_node(1usize << (own.len() - 1 - index));
                    let constant = b.binary_poly192_constant([basis.to_bits(), 0, 0])?;
                    let term = b.binary_poly192_mul(&constant, coordinate);
                    position = b.binary_poly192_add(&position, &term);
                }
                (n, b.binary_poly192_add(&position, &entries[block.table]))
            };
            let n = b.binary_poly192_mul(&weight, &n);
            let d = b.binary_poly192_mul(&weight, &d);
            numerator = b.binary_poly192_add(&numerator, &n);
            denominator = b.binary_poly192_add(&denominator, &d);
        }
        let one = b.binary_poly192_constant([1, 0, 0])?;
        let padding = b.binary_poly192_add(&one, &covered);
        Ok((numerator, b.binary_poly192_add(&denominator, &padding)))
    }

    fn initial_claim<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        readers: &[Vec<BinaryPolyLogupStarReaderTargets>],
        powers: &[Vec<BinaryPoly192Target>],
        gamma: &BinaryPoly192Target,
    ) -> Result<BinaryPoly192Target, VerificationError> {
        let mut total = b.binary_poly192_constant([0; 3])?;
        let mut power = b.binary_poly192_constant([1, 0, 0])?;
        for (table, description) in self.input.native.tables.iter().enumerate() {
            for column in 0..description.width {
                let mut combined = b.binary_poly192_constant([0; 3])?;
                for (reader, scale) in readers[table].iter().zip(&powers[table]) {
                    let term = b.binary_poly192_mul(scale, &reader.claims[column]);
                    combined = b.binary_poly192_add(&combined, &term);
                }
                let term = b.binary_poly192_mul(&power, &combined);
                total = b.binary_poly192_add(&total, &term);
                power = b.binary_poly192_mul(&power, gamma);
            }
        }
        Ok(total)
    }

    fn product_claim<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        proof: &BinaryPolyLogupStarProofTargets,
        point: &[BinaryPoly192Target],
        gamma: &BinaryPoly192Target,
    ) -> Result<BinaryPoly192Target, VerificationError> {
        let mut total = b.binary_poly192_constant([0; 3])?;
        let mut power = b.binary_poly192_constant([1, 0, 0])?;
        for (index, table) in self.input.native.tables.iter().enumerate() {
            let prefix = point.len() - table.num_variables;
            let weight = block_weight(b, &point[..prefix], 0)?;
            let pushed = poly_eval_multilinear(b, &proof.pushforwards[index], &point[prefix..])?;
            let mut columns = b.binary_poly192_constant([0; 3])?;
            for claim in &proof.column_claims[index] {
                let term = b.binary_poly192_mul(&power, claim);
                columns = b.binary_poly192_add(&columns, &term);
                power = b.binary_poly192_mul(&power, gamma);
            }
            let term = b.binary_poly192_mul(&pushed, &columns);
            let term = b.binary_poly192_mul(&weight, &term);
            total = b.binary_poly192_add(&total, &term);
        }
        Ok(total)
    }

    pub(crate) fn check_native(
        &self,
        lookups: &[TableLookup<'_, Poly192>],
        proof: &LogupStarProof<Poly64, Poly192>,
    ) -> Result<(), VerificationError> {
        if lookups.len() != self.input.native.tables.len()
            || proof.pushforwards.len() != lookups.len()
            || proof.column_claims.len() != lookups.len()
            || proof.position_claims.len() != self.input.reader_count()
        {
            return Err(invalid("binary indexed native count mismatch"));
        }
        for (index, table) in self.input.native.tables.iter().enumerate() {
            let lookup = &lookups[index];
            if lookup.num_variables != table.num_variables
                || lookup.readers.len() != table.readers.len()
                || proof.pushforwards[index].len() != 1usize << table.num_variables
                || proof.column_claims[index].len() != table.width
                || lookup
                    .readers
                    .iter()
                    .zip(&table.readers)
                    .any(|(reader, &height)| {
                        reader.point.num_variables() != height || reader.claims.len() != table.width
                    })
            {
                return Err(invalid("binary indexed native table mismatch"));
            }
        }
        self.fraction.check_native(&proof.fraction_gkr)?;
        self.product.check_native(&proof.product)?;
        Ok(())
    }

    /// Replays only finite, internally consistent messages. All failures
    /// preserve the caller's challenger. PCS authentication remains the caller's job.
    pub fn import_native<Ch>(
        &self,
        lookups: &[TableLookup<'_, Poly192>],
        proof: &LogupStarProof<Poly64, Poly192>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryPolyLogupStarInput, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64> + Clone,
    {
        self.import_native_with_reduction(lookups, proof, ch)
            .map(|(input, _)| input)
    }

    pub(crate) fn import_native_with_reduction<Ch>(
        &self,
        lookups: &[TableLookup<'_, Poly192>],
        proof: &LogupStarProof<Poly64, Poly192>,
        ch: &mut Ch,
    ) -> Result<(NativeBinaryPolyLogupStarInput, LogupStarOutput<Poly192>), VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64> + Clone,
    {
        self.check_native(lookups, proof)?;
        let mut staged = ch.clone();
        self.input
            .native
            .domain_separator::<Poly64, Poly192>()
            .seed(&mut staged);
        for lookup in lookups {
            for reader in lookup.readers {
                staged.observe_algebra_slice(reader.point.as_slice());
                staged.observe_algebra_slice(reader.claims);
            }
        }
        let rho = staged.sample_algebra_element::<Poly192>();
        for pushforward in &proof.pushforwards {
            staged.observe_algebra_slice(pushforward);
        }
        let entries = self.entries.sample_native(&mut staged)?;
        let (fraction_input, fraction) = self
            .fraction
            .import_native_with_reduction(&proof.fraction_gkr, &mut staged)?;
        let mut numerator = Poly192::ZERO;
        let mut denominator = Poly192::ZERO;
        let mut covered = Poly192::ZERO;
        for block in &self.input.blocks {
            let prefix = fraction.point.num_variables() - block.height;
            let weight = native_weight(
                &fraction.point.as_slice()[..prefix],
                block.offset >> block.height,
            );
            let own = Point::<Poly192>::new(fraction.point.as_slice()[prefix..].to_vec());
            covered += weight;
            if let Some(reader) = block.reader {
                numerator += weight
                    * rho.exp_u64(reader as u64)
                    * Point::<Poly192>::eval_eq(
                        lookups[block.table].readers[reader].point.as_slice(),
                        own.as_slice(),
                    );
                denominator += weight
                    * (entries[block.table]
                        + proof.position_claims[self.input.reader_offsets[block.table] + reader]);
            } else {
                numerator += weight
                    * Poly::new(proof.pushforwards[block.table].as_slice())
                        .eval_ext::<Poly64>(&own);
                let position = own
                    .iter()
                    .enumerate()
                    .map(|(index, &value)| {
                        value
                            * Poly192::from(Poly64::interpolation_node(
                                1usize << (own.num_variables() - 1 - index),
                            ))
                    })
                    .sum::<Poly192>();
                denominator += weight * (position + entries[block.table]);
            }
        }
        denominator += Poly192::ONE + covered;
        if numerator != fraction.numerator || denominator != fraction.denominator {
            return Err(invalid("binary indexed fraction closing mismatch"));
        }
        staged.observe_algebra_slice(&proof.position_claims);
        let gamma = staged.sample_algebra_element::<Poly192>();
        let mut initial = Poly192::ZERO;
        let mut power = Poly192::ONE;
        for lookup in lookups {
            for column in 0..lookup.width() {
                let mut scale = Poly192::ONE;
                let mut combined = Poly192::ZERO;
                for reader in lookup.readers {
                    combined += scale * reader.claims[column];
                    scale *= rho;
                }
                initial += power * combined;
                power *= gamma;
            }
        }
        if proof.product.claimed_sum != initial {
            return Err(invalid("binary indexed product initial sum mismatch"));
        }
        let (product_input, table_point, claim) = self
            .product
            .import_native_with_reduction(&proof.product, &mut staged)?;
        let mut terminal = Poly192::ZERO;
        power = Poly192::ONE;
        for (index, table) in self.input.native.tables.iter().enumerate() {
            let prefix = table_point.num_variables() - table.num_variables;
            let weight = native_weight(&table_point.as_slice()[..prefix], 0);
            let own = Point::<Poly192>::new(table_point.as_slice()[prefix..].to_vec());
            let pushed = Poly::new(proof.pushforwards[index].as_slice()).eval_ext::<Poly64>(&own);
            let mut columns = Poly192::ZERO;
            for &column in &proof.column_claims[index] {
                columns += power * column;
                power *= gamma;
            }
            terminal += weight * pushed * columns;
        }
        if claim != terminal {
            return Err(invalid("binary indexed product terminal mismatch"));
        }
        for columns in &proof.column_claims {
            staged.observe_algebra_slice(columns);
        }
        let output = LogupStarOutput {
            position_point: Point::<Poly192>::new(
                fraction.point.as_slice()[fraction.point.num_variables() - self.input.max_reader..]
                    .to_vec(),
            ),
            table_point,
            tables: self
                .input
                .native
                .tables
                .iter()
                .enumerate()
                .map(|(index, table)| {
                    let start = self.input.reader_offsets[index];
                    TableOutput {
                        column_claims: proof.column_claims[index].clone(),
                        position_claims: proof.position_claims[start..start + table.readers.len()]
                            .to_vec(),
                    }
                })
                .collect(),
        };
        let input = NativeBinaryPolyLogupStarInput {
            shape: self.input.clone(),
            pushforwards: proof.pushforwards.iter().flatten().copied().collect(),
            fraction: fraction_input,
            positions: proof.position_claims.iter().copied().collect(),
            product: product_input,
            columns: proof.column_claims.iter().flatten().copied().collect(),
        };
        *ch = staged;
        Ok((input, output))
    }
}

fn fields<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    count: usize,
) -> Result<Vec<BinaryPoly192Target>, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    (0..count)
        .map(|_| {
            let limbs = b.alloc_private_input_array::<12>("binary indexed field");
            Ok(b.binary_poly192_from_limbs::<BF>(limbs)?)
        })
        .collect()
}

fn pack<EF: Field>(fields: &[Poly192]) -> Vec<EF> {
    fields
        .iter()
        .flat_map(|v| {
            v.coefficients()
                .into_iter()
                .flat_map(|c| (0..4).map(move |i| EF::from_u16((c.to_bits() >> (16 * i)) as u16)))
        })
        .collect()
}

fn reader_powers<EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    rho: &BinaryPoly192Target,
    tables: &[LogupStarTableShape],
) -> Result<Vec<Vec<BinaryPoly192Target>>, VerificationError> {
    tables
        .iter()
        .map(|table| {
            let mut power = b.binary_poly192_constant([1, 0, 0])?;
            let mut powers = Vec::with_capacity(table.readers.len());
            for _ in &table.readers {
                powers.push(power.clone());
                power = b.binary_poly192_mul(&power, rho);
            }
            Ok(powers)
        })
        .collect()
}

fn block_weight<EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    point: &[BinaryPoly192Target],
    vertex: usize,
) -> Result<BinaryPoly192Target, VerificationError> {
    let one = b.binary_poly192_constant([1, 0, 0])?;
    let mut weight = one.clone();
    for (index, coordinate) in point.iter().enumerate() {
        let factor = if vertex >> (point.len() - 1 - index) & 1 == 1 {
            coordinate.clone()
        } else {
            b.binary_poly192_add(&one, coordinate)
        };
        weight = b.binary_poly192_mul(&weight, &factor);
    }
    Ok(weight)
}
fn native_weight<E: Field>(point: &[E], vertex: usize) -> E {
    point
        .iter()
        .enumerate()
        .map(|(index, &r)| {
            if vertex >> (point.len() - 1 - index) & 1 == 1 {
                r
            } else {
                E::ONE + r
            }
        })
        .product()
}
fn invalid(message: &str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
