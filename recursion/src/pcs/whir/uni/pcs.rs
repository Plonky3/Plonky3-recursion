//! A univariate polynomial commitment scheme backed by WHIR.
//!
//! `p3-whir` is a multilinear scheme, while `p3_uni_stark::StarkGenericConfig`
//! wants a univariate one. This adapter commits each matrix column by its
//! coefficient vector — read as a multilinear's hypercube evaluations — and
//! turns every univariate opening into the equality claim
//! [`crate::pcs::whir::uni::bridge::univariate_eq_point`] derives.
//!
//! One WHIR argument covers one commitment. The univariate interface hands the
//! prover several commitments per opening, so a proof carries one WHIR argument
//! per commitment, replayed in order against a shared transcript.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_commit::{Mmcs, MultilinearPcs, OpenedValues};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{Layout, Table};
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, OpeningRequest, PrescribedPointPcs, TableShape, TableSpec,
};
use p3_util::log2_strict_usize;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, WhirConfig};
use p3_whir::pcs::WhirProverData;
use p3_whir::pcs::proof::PcsProof;
use p3_whir::pcs::prover::WhirProver;
use serde::{Deserialize, Serialize};

use crate::pcs::whir::uni::bridge::univariate_eq_point;
use crate::pcs::whir::uni::plan::{PaddedArity, StackedPlan, padded_arity};

/// Prover state behind one WHIR-backed univariate commitment.
pub struct WhirUniProverData<F, EF, MT, L>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
    L: Layout<F, EF>,
{
    /// Evaluation domain each committed matrix was supplied on, in commit order.
    ///
    /// For a quotient commitment (built via
    /// [`WhirUniPcs::commit_quotient_coefficient_matrices`]) this holds a
    /// unit-shift placeholder coset per chunk — its `size()` is the chunk's
    /// real height, but its `shift()` is always `F::ONE`, not the chunk's
    /// actual coset shift. The univariate interface drops the real domains
    /// before that method runs, so only the height survives; callers must not
    /// read `shift()` from an entry produced this way.
    pub domains: Vec<TwoAdicMultiplicativeCoset<F>>,
    /// Coefficient matrix per committed matrix: height `2^log_height`, width
    /// equal to the matrix width, column `j` holding polynomial `j`'s
    /// coefficients in ascending degree.
    pub coeffs: Vec<RowMajorMatrix<F>>,
    /// Slot assignment of every column inside the stacked polynomial.
    pub plan: StackedPlan,
    /// Arity of the stacked polynomial.
    pub stacked_num_variables: usize,
    /// WHIR layout and Merkle prover data.
    pub whir: WhirProverData<F, EF, MT, L>,
}

/// Failure modes of [`WhirUniPcs`]'s opening check.
#[derive(Debug)]
pub enum WhirUniPcsError {
    /// The WHIR proximity argument for one commitment round rejected.
    Whir {
        /// Index of the rejecting round in commit order.
        round: usize,
        /// The underlying WHIR verifier error.
        source: p3_whir::pcs::verifier::errors::VerifierError,
    },
    /// A claimed univariate opening disagreed with the multilinear value the
    /// WHIR argument bound, once rescaled by the bridge's scale factor.
    OpeningValueMismatch {
        /// Index of the round in commit order.
        round: usize,
        /// Index of the opening batch within that round.
        batch: usize,
        /// Index of the column within that batch.
        column: usize,
    },
    /// The proof carried a different number of WHIR arguments than the verifier
    /// was given commitments.
    RoundCountMismatch {
        /// Number of commitments handed to the verifier.
        expected: usize,
        /// Number of WHIR arguments in the proof.
        actual: usize,
    },
    /// A commitment's opening points or claimed value counts did not match the
    /// shape the verifier reconstructed from the public domains.
    ShapeMismatch {
        /// Index of the round in commit order.
        round: usize,
    },
}

/// Opening proof: one WHIR argument per commitment round, in round order.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "F: Serialize, EF: Serialize, MT::Commitment: Serialize, MT::MultiProof: Serialize",
    deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>, MT::Commitment: Deserialize<'de>, MT::MultiProof: Deserialize<'de>"
))]
pub struct WhirUniProof<F: Send + Sync + Clone, EF, MT: Mmcs<F>> {
    /// One WHIR argument per commitment, in the order the opening call received them.
    pub rounds: Vec<PcsProof<F, EF, MT>>,
}

/// Opening schedule and per-(matrix, point) bridge scales for one commitment.
pub(crate) struct RoundSchedule<EF> {
    /// One table spec per committed matrix, one batch per opening point.
    pub(crate) protocol: OpeningProtocol,
    /// Substituted equality points, in `protocol.iter_openings()` order.
    pub(crate) points: Vec<Point<EF>>,
    /// Bridge scale per `[matrix][point]`, consumed by the verifier's
    /// rescaling check.
    pub(crate) scales: Vec<Vec<EF>>,
    /// Arity of the stacked polynomial this commitment covers.
    pub(crate) stacked_num_variables: usize,
}

/// Builds the opening schedule for one commitment from public data only.
///
/// `shapes` gives each matrix's unpadded `(log height, width)`;
/// `points_per_matrix[m]` lists the univariate points matrix `m` is opened at.
/// Every column of a matrix is opened at every one of its points, so each
/// (matrix, point) pair becomes one batch naming all of that matrix's columns.
pub(crate) fn round_schedule<F, EF>(
    shapes: &[(usize, usize)],
    points_per_matrix: &[Vec<EF>],
    folding: usize,
) -> RoundSchedule<EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    assert_eq!(shapes.len(), points_per_matrix.len());

    let specs: Vec<TableSpec> = shapes
        .iter()
        .zip(points_per_matrix)
        .map(|(&(log_height, width), points)| {
            let schedule: Vec<OpeningRequest> = points
                .iter()
                .map(|_| OpeningBatch::new((0..width).collect(), Vec::new()))
                .collect();
            TableSpec::new(TableShape::new(log_height, width), schedule)
        })
        .collect();
    let protocol = OpeningProtocol::new(specs).pad_to_min_num_variables(folding);

    let mut points = Vec::new();
    let mut scales = Vec::with_capacity(shapes.len());
    for (&(log_height, _width), zetas) in shapes.iter().zip(points_per_matrix) {
        let arity = padded_arity(log_height, folding).get();
        let mut row = Vec::with_capacity(zetas.len());
        for &zeta in zetas {
            let (point, scale) = univariate_eq_point(zeta, arity);
            points.push(point);
            row.push(scale);
        }
        scales.push(row);
    }

    let padded: Vec<(PaddedArity, usize)> = shapes
        .iter()
        .map(|&(log_height, width)| (padded_arity(log_height, folding), width))
        .collect();
    let stacked_num_variables = StackedPlan::new(&padded).num_variables;

    RoundSchedule {
        protocol,
        points,
        scales,
        stacked_num_variables,
    }
}

/// WHIR behind the univariate PCS interface.
#[derive(Clone, Debug)]
pub struct WhirUniPcs<EF, F, Dft, MT, Challenger, L> {
    /// WHIR protocol parameters shared by every commitment.
    pub protocol_params: ProtocolParameters,
    /// First-round folding factor, extracted from `protocol_params`.
    folding: usize,
    /// FFT engine used to encode each committed codeword.
    pub dft: Dft,
    /// Base-field Merkle commitment scheme.
    pub mmcs: MT,
    /// Challenger prototype cloned for the commit-time root absorption that the
    /// univariate interface has no transcript for; the real absorption is done
    /// by the STARK prover and verifier.
    pub challenger_proto: Challenger,
    /// Largest committed height this instance accepts, as a log2.
    pub log_max_lde_height: usize,
    _marker: PhantomData<(EF, F, L)>,
}

impl<EF, F, Dft, MT, Challenger, L> WhirUniPcs<EF, F, Dft, MT, Challenger, L>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F> + Clone,
    MT: Mmcs<F> + Clone,
    MT::ProverData<RowMajorMatrix<F>>: Clone,
    Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanSampleUniformBits<F>
        + CanObserve<MT::Commitment>
        + Clone,
    L: Layout<F, EF> + Clone,
{
    /// Builds an instance from WHIR protocol parameters.
    ///
    /// # Panics
    /// Panics unless `protocol_params.folding_factor` is
    /// [`FoldingFactor::Constant`]: the adapter derives every table's padded
    /// arity from a single first-round folding factor.
    pub fn new(
        protocol_params: ProtocolParameters,
        dft: Dft,
        mmcs: MT,
        challenger_proto: Challenger,
        log_max_lde_height: usize,
    ) -> Self {
        let FoldingFactor::Constant(folding) = protocol_params.folding_factor else {
            panic!("WhirUniPcs requires FoldingFactor::Constant");
        };
        Self {
            protocol_params,
            folding,
            dft,
            mmcs,
            challenger_proto,
            log_max_lde_height,
            _marker: PhantomData,
        }
    }

    /// First-round folding factor.
    pub const fn folding(&self) -> usize {
        self.folding
    }

    /// WHIR configuration for a stacked polynomial of the given arity.
    ///
    /// # Panics
    /// Panics if the parameters are invalid for that arity.
    pub fn whir_config(&self, stacked_num_variables: usize) -> WhirConfig<EF, F, Challenger> {
        WhirConfig::new(stacked_num_variables, self.protocol_params.clone())
            .expect("WHIR parameters are valid for the committed arity")
    }

    /// Padded arities and widths of the tables a commitment stacks.
    pub fn table_shapes(&self, coeffs: &[RowMajorMatrix<F>]) -> Vec<(PaddedArity, usize)> {
        coeffs
            .iter()
            .map(|m| {
                (
                    padded_arity(log2_strict_usize(m.height()), self.folding),
                    m.width(),
                )
            })
            .collect()
    }

    /// Commits matrices already given as coefficient vectors.
    ///
    /// Column `j` of `coeffs[m]` is polynomial `j`'s coefficients in ascending
    /// degree; the commitment stacks every column as one multilinear.
    pub fn commit_coefficient_matrices(
        &self,
        domains: Vec<TwoAdicMultiplicativeCoset<F>>,
        coeffs: Vec<RowMajorMatrix<F>>,
    ) -> (MT::Commitment, WhirUniProverData<F, EF, MT, L>) {
        let shapes = self.table_shapes(&coeffs);
        let plan = StackedPlan::new(&shapes);
        let stacked_num_variables = plan.num_variables;

        // One table per matrix: `Table` stores one polynomial per row, so the
        // coefficient matrix is transposed into (width x height).
        let tables: Vec<Table<F>> = coeffs.iter().map(|m| Table::new(m.transpose())).collect();
        let witness = L::new_witness(tables, self.folding);
        debug_assert_eq!(witness.num_variables(), stacked_num_variables);

        let prover = WhirProver::<EF, F, Dft, MT, Challenger, L>::new(
            self.whir_config(stacked_num_variables),
            self.dft.clone(),
            self.mmcs.clone(),
        );

        // `Layout::commit` absorbs the Merkle root, but the univariate interface
        // supplies no transcript here; the STARK prover absorbs the commitment
        // itself, so this absorption is directed into a discarded clone.
        let mut sink = self.challenger_proto.clone();
        let (commitment, whir) = <WhirProver<EF, F, Dft, MT, Challenger, L> as MultilinearPcs<
            EF,
            Challenger,
        >>::commit(&prover, witness, &mut sink);

        (
            commitment,
            WhirUniProverData {
                domains,
                coeffs,
                plan,
                stacked_num_variables,
                whir,
            },
        )
    }

    /// Evaluations of committed matrix `idx` over `domain`.
    ///
    /// The commitment stores coefficients, so this zero-extends them to the
    /// requested height and runs one coset DFT at the domain's shift.
    ///
    /// # Panics
    /// Panics if `domain` is smaller than the committed matrix.
    fn evaluations_on_domain(
        &self,
        prover_data: &WhirUniProverData<F, EF, MT, L>,
        idx: usize,
        domain: TwoAdicMultiplicativeCoset<F>,
    ) -> RowMajorMatrix<F> {
        let coeffs = &prover_data.coeffs[idx];
        let width = coeffs.width();
        assert!(
            domain.size() >= coeffs.height(),
            "requested domain is smaller than the committed matrix"
        );
        let mut values = coeffs.values.clone();
        values.resize(domain.size() * width, F::ZERO);
        self.dft
            .coset_dft_batch(RowMajorMatrix::new(values, width), domain.shift())
            .to_row_major_matrix()
    }

    /// Coefficient matrices for the quotient chunks.
    ///
    /// Each `(domain, evaluations)` pair is one chunk on its own sub-coset;
    /// interpolating at that coset's shift recovers the chunk polynomial's
    /// coefficients, which is what the commitment stores.
    fn quotient_coefficient_matrices(
        &self,
        evaluations: impl IntoIterator<Item = (TwoAdicMultiplicativeCoset<F>, RowMajorMatrix<F>)>,
        _num_chunks: usize,
    ) -> Vec<RowMajorMatrix<F>> {
        evaluations
            .into_iter()
            .map(|(domain, evals)| {
                debug_assert_eq!(evals.height(), domain.size());
                self.dft.coset_idft_batch(evals, domain.shift())
            })
            .collect()
    }

    /// Commits coefficient matrices produced by [`Self::quotient_coefficient_matrices`].
    ///
    /// The univariate interface drops the domains between producing these
    /// matrices and committing them; the commitment needs only each matrix's
    /// height, so a unit-shift coset of that height stands in for the domain.
    fn commit_quotient_coefficient_matrices(
        &self,
        coeffs: Vec<RowMajorMatrix<F>>,
    ) -> (MT::Commitment, WhirUniProverData<F, EF, MT, L>) {
        let domains = coeffs
            .iter()
            .map(|m| {
                TwoAdicMultiplicativeCoset::new(F::ONE, log2_strict_usize(m.height()))
                    .expect("chunk height is within the field's two-adicity")
            })
            .collect();
        self.commit_coefficient_matrices(domains, coeffs)
    }

    /// Opens every commitment at its points, one WHIR argument per commitment.
    ///
    /// The reported values are the true univariate evaluations; each WHIR
    /// argument binds the corresponding multilinear value, which rescales to
    /// them by the bridge's scale factor.
    #[allow(clippy::type_complexity)]
    fn open_rounds(
        &self,
        rounds: Vec<(&WhirUniProverData<F, EF, MT, L>, Vec<Vec<EF>>)>,
        challenger: &mut Challenger,
    ) -> (OpenedValues<EF>, WhirUniProof<F, EF, MT>) {
        let mut opened = Vec::with_capacity(rounds.len());
        let mut proofs = Vec::with_capacity(rounds.len());

        for (data, points_per_matrix) in rounds {
            let shapes: Vec<(usize, usize)> = data
                .coeffs
                .iter()
                .map(|m| (log2_strict_usize(m.height()), m.width()))
                .collect();
            let schedule = round_schedule::<F, EF>(&shapes, &points_per_matrix, self.folding);
            debug_assert_eq!(schedule.stacked_num_variables, data.stacked_num_variables);

            let prover = WhirProver::<EF, F, Dft, MT, Challenger, L>::new(
                self.whir_config(data.stacked_num_variables),
                self.dft.clone(),
                self.mmcs.clone(),
            );
            let proof = prover.open_at(
                data.whir.clone(),
                &schedule.protocol,
                &schedule.points,
                challenger,
            );

            let mut round_values = Vec::with_capacity(data.coeffs.len());
            for (m, zetas) in points_per_matrix.iter().enumerate() {
                let coeffs = &data.coeffs[m];
                let width = coeffs.width();
                let mut matrix_values = Vec::with_capacity(zetas.len());
                for &zeta in zetas {
                    let point_values: Vec<EF> = (0..width)
                        .map(|col| {
                            (0..coeffs.height()).rev().fold(EF::ZERO, |acc, i| {
                                acc * zeta + coeffs.values[i * width + col]
                            })
                        })
                        .collect();
                    matrix_values.push(point_values);
                }
                round_values.push(matrix_values);
            }
            opened.push(round_values);
            proofs.push(proof);
        }

        (opened, WhirUniProof { rounds: proofs })
    }

    /// Verifies every commitment's WHIR argument and the claimed evaluations.
    ///
    /// Each round rebuilds the same opening schedule the prover used from
    /// public data, replays the WHIR argument through
    /// [`PrescribedPointPcs::verify_at`] — which deliberately does not absorb
    /// the commitment, the STARK verifier having already done so — and then
    /// rescales the bound multilinear values into univariate ones and compares
    /// them against the claims.
    ///
    /// # Precondition
    ///
    /// `commitments` must carry, per matrix and in commit order, the
    /// `(log height, width)` that was actually committed: the height from
    /// each `domain`'s `log_size()` and the width implied by the opening
    /// values' lengths. This function does not authenticate those shapes
    /// against `commitment` itself — the WHIR Merkle root only pins the
    /// *stacked* arity, and distinct per-matrix shape vectors can pad to the
    /// same stacked arity — so it only checks that the WHIR argument is
    /// internally consistent with whatever shapes it is given. Callers must
    /// independently establish that the supplied shapes match what was
    /// committed; `p3_uni_stark::verify` satisfies this by fixing widths from
    /// the AIR and reconstructing domains before calling into this PCS.
    #[allow(clippy::type_complexity)]
    fn verify_rounds(
        &self,
        commitments: Vec<(
            MT::Commitment,
            Vec<(TwoAdicMultiplicativeCoset<F>, Vec<(EF, Vec<EF>)>)>,
        )>,
        proof: &WhirUniProof<F, EF, MT>,
        challenger: &mut Challenger,
    ) -> Result<(), WhirUniPcsError> {
        if proof.rounds.len() != commitments.len() {
            return Err(WhirUniPcsError::RoundCountMismatch {
                expected: commitments.len(),
                actual: proof.rounds.len(),
            });
        }

        for (round, ((commitment, matrices), round_proof)) in
            commitments.into_iter().zip(&proof.rounds).enumerate()
        {
            let mut shapes = Vec::with_capacity(matrices.len());
            let mut points_per_matrix = Vec::with_capacity(matrices.len());
            for (domain, openings) in &matrices {
                let width = openings
                    .first()
                    .map(|(_, values)| values.len())
                    .ok_or(WhirUniPcsError::ShapeMismatch { round })?;
                if openings.iter().any(|(_, values)| values.len() != width) {
                    return Err(WhirUniPcsError::ShapeMismatch { round });
                }
                shapes.push((domain.log_size(), width));
                points_per_matrix.push(openings.iter().map(|&(z, _)| z).collect::<Vec<EF>>());
            }

            let schedule = round_schedule::<F, EF>(&shapes, &points_per_matrix, self.folding);
            let prover = WhirProver::<EF, F, Dft, MT, Challenger, L>::new(
                self.whir_config(schedule.stacked_num_variables),
                self.dft.clone(),
                self.mmcs.clone(),
            );
            let evals = prover
                .verify_at(
                    &commitment,
                    round_proof,
                    &schedule.protocol,
                    &schedule.points,
                    challenger,
                )
                .map_err(|source| WhirUniPcsError::Whir { round, source })?;

            // `evals` follows `protocol.iter_openings()` order: matrix-major,
            // then point, matching how the schedule laid out its scales.
            let mut batch = 0usize;
            for (m, (_domain, openings)) in matrices.iter().enumerate() {
                for (p, (_zeta, claimed)) in openings.iter().enumerate() {
                    let scale = schedule.scales[m][p];
                    let bound = evals
                        .get(batch)
                        .ok_or(WhirUniPcsError::ShapeMismatch { round })?;
                    if bound.current().len() != claimed.len() {
                        return Err(WhirUniPcsError::ShapeMismatch { round });
                    }
                    for (column, (&bound_value, &claimed_value)) in
                        bound.current().iter().zip(claimed).enumerate()
                    {
                        if bound_value * scale != claimed_value {
                            return Err(WhirUniPcsError::OpeningValueMismatch {
                                round,
                                batch,
                                column,
                            });
                        }
                    }
                    batch += 1;
                }
            }
        }

        Ok(())
    }
}

impl<EF, F, Dft, MT, Challenger, L> p3_commit::Pcs<EF, Challenger>
    for WhirUniPcs<EF, F, Dft, MT, Challenger, L>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<F> + Clone,
    MT: Mmcs<F> + Clone,
    MT::ProverData<RowMajorMatrix<F>>: Clone,
    MT::Commitment: Serialize + for<'de> Deserialize<'de>,
    MT::MultiProof: Serialize + for<'de> Deserialize<'de>,
    Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanSampleUniformBits<F>
        + CanObserve<MT::Commitment>
        + Clone,
    L: Layout<F, EF> + Clone,
{
    type Domain = TwoAdicMultiplicativeCoset<F>;
    type Commitment = MT::Commitment;
    type ProverData = WhirUniProverData<F, EF, MT, L>;
    type EvaluationsOnDomain<'a> = RowMajorMatrix<F>;
    type Proof = WhirUniProof<F, EF, MT>;
    type Error = WhirUniPcsError;

    const ZK: bool = false;

    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        TwoAdicMultiplicativeCoset::new(F::ONE, log2_strict_usize(degree))
            .expect("degree is within the field's two-adicity")
    }

    fn log_max_lde_height(&self) -> usize {
        self.log_max_lde_height
    }

    fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<F>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        let mut domains = Vec::new();
        let mut coeffs = Vec::new();
        for (domain, mat) in evaluations {
            debug_assert_eq!(mat.height(), domain.size());
            coeffs.push(self.dft.coset_idft_batch(mat, domain.shift()));
            domains.push(domain);
        }
        self.commit_coefficient_matrices(domains, coeffs)
    }

    fn get_evaluations_on_domain<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        self.evaluations_on_domain(prover_data, idx, domain)
    }

    fn get_quotient_ldes(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<F>)>,
        num_chunks: usize,
    ) -> Vec<RowMajorMatrix<F>> {
        self.quotient_coefficient_matrices(evaluations, num_chunks)
    }

    fn commit_ldes(&self, ldes: Vec<RowMajorMatrix<F>>) -> (Self::Commitment, Self::ProverData) {
        self.commit_quotient_coefficient_matrices(ldes)
    }

    fn open(
        &self,
        commitment_data_with_opening_points: Vec<(&Self::ProverData, Vec<Vec<EF>>)>,
        fiat_shamir_challenger: &mut Challenger,
    ) -> (p3_commit::OpenedValues<EF>, Self::Proof) {
        self.open_rounds(commitment_data_with_opening_points, fiat_shamir_challenger)
    }

    fn verify(
        &self,
        commitments_with_opening_points: Vec<(
            Self::Commitment,
            Vec<(Self::Domain, Vec<(EF, Vec<EF>)>)>,
        )>,
        proof: &Self::Proof,
        fiat_shamir_challenger: &mut Challenger,
    ) -> Result<(), Self::Error> {
        self.verify_rounds(
            commitments_with_opening_points,
            proof,
            fiat_shamir_challenger,
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_commit::PolynomialSpace;
    use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
    use p3_field::coset::TwoAdicMultiplicativeCoset;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_matrix::Matrix;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_sumcheck::layout::PrefixProver;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::WhirUniPcs;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type PackedF = <F as Field>::Packing;
    type MyMmcs = MerkleTreeMmcs<PackedF, PackedF, MyHash, MyCompress, 2, 8>;
    type MyDft = Radix2DFTSmallBatch<F>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;
    type MyPcs = WhirUniPcs<EF, F, MyDft, MyMmcs, MyChallenger, PrefixProver<F, EF>>;

    pub(super) fn test_pcs() -> MyPcs {
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let params = ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        };
        WhirUniPcs::new(
            params,
            MyDft::default(),
            MyMmcs::new(hash, compress, 0),
            MyChallenger::new(perm),
            20,
        )
    }

    #[test]
    fn folding_is_read_from_the_protocol_parameters() {
        assert_eq!(test_pcs().folding(), 4);
    }

    /// The stacked arity a commitment reports must be what the layout planner
    /// says for the padded table shapes, and the WHIR config must be built for
    /// exactly that arity.
    #[test]
    fn commit_plans_the_stacked_layout_and_stores_coefficients() {
        let pcs = test_pcs();
        let dft = MyDft::default();
        let mut rng = SmallRng::seed_from_u64(3);

        // Two matrices: 2^6 x 3 and 2^5 x 2, on shifted cosets.
        let d0 = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 6).unwrap();
        let d1 = TwoAdicMultiplicativeCoset::<F>::new(F::GENERATOR, 5).unwrap();
        let m0 = RowMajorMatrix::<F>::rand(&mut rng, 1 << 6, 3);
        let m1 = RowMajorMatrix::<F>::rand(&mut rng, 1 << 5, 2);

        let (_commit, data) = <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::commit(
            &pcs,
            vec![(d0, m0.clone()), (d1, m1.clone())],
        );

        // 3 * 2^6 + 2 * 2^5 = 256 -> stacked arity 8.
        assert_eq!(data.stacked_num_variables, 8);
        assert_eq!(data.plan.num_variables, 8);
        // Largest table first.
        assert_eq!(data.plan.placements[0].table_idx, 0);
        assert_eq!(data.plan.placements[1].table_idx, 1);

        // The stored coefficients must interpolate back to the input evaluations.
        let back0 = dft
            .coset_dft_batch(data.coeffs[0].clone(), d0.shift())
            .to_row_major_matrix();
        assert_eq!(back0.values, m0.values);
        let back1 = dft
            .coset_dft_batch(data.coeffs[1].clone(), d1.shift())
            .to_row_major_matrix();
        assert_eq!(back1.values, m1.values);
    }

    #[test]
    fn natural_domain_has_the_requested_size() {
        let pcs = test_pcs();
        let d =
            <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::natural_domain_for_degree(&pcs, 1 << 7);
        assert_eq!(d.size(), 1 << 7);
        assert_eq!(d.shift(), F::ONE);
    }

    /// Evaluations returned for a larger, shifted domain must equal a direct
    /// coset LDE of the stored coefficients.
    #[test]
    fn evaluations_on_domain_matches_a_direct_coset_lde() {
        let pcs = test_pcs();
        let dft = MyDft::default();
        let mut rng = SmallRng::seed_from_u64(5);

        let trace_domain = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 5).unwrap();
        let mat = RowMajorMatrix::<F>::rand(&mut rng, 1 << 5, 2);
        let (_c, data) =
            <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::commit(&pcs, vec![(trace_domain, mat)]);

        // Quotient domain: 4x larger, disjoint coset.
        let quotient_domain = trace_domain.create_disjoint_domain(1 << 7);
        let got = <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::get_evaluations_on_domain(
            &pcs,
            &data,
            0,
            quotient_domain,
        );

        // Reference: pad the coefficients to the quotient height, then coset-DFT.
        let mut coeffs = data.coeffs[0].clone();
        let width = coeffs.width();
        coeffs
            .values
            .resize(quotient_domain.size() * width, F::ZERO);
        let want = dft
            .coset_dft_batch(
                RowMajorMatrix::new(coeffs.values, width),
                quotient_domain.shift(),
            )
            .to_row_major_matrix();

        assert_eq!(got.height(), quotient_domain.size());
        assert_eq!(got.values, want.values);
    }

    /// Asking for the committed domain itself must return the original evaluations.
    #[test]
    fn evaluations_on_the_committed_domain_round_trip() {
        let pcs = test_pcs();
        let mut rng = SmallRng::seed_from_u64(6);
        let domain = TwoAdicMultiplicativeCoset::<F>::new(F::GENERATOR, 4).unwrap();
        let mat = RowMajorMatrix::<F>::rand(&mut rng, 1 << 4, 3);
        let (_c, data) =
            <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::commit(&pcs, vec![(domain, mat.clone())]);

        let got = <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::get_evaluations_on_domain(
            &pcs, &data, 0, domain,
        );
        assert_eq!(got.values, mat.values);
    }

    /// A quotient commitment must open each chunk to the same values a direct
    /// interpolation of that chunk's evaluations would.
    #[test]
    fn quotient_chunks_are_committed_as_chunk_coefficients() {
        let pcs = test_pcs();
        let dft = MyDft::default();
        let mut rng = SmallRng::seed_from_u64(13);

        let quotient_domain = TwoAdicMultiplicativeCoset::<F>::new(F::GENERATOR, 6).unwrap();
        let evals = RowMajorMatrix::<F>::rand(&mut rng, 1 << 6, 1);
        let num_chunks = 4;

        let (_c, data) = <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::commit_quotient(
            &pcs,
            quotient_domain,
            evals.clone(),
            num_chunks,
        );

        let sub_domains = quotient_domain.split_domains(num_chunks);
        let sub_evals = quotient_domain.split_evals(num_chunks, evals);
        assert_eq!(data.coeffs.len(), num_chunks);
        for (i, (sd, se)) in sub_domains.iter().zip(sub_evals).enumerate() {
            let want = dft.coset_idft_batch(se, sd.shift());
            assert_eq!(data.coeffs[i].values, want.values, "chunk {i}");
        }

        // The recorded domains are unit-shift height-only placeholders, one
        // per chunk: real chunk height, but not the chunk's actual shift.
        assert_eq!(data.domains.len(), num_chunks);
        for (i, domain) in data.domains.iter().enumerate() {
            assert_eq!(domain.shift(), F::ONE, "chunk {i}");
            assert_eq!(domain.size(), data.coeffs[i].height(), "chunk {i}");
        }

        // 4 chunks x 2^4 rows x 1 column = 64 -> stacked arity 6.
        assert_eq!(data.stacked_num_variables, 6);
    }

    /// The schedule must place one opening batch per point per matrix, in
    /// matrix-then-point order, with points padded to the folding depth.
    #[test]
    fn round_schedule_lists_one_batch_per_point() {
        use super::round_schedule;

        let z0 = EF::from_u32(11);
        let z1 = EF::from_u32(13);
        // Matrix 0: 2^6 rows, 3 cols, opened at z0 and z1. Matrix 1: 2^2 rows,
        // 2 cols (below the folding depth of 4), opened at z0 only.
        let schedule = round_schedule::<F, EF>(&[(6, 3), (2, 2)], &[vec![z0, z1], vec![z0]], 4);

        assert_eq!(schedule.protocol.num_openings(), 3);
        assert_eq!(schedule.points.len(), 3);
        assert_eq!(schedule.points[0].num_variables(), 6);
        assert_eq!(schedule.points[1].num_variables(), 6);
        // Matrix 1 is padded from arity 2 up to the folding depth 4.
        assert_eq!(schedule.points[2].num_variables(), 4);
        assert_eq!(schedule.scales.len(), 2);
        assert_eq!(schedule.scales[0].len(), 2);
        assert_eq!(schedule.scales[1].len(), 1);
    }

    /// `open` must report the true univariate evaluations, and the WHIR
    /// argument's own multilinear values must rescale to exactly those.
    #[test]
    fn open_reports_univariate_evaluations_consistent_with_the_whir_claim() {
        let pcs = test_pcs();
        let mut rng = SmallRng::seed_from_u64(21);

        let domain = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 6).unwrap();
        let mat = RowMajorMatrix::<F>::rand(&mut rng, 1 << 6, 2);
        let (_c, data) =
            <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::commit(&pcs, vec![(domain, mat)]);

        let zeta = EF::from_u32(9_999);
        let mut challenger = pcs.challenger_proto.clone();
        let (opened, proof) = <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::open(
            &pcs,
            vec![(&data, vec![vec![zeta]])],
            &mut challenger,
        );

        // Reference: Horner over the stored coefficients.
        let coeffs = &data.coeffs[0];
        for (col, &got) in opened[0][0][0].iter().enumerate() {
            let want = (0..coeffs.height()).rev().fold(EF::ZERO, |acc, i| {
                acc * zeta + coeffs.values[i * coeffs.width() + col]
            });
            assert_eq!(got, want, "column {col}");
        }

        // The WHIR argument bound the rescaled multilinear values.
        let schedule = super::round_schedule::<F, EF>(&[(6, 2)], &[vec![zeta]], pcs.folding());
        let batch = &proof.rounds[0].evals[0];
        for (col, &want) in opened[0][0][0].iter().enumerate() {
            assert_eq!(batch.current()[col] * schedule.scales[0][0], want);
        }
    }

    /// Builds an honest commit/open pair over two matrices at two points and
    /// returns everything `verify` needs.
    #[allow(clippy::type_complexity)]
    fn open_two_matrices() -> (
        MyPcs,
        <MyMmcs as p3_commit::Mmcs<F>>::Commitment,
        Vec<(TwoAdicMultiplicativeCoset<F>, Vec<(EF, Vec<EF>)>)>,
        super::WhirUniProof<F, EF, MyMmcs>,
    ) {
        let pcs = test_pcs();
        let mut rng = SmallRng::seed_from_u64(31);
        let d0 = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 6).unwrap();
        let d1 = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 5).unwrap();
        let m0 = RowMajorMatrix::<F>::rand(&mut rng, 1 << 6, 2);
        let m1 = RowMajorMatrix::<F>::rand(&mut rng, 1 << 5, 1);
        let (commit, data) =
            <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::commit(&pcs, vec![(d0, m0), (d1, m1)]);

        let zeta = EF::from_u32(777);
        let zeta_next = zeta * EF::from(d0.subgroup_generator());
        let points = vec![vec![zeta, zeta_next], vec![zeta]];

        let mut challenger = pcs.challenger_proto.clone();
        let (opened, proof) = <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::open(
            &pcs,
            vec![(&data, points)],
            &mut challenger,
        );

        let coms = vec![
            (
                d0,
                vec![
                    (zeta, opened[0][0][0].clone()),
                    (zeta_next, opened[0][0][1].clone()),
                ],
            ),
            (d1, vec![(zeta, opened[0][1][0].clone())]),
        ];
        (pcs, commit, coms, proof)
    }

    #[test]
    fn verify_accepts_an_honest_opening() {
        let (pcs, commit, coms, proof) = open_two_matrices();
        let mut challenger = pcs.challenger_proto.clone();
        <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::verify(
            &pcs,
            vec![(commit, coms)],
            &proof,
            &mut challenger,
        )
        .expect("honest opening verifies");
    }

    #[test]
    fn verify_rejects_a_tampered_opened_value() {
        let (pcs, commit, mut coms, proof) = open_two_matrices();
        coms[0].1[0].1[0] += EF::ONE;
        let mut challenger = pcs.challenger_proto.clone();
        let err = <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::verify(
            &pcs,
            vec![(commit, coms)],
            &proof,
            &mut challenger,
        )
        .expect_err("a tampered opened value must be rejected");
        assert!(
            matches!(
                err,
                super::WhirUniPcsError::OpeningValueMismatch {
                    round: 0,
                    batch: 0,
                    column: 0,
                }
            ),
            "expected an OpeningValueMismatch at round 0, batch 0, column 0, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_a_tampered_final_polynomial() {
        let (pcs, commit, coms, mut proof) = open_two_matrices();
        let poly = proof.rounds[0]
            .whir
            .final_poly
            .as_mut()
            .expect("final poly");
        poly.as_mut_slice()[0] += EF::ONE;
        let mut challenger = pcs.challenger_proto.clone();
        let err = <MyPcs as p3_commit::Pcs<EF, MyChallenger>>::verify(
            &pcs,
            vec![(commit, coms)],
            &proof,
            &mut challenger,
        )
        .expect_err("a tampered final polynomial must be rejected");
        assert!(
            matches!(err, super::WhirUniPcsError::Whir { round: 0, .. }),
            "expected a Whir error at round 0, got {err:?}"
        );
    }
}
