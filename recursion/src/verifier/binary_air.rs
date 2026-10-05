//! Trusted binary AIR expressions evaluated at a multilinear opening point.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_air::Air;
use p3_air::boundary::{self, BoundaryEnd};
use p3_air::symbolic::{AirLayout, BaseEntry, BaseLeaf, SymbolicExpression};
use p3_binary_field::BinaryField128;
use p3_bus::{
    BusActivation, BusBoundary, BusDirection, BusName, BusSymbolicBuilder, SymbolicBusInteraction,
};
use p3_circuit::ops::{BinaryTower128Target, NativeTower128Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field};
use p3_lookup::InteractionSymbolicBuilder;
use p3_lookup::indexed::{IndexedLookups, IndexedRead, IndexedTable};

use super::binary_field_policy::{
    BinaryRelationPolicy, NativeTower128Relation, Poly64Relation, TowerRelation,
};
use super::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};

mod native_poly;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Constant(u128),
    Current(usize),
    Next(usize),
    PreprocessedCurrent(usize),
    PreprocessedNext(usize),
    Periodic(usize),
    Public(usize),
    First,
    Last,
    Transition,
    Add(usize, usize),
    Mul(usize, usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompiledBusDeclaration {
    pub name: String,
    pub direction: BusDirection,
    fields: Vec<usize>,
    activation: Option<usize>,
    pub factor_degree: usize,
}

pub(super) struct BinaryAirEvaluation<T = BinaryTower128Target> {
    pub folded: T,
    pub bus_fields: Vec<Vec<T>>,
    pub bus_activations: Vec<Option<T>>,
}

/// A private expression program compiled from a trusted, field-element AIR.
/// Its ordered assertions include native public-boundary pins. Proofs cannot
/// supply or replace its expressions, geometry, or successor-column map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryAirConstraintPlan<F = BinaryField128, E = BinaryField128> {
    program: AirProgram,
    fields: PhantomData<(F, E)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AirProgram {
    nodes: Vec<Node>,
    constraints: Vec<usize>,
    bus: Vec<CompiledBusDeclaration>,
    indexed: IndexedLookups,
    width: usize,
    public_count: usize,
    next_columns: Vec<usize>,
    preprocessed_width: usize,
    preprocessed_next_columns: Vec<usize>,
    periods: Vec<Vec<u128>>,
    log_height: usize,
    degree: usize,
    usage: InputResourceUsage,
}

impl<F, E> BinaryAirConstraintPlan<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    /// Canonical, explicitly tagged identity of the frozen constraint program.
    /// No user callback, pointer identity or Debug formatting enters this key.
    pub(crate) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        self.program.write_identity(F::RAW_BITS, w)
    }

    pub fn from_air<A>(air: &A, log_height: usize) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        Self::with_limits(air, log_height, &VerifierLimits::default())
    }

    pub fn with_limits<A>(
        air: &A,
        log_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        Self::build(air, log_height, limits, false).map(|(plan, _)| plan)
    }

    /// Internal entry point for a surrounding verifier that also consumes the
    /// retained bus and indexed obligations. The public AIR constructor rejects them.
    pub(super) fn with_interaction_limits<A>(
        air: &A,
        log_height: usize,
        limits: &VerifierLimits,
    ) -> Result<(Self, Vec<SymbolicBusInteraction<F>>), VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        Self::build(air, log_height, limits, true)
    }

    #[cfg(test)]
    pub(super) fn with_bus_limits<A>(
        air: &A,
        log_height: usize,
        limits: &VerifierLimits,
    ) -> Result<(Self, Vec<SymbolicBusInteraction<F>>), VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        let output = Self::with_interaction_limits(air, log_height, limits)?;
        if !output.0.program.indexed.is_empty() {
            return Err(invalid(
                "binary AIR interactions require a supported reduction",
            ));
        }
        Ok(output)
    }

    fn build<A>(
        air: &A,
        log_height: usize,
        limits: &VerifierLimits,
        allow_interactions: bool,
    ) -> Result<(Self, Vec<SymbolicBusInteraction<F>>), VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        AirProgram::build::<F, E, A>(
            air,
            log_height,
            limits,
            allow_interactions,
            F::raw_coordinates,
        )
        .map(|(program, bus)| {
            (
                Self {
                    program,
                    fields: PhantomData,
                },
                bus,
            )
        })
    }

    pub fn main_width(&self) -> usize {
        self.program.width
    }
    pub(super) fn indexed_reads(&self) -> &[IndexedRead] {
        self.program.indexed.reads()
    }
    pub(super) fn indexed_tables(&self) -> &[IndexedTable] {
        self.program.indexed.tables()
    }
    pub fn public_value_count(&self) -> usize {
        self.program.public_count
    }
    pub fn next_columns(&self) -> &[usize] {
        &self.program.next_columns
    }
    pub fn preprocessed_width(&self) -> usize {
        self.program.preprocessed_width
    }
    pub fn preprocessed_next_columns(&self) -> &[usize] {
        &self.program.preprocessed_next_columns
    }
    pub fn log_height(&self) -> usize {
        self.program.log_height
    }
    pub fn constraint_degree(&self) -> usize {
        self.program.degree
    }
    pub fn constraint_count(&self) -> usize {
        self.program.constraints.len()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.program.usage
    }

    pub(super) fn bus_declarations(&self) -> &[CompiledBusDeclaration] {
        &self.program.bus
    }

    /// Computes the native assertion-order Horner fold at an authenticated
    /// multilinear point. `next` follows the declared successor-column order.
    /// This arithmetic alone does not authenticate openings or verify a STARK.
    pub fn evaluate<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        point: &[BinaryTower128Target],
        current: &[BinaryTower128Target],
        next: &[BinaryTower128Target],
        public: &[BinaryTower128Target],
        alpha: &BinaryTower128Target,
    ) -> Result<BinaryTower128Target, VerificationError> {
        self.evaluate_with_auxiliary(b, point, current, next, &[], &[], public, alpha)
    }

    /// Evaluates the AIR with authenticated preprocessing openings. Successor
    /// values follow their own declared order; periodic values are recomputed
    /// from trusted vectors on the trailing coordinates of `point`.
    pub fn evaluate_with_auxiliary<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        point: &[BinaryTower128Target],
        current: &[BinaryTower128Target],
        next: &[BinaryTower128Target],
        preprocessed_current: &[BinaryTower128Target],
        preprocessed_next: &[BinaryTower128Target],
        public: &[BinaryTower128Target],
        alpha: &BinaryTower128Target,
    ) -> Result<BinaryTower128Target, VerificationError> {
        self.evaluate_with_bus(
            b,
            point,
            current,
            next,
            preprocessed_current,
            preprocessed_next,
            public,
            alpha,
        )
        .map(|evaluation| evaluation.folded)
    }

    /// Evaluates the ordinary assertion fold and retained bus payloads through
    /// one private program at the same authenticated openings. The surrounding
    /// verifier must consume both results in its terminal reduction equation.
    pub(super) fn evaluate_with_bus<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        point: &[BinaryTower128Target],
        current: &[BinaryTower128Target],
        next: &[BinaryTower128Target],
        preprocessed_current: &[BinaryTower128Target],
        preprocessed_next: &[BinaryTower128Target],
        public: &[BinaryTower128Target],
        alpha: &BinaryTower128Target,
    ) -> Result<BinaryAirEvaluation, VerificationError> {
        self.evaluate_using::<TowerRelation<F, E>, EF>(
            b,
            point,
            current,
            next,
            preprocessed_current,
            preprocessed_next,
            public,
            alpha,
        )
    }
    pub(super) fn evaluate_using<P, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        point: &[P::ChallengeTarget],
        current: &[P::ChallengeTarget],
        next: &[P::ChallengeTarget],
        preprocessed_current: &[P::ChallengeTarget],
        preprocessed_next: &[P::ChallengeTarget],
        public: &[P::BaseTarget],
        alpha: &P::ChallengeTarget,
    ) -> Result<BinaryAirEvaluation<P::ChallengeTarget>, VerificationError>
    where
        EF: Field + Eq + Hash,
        P: BinaryRelationPolicy<EF, Base = F, Challenge = E>,
    {
        self.program.evaluate::<P, EF>(
            b,
            point,
            current,
            next,
            preprocessed_current,
            preprocessed_next,
            public,
            alpha,
        )
    }
}

impl<F: RecursiveBinaryTowerField> BinaryAirConstraintPlan<F, BinaryField128>
where
    BinaryField128: ExtensionField<F>,
{
    /// Computes only the scalar AIR fold; the caller authenticates every opening.
    pub fn evaluate_native(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        point: &[NativeTower128Target],
        current: &[NativeTower128Target],
        next: &[NativeTower128Target],
        public: &[NativeTower128Target],
        alpha: &NativeTower128Target,
    ) -> Result<NativeTower128Target, VerificationError> {
        self.evaluate_native_with_auxiliary(b, point, current, next, &[], &[], public, alpha)
    }
    /// Evaluates trusted preprocessing and periodic vectors in the native carrier.
    pub fn evaluate_native_with_auxiliary(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        point: &[NativeTower128Target],
        current: &[NativeTower128Target],
        next: &[NativeTower128Target],
        preprocessed_current: &[NativeTower128Target],
        preprocessed_next: &[NativeTower128Target],
        public: &[NativeTower128Target],
        alpha: &NativeTower128Target,
    ) -> Result<NativeTower128Target, VerificationError> {
        self.evaluate_using::<NativeTower128Relation<F>, BinaryField128>(
            b,
            point,
            current,
            next,
            preprocessed_current,
            preprocessed_next,
            public,
            alpha,
        )
        .map(|evaluation| evaluation.folded)
    }
}

impl AirProgram {
    fn write_identity(
        &self,
        base_bits: usize,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        use p3_lookup::TraceWindow;
        for count in [
            self.width,
            self.public_count,
            self.preprocessed_width,
            self.log_height,
            self.degree,
        ] {
            w.write_count("binary AIR geometry", count)?;
        }
        for columns in [
            &self.next_columns,
            &self.preprocessed_next_columns,
            &self.constraints,
        ] {
            w.write_vec("binary AIR indices", columns, |w, &i| {
                w.write_count("binary AIR index", i)
            })?;
        }
        w.write_vec("binary AIR periods", &self.periods, |w, period| {
            w.write_vec("binary AIR period values", period, |w, &raw| {
                w.write_bytes(&raw.to_le_bytes()[..base_bits / 8])
            })
        })?;
        w.write_vec("binary AIR nodes", &self.nodes, |w, node| {
            let (tag, operands): (u8, &[usize]) = match node {
                Node::Constant(raw) => {
                    w.write_u8(0)?;
                    return w.write_bytes(&raw.to_le_bytes()[..base_bits / 8]);
                }
                Node::Current(i) => (1, core::slice::from_ref(i)),
                Node::Next(i) => (2, core::slice::from_ref(i)),
                Node::PreprocessedCurrent(i) => (3, core::slice::from_ref(i)),
                Node::PreprocessedNext(i) => (4, core::slice::from_ref(i)),
                Node::Periodic(i) => (5, core::slice::from_ref(i)),
                Node::Public(i) => (6, core::slice::from_ref(i)),
                Node::First => (7, &[]),
                Node::Last => (8, &[]),
                Node::Transition => (9, &[]),
                Node::Add(a, b) => {
                    w.write_u8(10)?;
                    w.write_count("binary AIR operand", *a)?;
                    return w.write_count("binary AIR operand", *b);
                }
                Node::Mul(a, b) => {
                    w.write_u8(11)?;
                    w.write_count("binary AIR operand", *a)?;
                    return w.write_count("binary AIR operand", *b);
                }
            };
            w.write_u8(tag)?;
            for &i in operands {
                w.write_count("binary AIR operand", i)?;
            }
            Ok(())
        })?;
        w.write_vec("binary AIR bus declarations", &self.bus, |w, bus| {
            w.write_count("binary bus name", bus.name.len())?;
            w.write_bytes(bus.name.as_bytes())?;
            w.write_u8(match bus.direction {
                BusDirection::Push => 0,
                BusDirection::Pull => 1,
            })?;
            w.write_vec("binary bus fields", &bus.fields, |w, &i| {
                w.write_count("binary bus node", i)
            })?;
            w.write_bool(bus.activation.is_some())?;
            if let Some(i) = bus.activation {
                w.write_count("binary bus activation", i)?;
            }
            w.write_count("binary bus degree", bus.factor_degree)
        })?;
        w.write_vec("binary indexed reads", self.indexed.reads(), |w, read| {
            w.write_count("binary indexed table name", read.table.len())?;
            w.write_bytes(read.table.as_bytes())?;
            w.write_count("binary indexed position", read.position)?;
            w.write_vec("binary indexed payload", &read.payload, |w, &i| {
                w.write_count("binary indexed column", i)
            })
        })?;
        w.write_vec(
            "binary indexed providers",
            self.indexed.tables(),
            |w, table| {
                w.write_count("binary indexed table name", table.name.len())?;
                w.write_bytes(table.name.as_bytes())?;
                w.write_u8(match table.window {
                    TraceWindow::Main => 0,
                    TraceWindow::Preprocessed => 1,
                })?;
                w.write_vec("binary indexed columns", &table.columns, |w, &i| {
                    w.write_count("binary indexed column", i)
                })
            },
        )
    }

    fn build<F, E, A>(
        air: &A,
        log_height: usize,
        limits: &VerifierLimits,
        allow_interactions: bool,
        base_raw: fn(F) -> u128,
    ) -> Result<(Self, Vec<SymbolicBusInteraction<F>>), VerificationError>
    where
        F: Field,
        E: ExtensionField<F>,
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        let layout = AirLayout::from_air::<F>(air);
        let mut usage = InputResourceUsage::default();
        usage.check_log_degree(limits, log_height)?;
        usage.check_matrix_width(limits, layout.main_width)?;
        usage.check_matrix_width(limits, layout.preprocessed_width)?;
        if layout.main_width == 0 {
            return Err(invalid("binary AIR has no main columns"));
        }
        let columns = layout
            .main_width
            .checked_add(layout.preprocessed_width)
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(layout.num_public_values))
            .and_then(|n| n.checked_add(layout.num_periodic_columns))
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary AIR symbolic columns",
            })?;
        usage.add_metadata_entries(limits, columns)?;
        if air.assumes_boolean_trace() {
            return Err(invalid("binary AIR requires a Boolean trace commitment"));
        }
        let next_columns = air.main_next_row_columns();
        usage.add_metadata_entries(limits, next_columns.len())?;
        for (i, &column) in next_columns.iter().enumerate() {
            if column >= layout.main_width || next_columns[..i].contains(&column) {
                return Err(invalid("binary AIR successor columns are invalid"));
            }
        }
        let preprocessed_next_columns = air.preprocessed_next_row_columns();
        usage.add_metadata_entries(limits, preprocessed_next_columns.len())?;
        for (i, &column) in preprocessed_next_columns.iter().enumerate() {
            if column >= layout.preprocessed_width
                || preprocessed_next_columns[..i].contains(&column)
            {
                return Err(invalid(
                    "binary AIR preprocessed successor columns are invalid",
                ));
            }
        }
        let periods = air.periodic_columns();
        if periods.len() != layout.num_periodic_columns {
            return Err(invalid("binary AIR periodic column count mismatch"));
        }
        for period in periods.iter() {
            if !period.len().is_power_of_two() || period.len().ilog2() as usize > log_height {
                return Err(invalid("binary AIR periodic column has invalid length"));
            }
            usage.add_metadata_entries(limits, period.len())?;
        }
        let periods: Vec<Vec<u128>> = periods
            .iter()
            .map(|period| period.iter().copied().map(base_raw).collect())
            .collect();
        let pins = air.public_boundary_io();
        let pin_nodes =
            pins.len()
                .checked_mul(5)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary AIR boundary pins",
                })?;
        usage.add_metadata_entries(limits, pin_nodes)?;
        boundary::validate(pins, layout.main_width, layout.num_public_values)
            .map_err(|_| invalid("binary AIR public boundary declarations are invalid"))?;

        // The lookup recorder retains the automatic Booleanity constraints
        // while discarding only bus metadata. Use its assertion order once.
        let symbolic = InteractionSymbolicBuilder::<F, E>::from_air(air, layout);
        if !symbolic.global_interactions().is_empty()
            || !symbolic.local_interactions().is_empty()
            || !symbolic.exclusive_interactions().is_empty()
            || (!allow_interactions
                && (!symbolic.indexed_reads().is_empty() || !symbolic.indexed_tables().is_empty()))
        {
            return Err(invalid(
                "binary AIR interactions require a supported reduction",
            ));
        }
        let bus_symbolic = BusSymbolicBuilder::<F, E>::from_air(air, layout);
        if !allow_interactions && !bus_symbolic.interactions().is_empty() {
            return Err(invalid(
                "binary AIR interactions require a supported reduction",
            ));
        }
        // Bound declaration-owned lists before cloning or resolving names.
        usage.add_metadata_entries(limits, symbolic.indexed_reads().len())?;
        usage.add_metadata_entries(limits, symbolic.indexed_tables().len())?;
        for read in symbolic.indexed_reads() {
            usage.add_metadata_entries(limits, read.payload.len())?;
            usage.add_metadata_string_bytes(limits, read.table.len())?;
        }
        for table in symbolic.indexed_tables() {
            usage.add_metadata_entries(limits, table.columns.len())?;
            usage.add_metadata_string_bytes(limits, table.name.len())?;
        }
        let indexed = IndexedLookups::new(
            symbolic.indexed_reads().to_vec(),
            symbolic.indexed_tables().to_vec(),
            &layout,
        )
        .map_err(|_| invalid("binary AIR indexed declaration is invalid"))?;
        usage.add_metadata_entries(limits, bus_symbolic.interactions().len())?;
        for declaration in bus_symbolic.interactions() {
            usage.add_metadata_entries(limits, declaration.fields.len())?;
            usage.add_metadata_string_bytes(limits, declaration.bus_name.len())?;
            if declaration.fields.is_empty() || BusName::try_new(&declaration.bus_name).is_err() {
                return Err(invalid("binary AIR bus declaration is invalid"));
            }
        }
        if !symbolic.extension_constraints().is_empty() {
            return Err(invalid("binary AIR extension assertions are unsupported"));
        }
        // Keep every root alive while pointer identities are memoized.
        let expressions = symbolic.base_constraints();
        usage.add_metadata_entries(limits, expressions.len())?;
        let order = symbolic.constraint_layout();
        if !order.ext_indices.is_empty()
            || order.base_indices.len() != expressions.len()
            || order
                .base_indices
                .iter()
                .enumerate()
                .any(|(i, &index)| i != index)
        {
            return Err(invalid("binary AIR assertion order is unsupported"));
        }
        let mut compiler = Compiler {
            base_raw,
            nodes: Vec::new(),
            degrees: Vec::new(),
            bus_valid: Vec::new(),
            cache: BTreeMap::new(),
            width: layout.main_width,
            public_count: layout.num_public_values,
            next_columns: &next_columns,
            preprocessed_width: layout.preprocessed_width,
            preprocessed_next_columns: &preprocessed_next_columns,
            periodic_count: layout.num_periodic_columns,
            usage,
            limits,
        };
        let constraint_count = expressions.len().checked_add(pins.len()).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "binary AIR constraint count",
            },
        )?;
        let mut constraints = Vec::with_capacity(constraint_count);
        let mut degree = 0;
        for expression in &expressions {
            let root = compiler.compile(expression)?;
            degree = degree.max(compiler.degrees[root]);
            constraints.push(root);
        }
        if !expressions.is_empty() {
            degree = degree.max(air.max_constraint_degree().unwrap_or(0));
        }
        for pin in pins {
            let selector = compiler.push(
                match pin.end {
                    BoundaryEnd::First => Node::First,
                    BoundaryEnd::Last => Node::Last,
                },
                1,
            );
            let current = compiler.push(Node::Current(pin.column), 1);
            let public = compiler.push(Node::Public(pin.public_value), 0);
            let difference = compiler.push(Node::Add(current, public), 1);
            let root = compiler.push(Node::Mul(selector, difference), 2);
            constraints.push(root);
            degree = degree.max(2);
        }
        if constraints.is_empty() || degree == 0 {
            return Err(invalid("binary AIR has no nonconstant constraint family"));
        }
        compiler.usage.check_log_degree(limits, degree)?;
        let mut bus = Vec::with_capacity(bus_symbolic.interactions().len());
        for declaration in bus_symbolic.interactions() {
            let mut fields = Vec::with_capacity(declaration.fields.len());
            let mut payload_degree = 0;
            for expression in &declaration.fields {
                let root = compiler.compile(expression)?;
                if !compiler.bus_valid[root] {
                    return Err(invalid("binary AIR bus reads an unsupported column"));
                }
                payload_degree = payload_degree.max(compiler.degrees[root]);
                fields.push(root);
            }
            let activation = match &declaration.activation {
                BusActivation::Always => None,
                BusActivation::Boundary(boundary) => {
                    compiler.usage.add_metadata_entries(limits, 1)?;
                    Some(compiler.push(
                        match boundary {
                            BusBoundary::First => Node::First,
                            BusBoundary::Last => Node::Last,
                        },
                        1,
                    ))
                }
                BusActivation::Boolean(expression) => {
                    let root = compiler.compile(expression)?;
                    if !compiler.bus_valid[root] {
                        return Err(invalid(
                            "binary AIR bus activation reads an unsupported column",
                        ));
                    }
                    Some(root)
                }
            };
            let factor_degree = payload_degree
                .checked_add(activation.map(|root| compiler.degrees[root]).unwrap_or(0))
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary AIR bus factor degree",
                })?;
            compiler.usage.check_log_degree(limits, factor_degree)?;
            bus.push(CompiledBusDeclaration {
                name: declaration.bus_name.clone(),
                direction: declaration.direction,
                fields,
                activation,
                factor_degree,
            });
        }
        let usage = compiler.usage;
        let nodes = compiler.nodes;
        Ok((
            Self {
                nodes,
                constraints,
                bus,
                indexed,
                width: layout.main_width,
                public_count: layout.num_public_values,
                next_columns,
                preprocessed_width: layout.preprocessed_width,
                preprocessed_next_columns,
                periods,
                log_height,
                degree,
                usage,
            },
            bus_symbolic.interactions().to_vec(),
        ))
    }

    fn evaluate<P: BinaryRelationPolicy<EF>, EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        point: &[P::ChallengeTarget],
        current: &[P::ChallengeTarget],
        next: &[P::ChallengeTarget],
        preprocessed_current: &[P::ChallengeTarget],
        preprocessed_next: &[P::ChallengeTarget],
        public: &[P::BaseTarget],
        alpha: &P::ChallengeTarget,
    ) -> Result<BinaryAirEvaluation<P::ChallengeTarget>, VerificationError> {
        if point.len() != self.log_height
            || current.len() != self.width
            || next.len() != self.next_columns.len()
            || public.len() != self.public_count
            || preprocessed_current.len() != self.preprocessed_width
            || preprocessed_next.len() != self.preprocessed_next_columns.len()
        {
            return Err(invalid("binary AIR evaluation target shape mismatch"));
        }
        for value in point
            .iter()
            .chain(current)
            .chain(next)
            .chain(preprocessed_current)
            .chain(preprocessed_next)
            .chain([alpha])
        {
            P::constrain_challenge(b, value);
        }
        for value in public {
            P::constrain_base(b, value)?;
        }
        let one = P::constant(b, 1)?;
        let mut first = one.clone();
        let mut last = one.clone();
        for r in point {
            let complement = P::add(b, &one, r);
            first = P::mul(b, &first, &complement);
            last = P::mul(b, &last, r);
        }
        let transition = P::add(b, &one, &last);
        let mut periodic_values = Vec::with_capacity(self.periods.len());
        for period in &self.periods {
            let coordinates = period.len().ilog2() as usize;
            let evaluations = period
                .iter()
                .map(|&raw| P::constant(b, raw))
                .collect::<Result<Vec<_>, _>>()?;
            periodic_values.push(evaluate_table::<P, EF>(
                b,
                &evaluations,
                &point[point.len() - coordinates..],
            )?);
        }
        let mut values: Vec<P::ChallengeTarget> = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let value = match *node {
                Node::Constant(raw) => P::constant(b, raw)?,
                Node::Current(i) => current[i].clone(),
                Node::Next(i) => next[i].clone(),
                Node::PreprocessedCurrent(i) => preprocessed_current[i].clone(),
                Node::PreprocessedNext(i) => preprocessed_next[i].clone(),
                Node::Periodic(i) => periodic_values[i].clone(),
                Node::Public(i) => P::lift(b, &public[i])?,
                Node::First => first.clone(),
                Node::Last => last.clone(),
                Node::Transition => transition.clone(),
                Node::Add(x, y) => P::add(b, &values[x], &values[y]),
                Node::Mul(x, y) => P::mul(b, &values[x], &values[y]),
            };
            values.push(value);
        }
        let mut folded = P::constant(b, 0)?;
        for &root in &self.constraints {
            let weighted = P::mul(b, &folded, alpha);
            folded = P::add(b, &weighted, &values[root]);
        }
        let bus_fields = self
            .bus
            .iter()
            .map(|declaration| {
                declaration
                    .fields
                    .iter()
                    .map(|&root| values[root].clone())
                    .collect()
            })
            .collect();
        let bus_activations = self
            .bus
            .iter()
            .map(|declaration| declaration.activation.map(|root| values[root].clone()))
            .collect();
        Ok(BinaryAirEvaluation {
            folded,
            bus_fields,
            bus_activations,
        })
    }
}

struct Compiler<'a, F> {
    base_raw: fn(F) -> u128,
    nodes: Vec<Node>,
    degrees: Vec<usize>,
    bus_valid: Vec<bool>,
    cache: BTreeMap<*const SymbolicExpression<F>, usize>,
    width: usize,
    public_count: usize,
    next_columns: &'a [usize],
    preprocessed_width: usize,
    preprocessed_next_columns: &'a [usize],
    periodic_count: usize,
    usage: InputResourceUsage,
    limits: &'a VerifierLimits,
}

impl<F: Field> Compiler<'_, F> {
    fn push(&mut self, node: Node, degree: usize) -> usize {
        let bus_valid = match node {
            Node::Next(_) | Node::PreprocessedNext(_) | Node::Periodic(_) => false,
            Node::Add(x, y) | Node::Mul(x, y) => self.bus_valid[x] && self.bus_valid[y],
            _ => true,
        };
        let id = self.nodes.len();
        self.nodes.push(node);
        self.degrees.push(degree);
        self.bus_valid.push(bus_valid);
        id
    }

    fn compile(&mut self, expression: &SymbolicExpression<F>) -> Result<usize, VerificationError> {
        let mut stack = alloc::vec![(expression, false, 0usize)];
        while let Some((expression, finish, depth)) = stack.pop() {
            let key = core::ptr::from_ref(expression);
            if self.cache.contains_key(&key) {
                continue;
            }
            if !finish {
                if depth >= self.limits.max_metadata_entries {
                    return Err(invalid("binary AIR expression depth exceeds its budget"));
                }
                stack.push((expression, true, depth));
                match expression {
                    SymbolicExpression::Add { x, y, .. }
                    | SymbolicExpression::Sub { x, y, .. }
                    | SymbolicExpression::Mul { x, y, .. } => {
                        stack.push((y, false, depth + 1));
                        stack.push((x, false, depth + 1));
                    }
                    SymbolicExpression::Neg { x, .. } => stack.push((x, false, depth + 1)),
                    SymbolicExpression::Leaf(_) => {}
                }
                if stack.len() > self.limits.max_metadata_entries {
                    return Err(invalid("binary AIR traversal exceeds its budget"));
                }
                continue;
            }
            self.usage.add_metadata_entries(self.limits, 1)?;
            let child = |x: &SymbolicExpression<F>| self.cache[&core::ptr::from_ref(x)];
            let (node, degree) = match expression {
                SymbolicExpression::Leaf(leaf) => match leaf {
                    BaseLeaf::Constant(c) => (Node::Constant((self.base_raw)(*c)), 0),
                    BaseLeaf::IsFirstRow => (Node::First, 1),
                    BaseLeaf::IsLastRow => (Node::Last, 1),
                    BaseLeaf::IsTransition => (Node::Transition, 1),
                    BaseLeaf::Variable(v) => match v.entry {
                        BaseEntry::Main { offset: 0 } if v.index < self.width => {
                            (Node::Current(v.index), 1)
                        }
                        BaseEntry::Main { offset: 1 } if v.index < self.width => {
                            let slot = self
                                .next_columns
                                .iter()
                                .position(|&c| c == v.index)
                                .ok_or_else(|| {
                                    invalid("binary AIR reads an undeclared successor column")
                                })?;
                            (Node::Next(slot), 1)
                        }
                        BaseEntry::Public if v.index < self.public_count => {
                            (Node::Public(v.index), 0)
                        }
                        BaseEntry::Preprocessed { offset: 0 }
                            if v.index < self.preprocessed_width =>
                        {
                            (Node::PreprocessedCurrent(v.index), 1)
                        }
                        BaseEntry::Preprocessed { offset: 1 }
                            if v.index < self.preprocessed_width =>
                        {
                            let slot = self.preprocessed_next_columns.iter()
                                .position(|&column| column == v.index)
                                .ok_or_else(|| invalid("binary AIR reads an undeclared preprocessed successor column"))?;
                            (Node::PreprocessedNext(slot), 1)
                        }
                        BaseEntry::Periodic if v.index < self.periodic_count => {
                            // MultiStark scores declared periodic leaves as
                            // degree one, including periods of length one.
                            (Node::Periodic(v.index), 1)
                        }
                        _ => {
                            return Err(invalid(
                                "binary AIR symbolic variable is unsupported or out of range",
                            ));
                        }
                    },
                },
                SymbolicExpression::Add { x, y, .. } | SymbolicExpression::Sub { x, y, .. } => {
                    let (x, y) = (child(x), child(y));
                    (Node::Add(x, y), self.degrees[x].max(self.degrees[y]))
                }
                SymbolicExpression::Mul { x, y, .. } => {
                    let (x, y) = (child(x), child(y));
                    let degree = self.degrees[x].checked_add(self.degrees[y]).ok_or(
                        VerificationError::ResourceArithmeticOverflow {
                            component: "binary AIR constraint degree",
                        },
                    )?;
                    (Node::Mul(x, y), degree)
                }
                SymbolicExpression::Neg { x, .. } => {
                    // Negation is identity in every sealed binary field.
                    let id = child(x);
                    self.cache.insert(key, id);
                    continue;
                }
            };
            self.usage.check_log_degree(self.limits, degree)?;
            let id = self.push(node, degree);
            self.cache.insert(key, id);
        }
        Ok(self.cache[&core::ptr::from_ref(expression)])
    }
}

pub(super) fn constrain_width<EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    value: &BinaryTower128Target,
    bits: usize,
) {
    for &bit in &value.bits()[bits..] {
        let difference = b.sub(ExprId::ZERO, bit);
        b.assert_zero(difference);
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

/// Trusted Poly64 AIR program evaluated with full Poly192 challenges.
/// Public values retain their base-field representation and are lifted into
/// the cubic extension only when the compiled expression consumes them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyAirConstraintPlan {
    program: AirProgram,
}

impl BinaryPolyAirConstraintPlan {
    /// Internal constructor for a relation that closes retained bus and indexed claims.
    pub(super) fn with_interaction_limits<A>(
        air: &A,
        log_height: usize,
        limits: &VerifierLimits,
    ) -> Result<(Self, Vec<SymbolicBusInteraction<p3_binary_field::Poly64>>), VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<p3_binary_field::Poly64, p3_binary_field::Poly192>>
            + Air<BusSymbolicBuilder<p3_binary_field::Poly64, p3_binary_field::Poly192>>,
    {
        let (program, declarations) = AirProgram::build::<
            p3_binary_field::Poly64,
            p3_binary_field::Poly192,
            A,
        >(air, log_height, limits, true, |value| {
            value.to_bits() as u128
        })?;
        Ok((Self { program }, declarations))
    }

    #[cfg(test)]
    pub(super) fn with_bus_limits<A>(
        air: &A,
        log_height: usize,
        limits: &VerifierLimits,
    ) -> Result<(Self, Vec<SymbolicBusInteraction<p3_binary_field::Poly64>>), VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<p3_binary_field::Poly64, p3_binary_field::Poly192>>
            + Air<BusSymbolicBuilder<p3_binary_field::Poly64, p3_binary_field::Poly192>>,
    {
        let output = Self::with_interaction_limits(air, log_height, limits)?;
        if !output.0.program.indexed.is_empty() {
            return Err(invalid(
                "binary Poly AIR indexed claims require a supported reduction",
            ));
        }
        Ok(output)
    }

    pub(super) fn indexed_reads(&self) -> &[IndexedRead] {
        self.program.indexed.reads()
    }
    pub(super) fn indexed_tables(&self) -> &[IndexedTable] {
        self.program.indexed.tables()
    }

    pub(super) fn bus_declarations(&self) -> &[CompiledBusDeclaration] {
        &self.program.bus
    }

    pub(super) fn evaluate_with_bus<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        point: &[p3_circuit::ops::BinaryPoly192Target],
        current: &[p3_circuit::ops::BinaryPoly192Target],
        next: &[p3_circuit::ops::BinaryPoly192Target],
        preprocessed_current: &[p3_circuit::ops::BinaryPoly192Target],
        preprocessed_next: &[p3_circuit::ops::BinaryPoly192Target],
        public: &[p3_circuit::ops::BinaryPoly64Target],
        alpha: &p3_circuit::ops::BinaryPoly192Target,
    ) -> Result<BinaryAirEvaluation<p3_circuit::ops::BinaryPoly192Target>, VerificationError> {
        self.program.evaluate::<Poly64Relation, EF>(
            b,
            point,
            current,
            next,
            preprocessed_current,
            preprocessed_next,
            public,
            alpha,
        )
    }

    pub(crate) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        self.program.write_identity(64, w)
    }

    pub fn from_air<A>(air: &A, log_height: usize) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<p3_binary_field::Poly64, p3_binary_field::Poly192>>
            + Air<BusSymbolicBuilder<p3_binary_field::Poly64, p3_binary_field::Poly192>>,
    {
        Self::with_limits(air, log_height, &VerifierLimits::default())
    }

    pub fn with_limits<A>(
        air: &A,
        log_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<p3_binary_field::Poly64, p3_binary_field::Poly192>>
            + Air<BusSymbolicBuilder<p3_binary_field::Poly64, p3_binary_field::Poly192>>,
    {
        AirProgram::build::<p3_binary_field::Poly64, p3_binary_field::Poly192, A>(
            air,
            log_height,
            limits,
            false,
            |value| value.to_bits() as u128,
        )
        .map(|(program, _)| Self { program })
    }

    pub fn main_width(&self) -> usize {
        self.program.width
    }
    pub fn public_value_count(&self) -> usize {
        self.program.public_count
    }
    pub fn next_columns(&self) -> &[usize] {
        &self.program.next_columns
    }
    pub fn preprocessed_width(&self) -> usize {
        self.program.preprocessed_width
    }
    pub fn preprocessed_next_columns(&self) -> &[usize] {
        &self.program.preprocessed_next_columns
    }
    pub fn log_height(&self) -> usize {
        self.program.log_height
    }
    pub fn constraint_degree(&self) -> usize {
        self.program.degree
    }
    pub fn constraint_count(&self) -> usize {
        self.program.constraints.len()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.program.usage
    }

    /// Arithmetic folding only; the caller must authenticate the openings and
    /// close the surrounding sumcheck relation before accepting a statement.
    pub fn evaluate<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        point: &[p3_circuit::ops::BinaryPoly192Target],
        current: &[p3_circuit::ops::BinaryPoly192Target],
        next: &[p3_circuit::ops::BinaryPoly192Target],
        public: &[p3_circuit::ops::BinaryPoly64Target],
        alpha: &p3_circuit::ops::BinaryPoly192Target,
    ) -> Result<p3_circuit::ops::BinaryPoly192Target, VerificationError> {
        self.evaluate_with_auxiliary(b, point, current, next, &[], &[], public, alpha)
    }

    pub fn evaluate_with_auxiliary<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        point: &[p3_circuit::ops::BinaryPoly192Target],
        current: &[p3_circuit::ops::BinaryPoly192Target],
        next: &[p3_circuit::ops::BinaryPoly192Target],
        preprocessed_current: &[p3_circuit::ops::BinaryPoly192Target],
        preprocessed_next: &[p3_circuit::ops::BinaryPoly192Target],
        public: &[p3_circuit::ops::BinaryPoly64Target],
        alpha: &p3_circuit::ops::BinaryPoly192Target,
    ) -> Result<p3_circuit::ops::BinaryPoly192Target, VerificationError> {
        self.program
            .evaluate::<Poly64Relation, EF>(
                b,
                point,
                current,
                next,
                preprocessed_current,
                preprocessed_next,
                public,
                alpha,
            )
            .map(|evaluation| evaluation.folded)
    }
}

fn evaluate_table<P: BinaryRelationPolicy<EF>, EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    values: &[P::ChallengeTarget],
    point: &[P::ChallengeTarget],
) -> Result<P::ChallengeTarget, VerificationError> {
    let count = u32::try_from(point.len())
        .ok()
        .and_then(|n| 1usize.checked_shl(n));
    if count != Some(values.len()) {
        return Err(invalid("binary AIR periodic evaluation shape mismatch"));
    }
    let mut layer = values.to_vec();
    for r in point.iter().rev() {
        layer = layer
            .chunks_exact(2)
            .map(|pair| {
                let slope = P::add(b, &pair[0], &pair[1]);
                let product = P::mul(b, r, &slope);
                P::add(b, &pair[0], &product)
            })
            .collect();
    }
    Ok(layer[0].clone())
}

#[cfg(test)]
#[path = "binary_bus_air_tests.rs"]
mod bus_tests;
