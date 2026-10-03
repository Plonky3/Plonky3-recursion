//! Trusted binary AIR expressions evaluated at a multilinear opening point.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_air::Air;
use p3_air::boundary::{self, BoundaryEnd};
use p3_air::symbolic::{AirLayout, BaseEntry, BaseLeaf, SymbolicExpression};
use p3_binary_field::BinaryField128;
use p3_bus::BusSymbolicBuilder;
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field};
use p3_lookup::InteractionSymbolicBuilder;

use super::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::pcs::binary::{
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField, binary128_eval_multilinear,
};

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

/// A private expression program compiled from a trusted, field-element AIR.
/// Its ordered assertions include native public-boundary pins. Proofs cannot
/// supply or replace its expressions, geometry, or successor-column map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryAirConstraintPlan<F = BinaryField128, E = BinaryField128> {
    nodes: Vec<Node>,
    constraints: Vec<usize>,
    width: usize,
    public_count: usize,
    next_columns: Vec<usize>,
    preprocessed_width: usize,
    preprocessed_next_columns: Vec<usize>,
    periods: Vec<Vec<u128>>,
    log_height: usize,
    degree: usize,
    usage: InputResourceUsage,
    fields: PhantomData<(F, E)>,
}

impl<F, E> BinaryAirConstraintPlan<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
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
            .map(|period| period.iter().copied().map(F::raw_coordinates).collect())
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

        // The lookup recorder deliberately discards binary bus declarations;
        // a separate recorder is necessary before accepting a plain AIR plan.
        let symbolic = InteractionSymbolicBuilder::<F, E>::from_air(air, layout);
        if !symbolic.global_interactions().is_empty()
            || !symbolic.local_interactions().is_empty()
            || !symbolic.exclusive_interactions().is_empty()
            || !symbolic.indexed_reads().is_empty()
            || !symbolic.indexed_tables().is_empty()
            || !BusSymbolicBuilder::<F, E>::from_air(air, layout)
                .interactions()
                .is_empty()
        {
            return Err(invalid(
                "binary AIR interactions require a supported reduction",
            ));
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
            nodes: Vec::new(),
            degrees: Vec::new(),
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
        let usage = compiler.usage;
        let nodes = compiler.nodes;
        Ok(Self {
            nodes,
            constraints,
            width: layout.main_width,
            public_count: layout.num_public_values,
            next_columns,
            preprocessed_width: layout.preprocessed_width,
            preprocessed_next_columns,
            periods,
            log_height,
            degree,
            usage,
            fields: PhantomData,
        })
    }

    pub fn main_width(&self) -> usize {
        self.width
    }
    pub fn public_value_count(&self) -> usize {
        self.public_count
    }
    pub fn next_columns(&self) -> &[usize] {
        &self.next_columns
    }
    pub fn preprocessed_width(&self) -> usize {
        self.preprocessed_width
    }
    pub fn preprocessed_next_columns(&self) -> &[usize] {
        &self.preprocessed_next_columns
    }
    pub fn log_height(&self) -> usize {
        self.log_height
    }
    pub fn constraint_degree(&self) -> usize {
        self.degree
    }
    pub fn constraint_count(&self) -> usize {
        self.constraints.len()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
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
            constrain_width(b, value, E::RAW_BITS);
        }
        for value in public {
            constrain_width(b, value, F::RAW_BITS);
        }
        let one = b.binary128_constant(1)?;
        let mut first = one.clone();
        let mut last = one.clone();
        for r in point {
            let complement = b.binary128_add(&one, r);
            first = b.binary128_mul(&first, &complement);
            last = b.binary128_mul(&last, r);
        }
        let transition = b.binary128_add(&one, &last);
        let mut periodic_values = Vec::with_capacity(self.periods.len());
        for period in &self.periods {
            let coordinates = period.len().ilog2() as usize;
            let evaluations = period
                .iter()
                .map(|&raw| b.binary128_constant(raw))
                .collect::<Result<Vec<_>, _>>()?;
            periodic_values.push(binary128_eval_multilinear(
                b,
                &evaluations,
                &point[point.len() - coordinates..],
            )?);
        }
        let mut values: Vec<BinaryTower128Target> = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let value = match *node {
                Node::Constant(raw) => b.binary128_constant(raw)?,
                Node::Current(i) => current[i].clone(),
                Node::Next(i) => next[i].clone(),
                Node::PreprocessedCurrent(i) => preprocessed_current[i].clone(),
                Node::PreprocessedNext(i) => preprocessed_next[i].clone(),
                Node::Periodic(i) => periodic_values[i].clone(),
                Node::Public(i) => public[i].clone(),
                Node::First => first.clone(),
                Node::Last => last.clone(),
                Node::Transition => transition.clone(),
                Node::Add(x, y) => b.binary128_add(&values[x], &values[y]),
                Node::Mul(x, y) => b.binary128_mul(&values[x], &values[y]),
            };
            values.push(value);
        }
        let mut folded = b.binary128_constant(0)?;
        for &root in &self.constraints {
            let weighted = b.binary128_mul(&folded, alpha);
            folded = b.binary128_add(&weighted, &values[root]);
        }
        Ok(folded)
    }
}

struct Compiler<'a, F> {
    nodes: Vec<Node>,
    degrees: Vec<usize>,
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

impl<F: RecursiveBinaryTowerField> Compiler<'_, F> {
    fn push(&mut self, node: Node, degree: usize) -> usize {
        let id = self.nodes.len();
        self.nodes.push(node);
        self.degrees.push(degree);
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
                    BaseLeaf::Constant(c) => (Node::Constant(c.raw_coordinates()), 0),
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
