/// This module provides a builder for defining public inputs.
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::PrimeCharacteristicRing;

use crate::builder::expr_builder::ExpressionBuilder;
use crate::{ExprId, WitnessId};

/// Builder for constructing public inputs
#[derive(Default)]
pub struct PublicInputBuilder<F> {
    count: usize,
    _phantom: PhantomData<F>,
}

impl<F> PublicInputBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new public input.
    ///
    /// Cost: 1 row in Public table + 1 row in witness table.
    ///
    /// # Parameters
    /// - `witness_id`: The witness ID of the public input
    ///
    /// # Returns
    /// The position of the public input
    pub fn add_public_input(&mut self, expr_builder: &mut ExpressionBuilder<F>) -> ExprId {
        let position = self.count;
        self.count += 1;
        expr_builder.add_public_expr(position)
    }

    /// Get the current number of public inputs.
    pub fn count(&self) -> usize {
        self.count
    }
}

pub struct PublicInputs {
    pub count: usize,
    pub rows: Vec<WitnessId>,
}
