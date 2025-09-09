use std::array;

use p3_field::extension::BinomiallyExtendable;
use p3_field::{ExtensionField, Field};
use p3_uni_stark::{Entry, SymbolicExpression};

use crate::gates::arith_gates::{AddExtensionGate, MulExtensionGate, SubExtensionGate};
use crate::gates::event::AllEvents;
use crate::gates::gate::Gate;

pub type WireId = usize;

#[derive(Default)]
pub struct CircuitBuilder<F: Field, const D: usize> {
    wires: Vec<Option<F>>,
    gate_instances: Vec<Box<dyn Gate<F, D>>>,
}

pub type ExtensionWireId<const D: usize> = [WireId; D];

impl<F: Field, const D: usize> CircuitBuilder<F, D> {
    pub fn new() -> Self {
        CircuitBuilder {
            wires: Vec::new(),
            gate_instances: Vec::new(),
            ..Default::default()
        }
    }

    pub fn new_wire(&mut self) -> WireId {
        self.wires.push(None);
        self.wires.len() - 1
    }

    pub fn new_extension_wires(&mut self) -> ExtensionWireId<D> {
        array::from_fn(|_| self.new_wire())
    }

    pub fn add_gate(&mut self, gate: Box<dyn Gate<F, D>>) {
        self.gate_instances.push(gate);
    }

    pub fn add_constant(&mut self, value: F) -> WireId {
        let wire_id = self.new_wire();
        self.set_wire_value(wire_id, value).unwrap();
        wire_id
    }

    pub fn add_extension_constant<EF: ExtensionField<F>>(
        &mut self,
        value: EF,
    ) -> ExtensionWireId<D> {
        assert_eq!(
            EF::DIMENSION,
            D,
            "The dimension of the extension field must match the number of wires in a ChallengerWire"
        );
        let wire_id = array::from_fn(|_| self.new_wire());
        let base_values = value.as_basis_coefficients_slice();
        self.set_wire_values(&wire_id, &base_values).unwrap();
        wire_id
    }

    pub fn wires(&mut self) -> &Vec<Option<F>> {
        &mut self.wires
    }

    pub fn get_wire_value(&self, id: WireId) -> Result<Option<F>, CircuitError> {
        if id >= self.wires.len() {
            Err(CircuitError::InvalidWireId)
        } else {
            Ok(self.wires[id])
        }
    }

    pub fn set_wire_value(&mut self, id: WireId, value: F) -> Result<(), CircuitError> {
        let prev = self.get_wire_value(id)?;
        if let Some(val) = prev {
            if val != value {
                return Err(CircuitError::WireSetTwice);
            }
        } else {
            self.wires[id] = Some(value);
        }
        Ok(())
    }

    pub fn set_wire_values(&mut self, ids: &[WireId], value: &[F]) -> Result<(), CircuitError> {
        for (id, val) in ids.iter().zip(value.iter()) {
            self.set_wire_value(*id, *val)?;
        }

        Ok(())
    }

    pub fn set_extension_wires(
        &mut self,
        ids: ExtensionWireId<D>,
        value: &[F; D],
    ) -> Result<(), CircuitError> {
        self.set_wire_values(&ids, value)
    }

    pub fn set_extension_wires_slice(
        &mut self,
        ids: &[ExtensionWireId<D>],
        value: &[[F; D]],
    ) -> Result<(), CircuitError> {
        for (id, val) in ids.iter().zip(value.iter()) {
            self.set_extension_wires(*id, val)?;
        }
        Ok(())
    }

    pub fn set_public_inputs(&mut self, ids: &[WireId], values: &[F]) -> Result<(), CircuitError> {
        self.set_wire_values(ids, values)
    }

    pub fn get_instances(&self) -> &Vec<Box<dyn Gate<F, D>>> {
        &self.gate_instances
    }

    pub fn generate(&mut self) -> Result<AllEvents<F, D>, CircuitError> {
        let mut gate_instances = core::mem::take(&mut self.gate_instances);
        let mut all_events = AllEvents {
            add_events: Vec::new(),
            sub_events: Vec::new(),
            mul_events: Vec::new(),
            ext_add_events: Vec::new(),
            ext_sub_events: Vec::new(),
            ext_mul_events: Vec::new(),
        };
        for gate in gate_instances.iter_mut() {
            gate.generate(self, &mut all_events)?;
        }
        Ok(all_events)
    }
}

#[derive(Debug)]
pub enum CircuitError {
    RandomizationError,
    DegreeBitsMismatch,
    InvalidProofShape,
    InvalidWireId,
    InputNotSet,
    WireSetTwice,
}

pub fn symbolic_to_circuit<F: Field, EF, const D: usize>(
    is_first_row: ExtensionWireId<D>,
    is_last_row: ExtensionWireId<D>,
    is_transition: ExtensionWireId<D>,
    challenges: &[ExtensionWireId<D>],
    public_values: &[WireId],
    local_prep_values: &[ExtensionWireId<D>],
    next_prep_values: &[ExtensionWireId<D>],
    local_values: &[ExtensionWireId<D>],
    next_values: &[ExtensionWireId<D>],
    symbolic: &SymbolicExpression<EF>,
    circuit: &mut CircuitBuilder<F, D>,
) -> ExtensionWireId<D>
where
    F: BinomiallyExtendable<D>,
    EF: ExtensionField<F>,
{
    assert_eq!(D, EF::DIMENSION);
    match symbolic {
        SymbolicExpression::Constant(c) => circuit.add_extension_constant(c.clone()),
        SymbolicExpression::Variable(v) => match v.entry {
            Entry::Preprocessed { offset } => {
                if offset == 0 {
                    local_prep_values[v.index].clone()
                } else if offset == 1 {
                    next_prep_values[v.index].clone()
                } else {
                    panic!("Cannot have expressions involving more than two rows.")
                }
            }
            Entry::Main { offset } => {
                if offset == 0 {
                    local_values[v.index].clone()
                } else if offset == 1 {
                    next_values[v.index].clone()
                } else {
                    panic!("Cannot have expressions involving more than two rows.")
                }
            }
            Entry::Public => {
                let mut res = circuit.add_extension_constant(EF::ZERO);
                res[0] = public_values[v.index].clone();

                res
            }
            Entry::Challenge => challenges[v.index].clone(),
            _ => unimplemented!(),
        },
        SymbolicExpression::Add { x, y, .. } => {
            let x_wire = symbolic_to_circuit::<F, EF, D>(
                is_first_row.clone(),
                is_last_row.clone(),
                is_transition.clone(),
                challenges,
                public_values,
                local_prep_values,
                next_prep_values,
                local_values,
                next_values,
                x,
                circuit,
            );
            let y_wire = symbolic_to_circuit::<F, EF, D>(
                is_first_row,
                is_last_row,
                is_transition,
                challenges,
                public_values,
                local_prep_values,
                next_prep_values,
                local_values,
                next_values,
                y,
                circuit,
            );

            let out_wire = circuit.new_extension_wires();

            AddExtensionGate::add_to_circuit(circuit, x_wire, y_wire, out_wire);

            out_wire
        }
        SymbolicExpression::Mul { x, y, .. } => {
            let x_wire = symbolic_to_circuit::<F, EF, D>(
                is_first_row.clone(),
                is_last_row.clone(),
                is_transition.clone(),
                challenges,
                public_values,
                local_prep_values,
                next_prep_values,
                local_values,
                next_values,
                x,
                circuit,
            );
            let y_wire = symbolic_to_circuit::<F, EF, D>(
                is_first_row,
                is_last_row,
                is_transition,
                challenges,
                public_values,
                local_prep_values,
                next_prep_values,
                local_values,
                next_values,
                y,
                circuit,
            );

            let out_wire = circuit.new_extension_wires();

            MulExtensionGate::add_to_circuit(circuit, x_wire, y_wire, out_wire);
            out_wire
        }
        SymbolicExpression::Sub { x, y, .. } => {
            let x_wire = symbolic_to_circuit::<F, EF, D>(
                is_first_row.clone(),
                is_last_row.clone(),
                is_transition.clone(),
                challenges,
                public_values,
                local_prep_values,
                next_prep_values,
                local_values,
                next_values,
                x,
                circuit,
            );
            let y_wire = symbolic_to_circuit::<F, EF, D>(
                is_first_row,
                is_last_row,
                is_transition,
                challenges,
                public_values,
                local_prep_values,
                next_prep_values,
                local_values,
                next_values,
                y,
                circuit,
            );

            let out_wire = circuit.new_extension_wires();

            SubExtensionGate::add_to_circuit(circuit, x_wire, y_wire, out_wire);

            out_wire
        }
        SymbolicExpression::Neg { x, .. } => {
            let x_wire = symbolic_to_circuit::<F, EF, D>(
                is_first_row,
                is_last_row,
                is_transition,
                challenges,
                public_values,
                local_prep_values,
                next_prep_values,
                local_values,
                next_values,
                x,
                circuit,
            );
            let zero = circuit.add_extension_constant(EF::ZERO);

            let out_wire = circuit.new_extension_wires();

            SubExtensionGate::add_to_circuit(circuit, zero, x_wire, out_wire);

            out_wire
        }
        SymbolicExpression::IsFirstRow => is_first_row,
        SymbolicExpression::IsLastRow => is_last_row,
        SymbolicExpression::IsTransition => is_transition,
    }
}
