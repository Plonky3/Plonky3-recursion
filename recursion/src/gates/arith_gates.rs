use std::array;

use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{BasedVectorSpace, Field};

use crate::air::alu::cols::{ExtAddEvent, ExtFieldOpEvent, ExtMulEvent, ExtSubEvent, FieldOpEvent};
use crate::air::ext_alu_air::BinomialExtension;
use crate::air::{AddEvent, MulEvent, SubEvent};
use crate::circuit_builder::ExtensionWireId;
use crate::circuit_builder::{CircuitBuilder, CircuitError, WireId};
use crate::gates::event::AllEvents;
use crate::gates::gate::Gate;

#[derive(Clone)]
pub struct AddGate<F: Field> {
    inputs: Vec<WireId>,
    outputs: Vec<WireId>,
    _marker: std::marker::PhantomData<F>,
}

const BINOP_N_INPUTS: usize = 2;
const BINOP_N_OUTPUTS: usize = 1;

impl<F: Field> AddGate<F> {
    pub fn new(inputs: Vec<WireId>, outputs: Vec<WireId>) -> Self {
        assert!(inputs.len() == BINOP_N_INPUTS);
        assert!(outputs.len() == BINOP_N_OUTPUTS);

        AddGate {
            inputs,
            outputs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn add_to_circuit<const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: WireId,
        b: WireId,
        c: WireId,
    ) -> () {
        let gate = AddGate::new(vec![a, b], vec![c]);
        builder.add_gate(Box::new(gate));
    }
}

impl<F: Field, const D: usize> Gate<F, D> for AddGate<F> {
    fn n_inputs(&self) -> usize {
        BINOP_N_INPUTS
    }

    fn n_outputs(&self) -> usize {
        BINOP_N_OUTPUTS
    }

    fn generate(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        all_events: &mut AllEvents<F, D>,
    ) -> Result<(), CircuitError> {
        <AddGate<F> as Gate<F, D>>::check_shape(self, self.inputs.len(), self.outputs.len());

        let input1 = builder.get_wire_value(self.inputs[0])?;
        let input2 = builder.get_wire_value(self.inputs[1])?;

        if input1.is_none() || input2.is_none() {
            return Err(CircuitError::InputNotSet);
        }

        let res = input1.unwrap() + input2.unwrap();
        builder.set_wire_value(self.outputs[0], res)?;

        all_events.add_events.push(AddEvent(FieldOpEvent {
            left_addr: [self.inputs[0]; 1],
            left_val: [input1.unwrap(); 1],
            right_addr: [self.inputs[1]; 1],
            right_val: [input2.unwrap(); 1],
            res_addr: [self.outputs[0]; 1],
            res_val: [res; 1],
        }));

        Ok(())
    }
}
#[derive(Clone)]
pub struct SubGate<F: Field> {
    inputs: Vec<WireId>,
    outputs: Vec<WireId>,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> SubGate<F> {
    pub fn new(inputs: Vec<WireId>, outputs: Vec<WireId>) -> Self {
        assert!(inputs.len() == BINOP_N_INPUTS);
        assert!(outputs.len() == BINOP_N_OUTPUTS);

        SubGate {
            inputs,
            outputs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn add_to_circuit<const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: WireId,
        b: WireId,
        c: WireId,
    ) -> () {
        let gate = SubGate::new(vec![a, b], vec![c]);
        builder.add_gate(Box::new(gate));
    }
}

impl<F: Field, const D: usize> Gate<F, D> for SubGate<F> {
    fn n_inputs(&self) -> usize {
        2
    }

    fn n_outputs(&self) -> usize {
        1
    }

    fn generate(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        all_events: &mut AllEvents<F, D>,
    ) -> Result<(), CircuitError> {
        <SubGate<F> as Gate<F, D>>::check_shape(self, self.inputs.len(), self.outputs.len());

        let input1 = builder.get_wire_value(self.inputs[0])?;
        let input2 = builder.get_wire_value(self.inputs[1])?;

        if input1.is_none() || input2.is_none() {
            return Err(CircuitError::InputNotSet);
        }

        let res = input1.unwrap() - input2.unwrap();
        builder.set_wire_value(self.outputs[0], res)?;

        all_events.sub_events.push(SubEvent(FieldOpEvent {
            left_addr: [self.inputs[0]; 1],
            left_val: [input1.unwrap(); 1],
            right_addr: [self.inputs[1]; 1],
            right_val: [input2.unwrap(); 1],
            res_addr: [self.outputs[0]; 1],
            res_val: [res; 1],
        }));
        Ok(())
    }
}

#[derive(Clone)]
pub struct MulGate<F: Field> {
    inputs: Vec<WireId>,
    outputs: Vec<WireId>,
    _marker: std::marker::PhantomData<F>,
}
impl<F: Field> MulGate<F> {
    pub fn new(inputs: Vec<WireId>, outputs: Vec<WireId>) -> Self {
        assert!(inputs.len() == BINOP_N_INPUTS);
        assert!(outputs.len() == BINOP_N_OUTPUTS);

        MulGate {
            inputs,
            outputs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn add_to_circuit<const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: WireId,
        b: WireId,
        c: WireId,
    ) -> () {
        let gate = MulGate::new(vec![a, b], vec![c]);
        builder.add_gate(Box::new(gate));
    }
}

impl<F: Field, const D: usize> Gate<F, D> for MulGate<F> {
    fn n_inputs(&self) -> usize {
        2
    }

    fn n_outputs(&self) -> usize {
        1
    }

    fn generate(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        all_events: &mut AllEvents<F, D>,
    ) -> Result<(), CircuitError> {
        <MulGate<F> as Gate<F, D>>::check_shape(self, self.inputs.len(), self.outputs.len());

        let input1 = builder.get_wire_value(self.inputs[0])?;
        let input2 = builder.get_wire_value(self.inputs[1])?;

        if input1.is_none() || input2.is_none() {
            return Err(CircuitError::InputNotSet);
        }

        let res = input1.unwrap() * input2.unwrap();
        builder.set_wire_value(self.outputs[0], res)?;

        all_events.mul_events.push(MulEvent(FieldOpEvent {
            left_addr: [self.inputs[0]; 1],
            left_val: [input1.unwrap(); 1],
            right_addr: [self.inputs[1]; 1],
            right_val: [input2.unwrap(); 1],
            res_addr: [self.outputs[0]; 1],
            res_val: [res; 1],
        }));

        Ok(())
    }
}

#[derive(Clone)]
pub struct MulExtensionGate<F: Field, const D: usize> {
    inputs: Vec<WireId>,
    outputs: Vec<WireId>,
    _marker: std::marker::PhantomData<F>,
}
impl<F: Field + BinomiallyExtendable<D>, const D: usize> MulExtensionGate<F, D> {
    const EXTENSION_N_INPUTS: usize = 2 * D;
    const EXTENSION_N_OUTPUTS: usize = D;

    pub fn new(inputs: Vec<WireId>, outputs: Vec<WireId>) -> Self {
        assert!(inputs.len() == Self::EXTENSION_N_INPUTS);
        assert!(outputs.len() == Self::EXTENSION_N_OUTPUTS);

        MulExtensionGate {
            inputs,
            outputs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn add_to_circuit(
        builder: &mut CircuitBuilder<F, D>,
        a: ExtensionWireId<D>,
        b: ExtensionWireId<D>,
        c: ExtensionWireId<D>,
    ) -> () {
        let gate = MulExtensionGate::<F, D>::new([a, b].concat(), c.to_vec());
        builder.add_gate(Box::new(gate));
    }

    pub fn get_first_input_wires(&self) -> ExtensionWireId<D> {
        self.inputs[0..D].try_into().unwrap()
    }

    pub fn get_second_input_wires(&self) -> ExtensionWireId<D> {
        self.inputs[D..2 * D].try_into().unwrap()
    }

    pub fn get_output_wires(&self) -> ExtensionWireId<D> {
        self.outputs.clone().try_into().unwrap()
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Gate<F, D> for MulExtensionGate<F, D> {
    fn n_inputs(&self) -> usize {
        Self::EXTENSION_N_INPUTS
    }

    fn n_outputs(&self) -> usize {
        Self::EXTENSION_N_OUTPUTS
    }

    fn generate(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        all_events: &mut AllEvents<F, D>,
    ) -> Result<(), CircuitError> {
        self.check_shape(self.inputs.len(), self.outputs.len());

        let input1_wires = self.get_first_input_wires();
        let input1: [Option<F>; D] = input1_wires
            .iter()
            .map(|&wire| builder.get_wire_value(wire))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        let input2_wires = self.get_second_input_wires();
        let input2: [Option<F>; D] = input2_wires
            .iter()
            .map(|&wire| builder.get_wire_value(wire))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();

        let res_wires = self.get_output_wires();
        let res_opt: [Option<F>; D] = res_wires
            .iter()
            .map(|&wire| builder.get_wire_value(wire))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        for i in 0..D {
            if input1[i].is_none() || (input2[i].is_none() && res_opt[i].is_none()) {
                return Err(CircuitError::InputNotSet);
            }
        }

        let inp1 = array::from_fn(|i| input1[i].unwrap());
        let inp1_ext = BinomialExtensionField::from_basis_coefficients_slice(&inp1).unwrap();

        let (inp2, res) = if input2.iter().any(|x| x.is_none()) {
            let res = array::from_fn(|i| res_opt[i].unwrap());
            let res_ext = BinomialExtensionField::from_basis_coefficients_slice(&res).unwrap();
            let inp2 = res_ext / inp1_ext;
            let inp2_slice = inp2.as_basis_coefficients_slice();
            builder.set_wire_values(&input2_wires, &inp2_slice)?;
            (inp2_slice.try_into().unwrap(), res)
        } else {
            let inp2 = array::from_fn(|i| input2[i].unwrap());
            let inp2_ext = BinomialExtensionField::from_basis_coefficients_slice(&inp2).unwrap();
            let res = inp1_ext * inp2_ext;
            let res_slice = res.as_basis_coefficients_slice();
            builder.set_wire_values(&res_wires, &res_slice)?;
            (inp2, res_slice.try_into().unwrap())
        };

        all_events.ext_mul_events.push(ExtMulEvent(ExtFieldOpEvent {
            left_addr: [self.get_first_input_wires(); 1],
            left_val: [inp1; 1],
            right_addr: [self.get_second_input_wires(); 1],
            right_val: [inp2; 1],
            res_addr: [self.get_output_wires(); 1],
            res_val: [res; 1],
        }));

        Ok(())
    }
}

#[derive(Clone)]
pub struct SubExtensionGate<F: Field, const D: usize> {
    inputs: Vec<WireId>,
    outputs: Vec<WireId>,
    _marker: std::marker::PhantomData<F>,
}
impl<F: Field + BinomiallyExtendable<D>, const D: usize> SubExtensionGate<F, D> {
    const EXTENSION_N_INPUTS: usize = 2 * D;
    const EXTENSION_N_OUTPUTS: usize = D;

    pub fn new(inputs: Vec<WireId>, outputs: Vec<WireId>) -> Self {
        assert!(inputs.len() == Self::EXTENSION_N_INPUTS);
        assert!(outputs.len() == Self::EXTENSION_N_OUTPUTS);

        SubExtensionGate {
            inputs,
            outputs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn add_to_circuit(
        builder: &mut CircuitBuilder<F, D>,
        a: ExtensionWireId<D>,
        b: ExtensionWireId<D>,
        c: ExtensionWireId<D>,
    ) -> () {
        let gate = SubExtensionGate::<F, D>::new([a, b].concat(), c.to_vec());
        builder.add_gate(Box::new(gate));
    }

    pub fn get_first_input_wires(&self) -> ExtensionWireId<D> {
        self.inputs[0..D].try_into().unwrap()
    }

    pub fn get_second_input_wires(&self) -> ExtensionWireId<D> {
        self.inputs[D..2 * D].try_into().unwrap()
    }

    pub fn get_output_wires(&self) -> ExtensionWireId<D> {
        self.outputs.clone().try_into().unwrap()
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Gate<F, D> for SubExtensionGate<F, D> {
    fn n_inputs(&self) -> usize {
        Self::EXTENSION_N_INPUTS
    }

    fn n_outputs(&self) -> usize {
        Self::EXTENSION_N_OUTPUTS
    }

    fn generate(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        all_events: &mut AllEvents<F, D>,
    ) -> Result<(), CircuitError> {
        self.check_shape(self.inputs.len(), self.outputs.len());

        let input1_wires = self.get_first_input_wires();
        let input1: [Option<F>; D] = input1_wires
            .iter()
            .map(|&wire| builder.get_wire_value(wire))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        let input2_wires = self.get_second_input_wires();
        let input2: [Option<F>; D] = input2_wires
            .iter()
            .map(|&wire| builder.get_wire_value(wire))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();

        for i in 0..D {
            if input1[i].is_none() || input2[i].is_none() {
                return Err(CircuitError::InputNotSet);
            }
        }

        let inp1 = array::from_fn(|i| input1[i].unwrap());
        let inp1_ext = BinomialExtension(inp1);
        let inp2 = array::from_fn(|i| input2[i].unwrap());
        let inp2_ext = BinomialExtension(inp2);
        let res = inp1_ext - inp2_ext;
        builder.set_wire_values(&self.get_output_wires(), &res.0)?;

        all_events.ext_sub_events.push(ExtSubEvent(ExtFieldOpEvent {
            left_addr: [self.get_first_input_wires(); 1],
            left_val: [inp1; 1],
            right_addr: [self.get_second_input_wires(); 1],
            right_val: [inp2; 1],
            res_addr: [self.get_output_wires(); 1],
            res_val: [res.0; 1],
        }));

        Ok(())
    }
}

#[derive(Clone)]
pub struct AddExtensionGate<F: Field, const D: usize> {
    inputs: Vec<WireId>,
    outputs: Vec<WireId>,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> AddExtensionGate<F, D> {
    const EXTENSION_N_INPUTS: usize = 2 * D;
    const EXTENSION_N_OUTPUTS: usize = D;

    pub fn new(inputs: Vec<WireId>, outputs: Vec<WireId>) -> Self {
        assert!(inputs.len() == Self::EXTENSION_N_INPUTS);
        assert!(outputs.len() == Self::EXTENSION_N_OUTPUTS);

        AddExtensionGate {
            inputs,
            outputs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn add_to_circuit(
        builder: &mut CircuitBuilder<F, D>,
        a: ExtensionWireId<D>,
        b: ExtensionWireId<D>,
        c: ExtensionWireId<D>,
    ) -> () {
        let gate = AddExtensionGate::<F, D>::new([a, b].concat(), c.to_vec());
        builder.add_gate(Box::new(gate));
    }

    pub fn get_first_input_wires(&self) -> ExtensionWireId<D> {
        self.inputs[0..D].try_into().unwrap()
    }

    pub fn get_second_input_wires(&self) -> ExtensionWireId<D> {
        self.inputs[D..2 * D].try_into().unwrap()
    }

    pub fn get_output_wires(&self) -> ExtensionWireId<D> {
        self.outputs.clone().try_into().unwrap()
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Gate<F, D> for AddExtensionGate<F, D> {
    fn n_inputs(&self) -> usize {
        Self::EXTENSION_N_INPUTS
    }

    fn n_outputs(&self) -> usize {
        Self::EXTENSION_N_OUTPUTS
    }

    fn generate(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        all_events: &mut AllEvents<F, D>,
    ) -> Result<(), CircuitError> {
        self.check_shape(self.inputs.len(), self.outputs.len());

        let input1_wires = self.get_first_input_wires();
        let input1: [Option<F>; D] = input1_wires
            .iter()
            .map(|&wire| builder.get_wire_value(wire))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        let input2_wires = self.get_second_input_wires();
        let input2: [Option<F>; D] = input2_wires
            .iter()
            .map(|&wire| builder.get_wire_value(wire))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();

        for i in 0..D {
            if input1[i].is_none() || input2[i].is_none() {
                return Err(CircuitError::InputNotSet);
            }
        }

        let inp1 = array::from_fn(|i| input1[i].unwrap());
        let inp1_ext = BinomialExtension(inp1);
        let inp2 = array::from_fn(|i| input2[i].unwrap());
        let inp2_ext = BinomialExtension(inp2);
        let res = inp1_ext + inp2_ext;
        builder.set_wire_values(&self.get_output_wires(), &res.0)?;

        all_events.ext_add_events.push(ExtAddEvent(ExtFieldOpEvent {
            left_addr: [self.get_first_input_wires(); 1],
            left_val: [inp1; 1],
            right_addr: [self.get_second_input_wires(); 1],
            right_val: [inp2; 1],
            res_addr: [self.get_output_wires(); 1],
            res_val: [res.0; 1],
        }));

        Ok(())
    }
}
