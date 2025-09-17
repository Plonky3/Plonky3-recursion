use crate::{CircuitBuilder, ExprId};

pub struct Challenger<const R: usize> {
    pub inputs: Vec<ExprId>,
    pub reset_flag: bool,
}

impl<const R: usize> Challenger<R> {
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            reset_flag: false,
        }
    }

    pub fn add_input(&mut self, expr_id: ExprId) {
        self.inputs.push(expr_id);
    }

    pub fn add_inputs(&mut self, expr_ids: &[ExprId]) {
        self.inputs.extend_from_slice(expr_ids);
    }

    pub fn clear(&mut self) {
        self.inputs.clear();
        self.reset_flag = true;
    }

    pub fn squeeze<F: Clone>(&mut self, builder: &mut CircuitBuilder<F>, outputs: &[ExprId; R]) {
        assert!(
            self.inputs.len() % R == 0,
            "Number of inputs must be a multiple of R"
        );

        let input_chunks = self.inputs.chunks_exact(R);

        for chunk in input_chunks {
            if self.reset_flag {
                builder.add_hash_absorb(chunk, true);
                self.reset_flag = false;
            } else {
                builder.add_hash_absorb(chunk, false);
            }
        }
        self.inputs.clear();
        self.reset_flag = false;

        builder.add_hash_squeeze(outputs);
    }
}
