#[derive(Clone, Copy, Debug)]
pub enum GateInput {
    AliceInput(usize),
    BobInput(usize),
    Gate(usize),
    Constant(bool),
}

#[derive(Clone, Copy, Debug)]
pub struct Gate(pub GateInput, pub GateInput, pub [bool; 4]);

pub struct Circuit {
    pub alice_inputs: usize,
    pub bob_inputs: usize,
    pub gates: Vec<Gate>,
    pub outputs: Vec<GateInput>,
}

macro_rules! gatetype {
        ($name:ident, $bitwise:ident, $table:expr) => {
            #[allow(dead_code)]
            pub fn $name(&mut self, a: GateInput, b: GateInput) -> GateInput {
                self.gate(a, b, $table)
            }

            #[allow(dead_code)]
            pub fn $bitwise(&mut self, a: &[GateInput], b: &[GateInput]) -> Vec<GateInput> {
                if a.len() != b.len() {
                    panic!("Bitwise gate length mismatch, {} vs {}", a.len(), b.len());
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(self.$name(a[i], b[i]));
                }
                result
            }
        };
}

macro_rules! nary_gate {
    ($name:ident, $base:ident, $identity:expr) => {
        #[allow(dead_code)]
        pub fn $name(&mut self, inputs: &[GateInput]) -> GateInput {
            if inputs.len() == 0 {
                return GateInput::Constant($identity);
            }
            let mut inputs: Vec<GateInput> = inputs.iter().cloned().collect();
            let mut i = 0;
            while i < inputs.len()-1 {
                let a = inputs[i];
                let b = inputs[i+1];
                inputs.push(self.$base(a, b));
                i += 2;
            }
            inputs[i]
        }
    }
}

impl Circuit {
    #[allow(dead_code)]
    pub fn evaluate(&self, alice: &[bool], bob: &[bool]) -> Vec<bool> {
        assert_eq!(alice.len(), self.alice_inputs, "Number of Alice's inputs doesn't match");
        assert_eq!(bob.len(), self.bob_inputs, "Number of Bob's inputs doesn't match");
        let mut gate_evals = Vec::<bool>::new();
        let eval_input = |input: &GateInput, gate_evals: &[bool]| {
            match input {
                GateInput::AliceInput(n) => alice[*n],
                GateInput::BobInput(n) => bob[*n],
                GateInput::Gate(n) => gate_evals[*n],
                GateInput::Constant(c) => *c,
            }
        };
        for Gate(x, y, table) in self.gates.iter() {
            let a = eval_input(x, &gate_evals);
            let b = eval_input(y, &gate_evals);
            let idx = 2*(a as usize) + (b as usize);
            let r = table[idx];
            gate_evals.push(r);
        }
        let mut out_evals = Vec::new();
        for idx in self.outputs.iter() {
            out_evals.push(eval_input(idx, &gate_evals));
        }
        out_evals
    }

    pub fn new(alice_inputs: usize, bob_inputs: usize) -> Self {
        Self {alice_inputs, bob_inputs, gates: Vec::new(), outputs: Vec::new()}
    }

    pub fn gate(&mut self, a: GateInput, b: GateInput, table: [bool; 4]) -> GateInput {
        let g = Gate(a, b, table);
        self.gates.push(g);
        GateInput::Gate(self.gates.len() - 1)
    }

    pub fn add_output(&mut self, output: GateInput) {
        self.outputs.push(output);
    }

    pub fn get_alice_inputs(&self) -> Vec<GateInput> {
        (0..self.alice_inputs).map(GateInput::AliceInput).collect()
    }

    pub fn get_bob_inputs(&self) -> Vec<GateInput> {
        (0..self.bob_inputs).map(GateInput::BobInput).collect()
    }

    gatetype!(xor, bitwise_xor, [false, true, true, false]);
    gatetype!(xnor, bitwise_xnor, [true, false, false, true]);
    gatetype!(and, bitwise_and, [false, false, false, true]);
    gatetype!(nand, bitwise_nand, [true, true, true, false]);
    gatetype!(or, bitwise_or, [false, true, true, true]);
    gatetype!(nor, bitwise_nor, [true, false, false, false]);
    nary_gate!(and_nary, and, true);
    nary_gate!(or_nary, or, false);
    nary_gate!(xor_nary, xor, false);

    #[allow(dead_code)]
    pub fn not(&mut self, a: GateInput) -> GateInput {
        self.xor(a, GateInput::Constant(true))
    }

    #[allow(dead_code)]
    pub fn bitwise_not(&mut self, inputs: &[GateInput]) -> Vec<GateInput> {
        inputs.iter().cloned().map(|x| self.not(x)).collect()
    }
}
