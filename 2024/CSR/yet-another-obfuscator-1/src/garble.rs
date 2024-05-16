use crate::circuit::{Circuit, Gate, GateInput};
use crate::hashable::HashViaSerialize;
use crate::rng::{Rng, RngGenerateWith, RngGenerate};
use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use serde::{Serialize, Deserialize};


pub type GarbledWireValue = [u8; 16];
pub type EncryptedWireValue = [u8; 16];

const OUT0: GarbledWireValue = [13u8, 37u8, 42u8, 42u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
const OUT1: GarbledWireValue = [13u8, 37u8, 42u8, 42u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8];


#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct GarbledWire(pub GarbledWireValue, pub GarbledWireValue);

impl GarbledWire {
    pub fn select(&self, b: bool) -> GarbledWireValue {
        if b {self.1} else {self.0}
    }
}

impl RngGenerate for GarbledWire {
    fn generate(rng: &mut Rng) -> Self {
        let x = GarbledWireValue::generate(rng);
        let mut y = GarbledWireValue::generate(rng);
        y[0] = (y[0] & !1) | ((x[0] & 1) ^ 1);
        GarbledWire(x, y)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GarbledGate {
    pub table: [EncryptedWireValue; 4]
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputTable {
    pub table: [EncryptedWireValue; 2]
}

pub fn encrypt(a: &GarbledWireValue, b: &GarbledWireValue, out: &GarbledWireValue) -> EncryptedWireValue {
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(a);
    key[16..32].copy_from_slice(b);
    let key = GenericArray::from(key);
    let aes = Aes256::new(&key);
    let mut res = GenericArray::from(*out);
    aes.encrypt_block(&mut res);
    res.into()
}

pub fn decrypt(a: &GarbledWireValue, b: &GarbledWireValue, out: &EncryptedWireValue) -> GarbledWireValue {
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(a);
    key[16..32].copy_from_slice(b);
    let key = GenericArray::from(key);
    let aes = Aes256::new(&key);
    let mut res = GenericArray::from(*out);
    aes.decrypt_block(&mut res);
    res.into()
}


impl GarbledGate {
    pub fn new(table: &[bool; 4], a: &GarbledWire, b: &GarbledWire, out: &GarbledWire) -> Self {
        let mut garbled_table: [EncryptedWireValue; 4] = Default::default();
        for a_bit in [false, true] {
            for b_bit in [false, true] {
                let a_val = if a_bit {&a.1} else {&a.0};
                let a_idx = a_val[0]&1;
                let b_val = if b_bit {&b.1} else {&b.0};
                let b_idx = b_val[0]&1;
                let idx_garbled = (2*a_idx + b_idx) as usize;
                let idx_real = 2*(a_bit as usize) + (b_bit as usize);
                let out_bit = table[idx_real];
                let out_val = if out_bit {&out.1} else {&out.0};
                
                let out_enc = encrypt(a_val, b_val, out_val);
                garbled_table[idx_garbled] = out_enc;

            }
        } 
        Self {table: garbled_table}
    }

    pub fn evaluate(&self, a: &GarbledWireValue, b: &GarbledWireValue) -> GarbledWireValue {
        let a_bit = a[0]&1;
        let b_bit = b[0]&1;
        let idx = 2*a_bit + b_bit;
        decrypt(a, b, &self.table[idx as usize])
    }
}

impl OutputTable {
    pub fn new(w: &GarbledWire) -> Self {
        let enc0 = encrypt(&w.0, &w.0, &OUT0);
        let enc1 = encrypt(&w.1, &w.1, &OUT1);
        if w.0[0]&1 == 0 {
            Self{table: [enc0, enc1]}
        } else {
            Self{table: [enc1, enc0]}
        }
    }

    pub fn evaluate(&self, w: &GarbledWireValue) -> Option<bool> {
        let t = &self.table[(w[0]&1) as usize];
        let v = decrypt(w, w, t);
        match v {
            OUT0 => Some(false),
            OUT1 => Some(true),
            _ => None,
        }
    }
}


#[derive(Serialize, Deserialize)]
pub struct GarbledCircuitContent {
    pub gates: Vec<GarbledGate>,
    pub outputs: Vec<OutputTable>,
}

pub struct GarbledCircuit<'a> {
    pub circuit: &'a Circuit,
    pub content: GarbledCircuitContent,
}


pub struct GarbledCircuitPrivate<'a> {
    pub garbled: GarbledCircuit<'a>,
    pub alice_ins: Vec<GarbledWire>,
    pub bob_ins: Vec<GarbledWire>,
}

impl<'a> RngGenerateWith<&'a Circuit> for GarbledCircuitPrivate<'a> {
    fn generate_with(rng: &mut Rng, circuit: &'a Circuit) -> Self {
        let mut r0: GarbledWireValue = RngGenerate::generate(rng);
        r0[0] |= 1;
        let mut r1: GarbledWireValue = RngGenerate::generate(rng);
        r1[0] |= 1;
        let const0: GarbledWire = GarbledWire([0u8; 16], r0);
        let const1: GarbledWire = GarbledWire(r1, [0u8; 16]);

        let mut alice = Vec::new();
        for _ in 0..circuit.alice_inputs {
            alice.push(GarbledWire::generate(rng));
        }
        let mut bob = Vec::new();
        for _ in 0..circuit.bob_inputs {
            bob.push(GarbledWire::generate(rng));
        }

        let mut gate_wires = Vec::with_capacity(circuit.gates.len());
        let get_input = |inp: &GateInput, gate_wires: &[GarbledWire]| {
            match inp {
                GateInput::AliceInput(i) => alice[*i],
                GateInput::BobInput(i) => bob[*i],
                GateInput::Gate(i) => gate_wires[*i],
                GateInput::Constant(false) => const0,
                GateInput::Constant(true) => const1,
            }
        };

        let gates: Vec<GarbledGate> = circuit.gates.iter().map(|Gate(x, y, table)| {
            let a = get_input(x, &gate_wires);
            let b = get_input(y, &gate_wires);
            let out = GarbledWire::generate(rng);
            let gate = GarbledGate::new(table, &a, &b, &out);

            gate_wires.push(out);
            gate
        }).collect();

        let outputs = circuit.outputs.iter().map(|o| {
            OutputTable::new(&get_input(o, &gate_wires))
        }).collect();

        let gc = GarbledCircuit {
            circuit, content: GarbledCircuitContent {gates, outputs},
        };

        Self {
            garbled: gc,
            alice_ins: alice,
            bob_ins: bob,
        }
    }
}

impl<'a> GarbledCircuit<'a> {
    pub fn evaluate(&self, alice_in: &[GarbledWireValue], bob_in: &[GarbledWireValue]) -> Option<Vec<bool>> {
        let mut wires: Vec<GarbledWireValue> = Vec::with_capacity(self.circuit.gates.len());
        let get_input = |inp: &GateInput, wires: &[GarbledWireValue]| {
            match inp {
                GateInput::AliceInput(i) => alice_in[*i],
                GateInput::BobInput(i) => bob_in[*i],
                GateInput::Gate(i) => wires[*i],
                GateInput::Constant(_) => [0u8; 16],
            }
        };

        for (Gate(x,y,_), g) in self.circuit.gates.iter().zip(self.content.gates.iter()) {
            let a = get_input(x, &wires);
            let b = get_input(y, &wires);
            let c = g.evaluate(&a, &b);
            wires.push(c);
        }

        let mut res = Vec::with_capacity(self.circuit.outputs.len());
        for (out, table) in self.circuit.outputs.iter().zip(self.content.outputs.iter()) {
            let ev = table.evaluate(&get_input(out, &wires))?;
            res.push(ev);
        }
        Some(res)
    }
}

impl HashViaSerialize for GarbledCircuitContent {}