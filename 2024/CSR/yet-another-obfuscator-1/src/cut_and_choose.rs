use std::io::{Read, Write};

use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;
use crate::garble::{decrypt, encrypt, GarbledCircuit, GarbledCircuitContent, GarbledWire, GarbledWireValue};
use crate::hashable::{Hash, Hashable};
use crate::oblivious_transfer::{OTClient, OTServer};
use std::io::Error;

use crate::rng::Rng;
use crate::{circuit::Circuit, garble::GarbledCircuitPrivate, rng::{RngGenerate, RngGenerateWith, Seed}};


const N_CIRCUITS: usize = 128;
const N_REVEAL: usize = 64;

pub struct CutAndChooseServer<'a> {
    circuit: &'a Circuit,
    inputs: &'a [bool],
}

fn other_indices(indices: &[usize]) -> Vec<usize> {
    let mut result = Vec::with_capacity(N_CIRCUITS - N_REVEAL);
    let mut j = 0;
    for i in 0..N_CIRCUITS {
        if j < indices.len() && indices[j] == i {
            j += 1;
        } else {
            result.push(i);
        }
    }
    result
}

impl<'a> CutAndChooseServer<'a> {
    pub fn new(circuit: &'a Circuit, inputs: &'a [bool]) -> Self {
        Self {circuit, inputs}
    }


    pub fn run<C>(&self, mut channel: C) -> bincode::Result<Vec<bool>>
        where C : Read + Write {

        let mut rng = ChaCha20Rng::from_entropy();
        let mut garbled_circuits = Vec::with_capacity(N_CIRCUITS);
        let mut seeds = Vec::with_capacity(N_CIRCUITS);
        let mut hashes = Vec::with_capacity(N_CIRCUITS);

        for _ in 0..N_CIRCUITS {
            let seed: Seed = RngGenerate::generate(&mut rng);
            seeds.push(seed);
            let gc = GarbledCircuitPrivate::from_seed_with(seed, self.circuit);
            let hash = gc.garbled.content.hash();
            garbled_circuits.push(gc);
            hashes.push(hash);
        }

        // (1) send hashes of all circuits
        bincode::serialize_into(&mut channel, &hashes)?;

        // (2) send all encrypted Bob inputs
        let mut input_keys = Vec::with_capacity(self.circuit.bob_inputs);
        for _ in 0..self.circuit.bob_inputs {
            input_keys.push(GarbledWire::generate(&mut rng));
        }

        for gc in garbled_circuits.iter() {
            let mut encrypted_inputs = Vec::with_capacity(self.circuit.bob_inputs);
            for (bin, k) in gc.bob_ins.iter().zip(input_keys.iter()) {
                let e0 = encrypt(&k.0, &k.0, &bin.0);
                let e1 = encrypt(&k.1, &k.1, &bin.1);
                encrypted_inputs.push(GarbledWire(e0,e1));
            }
            bincode::serialize_into(&mut channel, &encrypted_inputs)?;
        }

        // (3) Do Oblivious Transfer
        let mut otserv = OTServer::new(Rng::from_rng(&mut rng).unwrap());
        otserv.run(&mut channel, &input_keys)?;


        // (4) Receive cut indices
        let reveal_indices: Vec<usize> = bincode::deserialize_from(&mut channel)?;
        let run_indices = other_indices(&reveal_indices);
        if reveal_indices.len() != N_REVEAL {
            return Err(Error::other("Bob has sent an invalid number of circuits to reveal").into());
        }

        for i in 0..N_REVEAL-1 {
            if reveal_indices[i] >= reveal_indices[i+1] {
                return Err(Error::other("Indices not in ascending order").into());
            }
        }

        // (5) Reveal RNG seeds for the cut circuits
        let reveal_seeds: Vec<Seed> = reveal_indices.iter().map(|i| seeds[*i]).collect();
        bincode::serialize_into(&mut channel, &reveal_seeds)?;

        // (6) Send circuits to run, and Alice inputs
        for idx in run_indices {
            let mut alice_ins = Vec::with_capacity(self.circuit.alice_inputs);
            for b in 0..self.circuit.alice_inputs {
                let ain = garbled_circuits[idx].alice_ins[b];
                alice_ins.push(ain.select(self.inputs[b]));
            }
            bincode::serialize_into(&mut channel, &garbled_circuits[idx].garbled.content)?;
            bincode::serialize_into(&mut channel, &alice_ins)?;
        }

        // (7) Receive evaluation results (untrusted)
        let results: Vec<bool> = bincode::deserialize_from(&mut channel)?;

        if results.len() != self.circuit.outputs.len() {
            return Err(Error::other("Invalid number of outputs").into());
        }

        Ok(results)

    }

}


pub struct CutAndChooseClient<'a> {
    circuit: &'a Circuit,
    inputs: &'a [bool],
}

fn average_results(evaluations: &[Vec<bool>]) -> Vec<bool> {
    let mut totals = vec![0usize; evaluations[0].len()];
    for ev in evaluations {
        for i in 0..ev.len() {
            if ev[i] {
                totals[i] += 1;
            }
        }
    }

    totals.into_iter().map(|x| x >= evaluations.len()/2).collect()
}

impl<'a> CutAndChooseClient<'a> {
    pub fn new(circuit: &'a Circuit, inputs: &'a [bool]) -> Self {
        Self {circuit, inputs}
    }


    pub fn run<C>(&self, mut channel: C) -> bincode::Result<Vec<bool>>
        where C : Read + Write {
        let mut rng = ChaCha20Rng::from_entropy();

        // (1) Receive hashes of all circuits
        let hashes: Vec<Hash> = bincode::deserialize_from(&mut channel)?;
        if hashes.len() != N_CIRCUITS {
            return Err(Error::other("Invalid number of circuits received").into());
        }

        // (2) Receive encrypted bob inputs
        let mut encrypted_inputs = Vec::with_capacity(N_CIRCUITS);
        for _ in 0..N_CIRCUITS {
            let enc: Vec<GarbledWire> = bincode::deserialize_from(&mut channel)?;
            if enc.len() != self.circuit.bob_inputs {
                return Err(Error::other("Invalid number of encrypted inputs recieved").into());
            }
            encrypted_inputs.push(enc);
        }
        
        // (3) Do Oblivious Transfer
        let mut otclient = OTClient::new(Rng::from_rng(&mut rng).unwrap());
        let keys = otclient.run(&mut channel, self.inputs)?;

        
        // (4) Send cut indices
        let indices: Vec<usize> = (0..N_CIRCUITS).collect();
        let mut reveal_indices: Vec<usize> = indices.choose_multiple(&mut rng, N_REVEAL).cloned().collect();
        reveal_indices.sort();
        let run_indices = other_indices(&reveal_indices);
        bincode::serialize_into(&mut channel, &reveal_indices)?;

        
        // (5) Receive and check RNG seeds for cut circuits
        let reveal_seeds: Vec<Seed> = bincode::deserialize_from(&mut channel)?;
        
        if reveal_seeds.len() != reveal_indices.len() {
            return Err(Error::other("Invalid number of revealed seeds received").into());
        }

        for (seed, idx) in reveal_seeds.iter().cloned().zip(reveal_indices.iter()) {
            let gc = GarbledCircuitPrivate::from_seed_with(seed, self.circuit);
            let hash = gc.garbled.content.hash();
            if hash != hashes[*idx] {
                return Err(Error::other("Hash of revealed circuit does not match - cheating detected!").into());
            }
            let enc_input = &encrypted_inputs[*idx];
            for b in 0..self.circuit.bob_inputs {
                let input_received = decrypt(&keys[b], &keys[b], &enc_input[b].select(self.inputs[b]));
                let input_actual = gc.bob_ins[b].select(self.inputs[b]);
                if input_received != input_actual {
                    return Err(Error::other("Input does not match - cheating detected!").into());
                }
            }
        }


        // (6) Evaluate Circuits
        let mut evals = Vec::with_capacity(N_CIRCUITS-N_REVEAL);
        for idx in run_indices {
            let gc: GarbledCircuitContent = bincode::deserialize_from(&mut channel)?;
            if gc.hash() != hashes[idx] {
                return Err(Error::other("Circuit has wrong hash - cheating detected!").into());
            }
            let gc = GarbledCircuit {content: gc, circuit: self.circuit};
            let alice_ins: Vec<GarbledWireValue> = bincode::deserialize_from(&mut channel)?;
            if alice_ins.len() != self.circuit.alice_inputs {
                return Err(Error::other("Length of Alice inputs does not match").into());
            }
            let mut bob_ins = Vec::with_capacity(self.circuit.bob_inputs);

            for b in 0..self.circuit.bob_inputs {
                let enc_in = encrypted_inputs[idx][b].select(self.inputs[b]);
                let input = decrypt(&keys[b], &keys[b], &enc_in);
                bob_ins.push(input);
            }

            if let Some(eval) = gc.evaluate(&alice_ins, &bob_ins) {
                evals.push(eval);
            }
        }

        if evals.is_empty() {
            return Err(Error::other("All evaluations failed").into());
        }
        
        // (7) Average results and send

        let eval = average_results(&evals);
        bincode::serialize_into(&mut channel, &eval)?;

        Ok(eval)
    }
}