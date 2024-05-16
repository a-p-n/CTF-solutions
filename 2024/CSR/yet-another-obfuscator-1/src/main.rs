mod circuit;
mod garble;
mod rng;
mod cut_and_choose;
mod hashable;
mod oblivious_transfer;

use std::{fs, net::TcpListener, thread};

use circuit::Circuit;
use cut_and_choose::CutAndChooseClient;
use kctf_pow::KctfPow;
use rand::{thread_rng, Fill};

const INPUTLEN: usize = 128;
const POW_DIFFICULTY: u32 = 1337;

fn main() {
    let mut circuit = Circuit::new(INPUTLEN,INPUTLEN);
    let alice = circuit.get_alice_inputs();
    let bob = circuit.get_bob_inputs();
    let diff = circuit.bitwise_xor(&alice, &bob);
    let any_diff = circuit.or_nary(&diff);
    let out = circuit.not(any_diff);
    circuit.add_output(out);
    let circuit = Box::leak(Box::new(circuit)) as &Circuit;

    let flag = fs::read_to_string("./flag.txt").expect("Could not read flag");
    let flag = Box::leak(Box::new(flag)) as &String;

    let pow = Box::leak(Box::new(KctfPow::new())) as &KctfPow;

    
    let listener = TcpListener::bind("0.0.0.0:1373").expect("Could not start listener");
    for client in listener.incoming() {
        match client {
            Ok(stream) => {
                thread::spawn(move || { 
                let challenge = pow.generate_challenge(POW_DIFFICULTY);
                if let Err(_) = bincode::serialize_into(&stream, &challenge.to_string()) {
                    println!("Couldn't send pow");
                    return;
                }
                let pow_solution: String = match bincode::deserialize_from(&stream) {
                    Ok(s) => s,
                    Err(err) => {println!("Couldn't read pow: {}", err); return}
                };
                if challenge.check(&pow_solution) != Ok(true) { 
                    println!("Invalid POW");
                }
    

                let mut input = [false; INPUTLEN];
                if let Err(err) = input.try_fill(&mut thread_rng()) {
                    println!("Could not get randomness: {:?}", err);
                    return;
                }
                let server = CutAndChooseClient::new(circuit, &input);
                match server.run(&stream) {
                    Ok(res) => {
                    	println!("Run successfully with output {:?}", res[0]);
                        if res[0] {
                            let _ = bincode::serialize_into(&stream, flag);
                        }
                    }
                    Err(err) => {
                        println!("Execution error: {:?}", err);
                    }
                }
                
            });}
            Err(err) =>  {
                println!("Connection error: {:?}", err);
            }
        }
    }
}
