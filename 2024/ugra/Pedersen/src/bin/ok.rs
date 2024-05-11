use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_ng::scalar::Scalar;
use bulletproofs::PedersenGens;
use rand::thread_rng;
use base64::prelude::*;
use hex::ToHex;
use serde::{Serialize, Deserialize};
use std::convert::TryInto;


#[derive(Serialize, Deserialize)]
struct Wallet {
    commitment: String,
    blinding: String,
    balance: u128,
}

#[derive(Debug)]
struct BadRequest(&'static str);

fn checkout<'a>(wallet: &'a str) -> Result<String, BadRequest> {
    let json_wallet = BASE64_STANDARD.decode(wallet.as_bytes()).map_err(|_| BadRequest("Invalid wallet"))?;

    let wallet: Wallet = serde_json::from_str(&String::from_utf8(json_wallet).map_err(|_| BadRequest("Invalid wallet"))?).map_err(|_| BadRequest("Invalid wallet"))?;

    let commitment = match hex::decode(&wallet.commitment) {
        Ok(bytes) if bytes.len() == 32 => CompressedRistretto::from_slice(&bytes),
        _ => return Err(BadRequest("Invalid commitment"))
    };

    let balance = Scalar::from(wallet.balance);

    let blinding = match hex::decode(&wallet.blinding) {
        Ok(bytes) if bytes.len() == 32 => Scalar::from_bytes_mod_order(bytes.try_into().expect("Invalid length")),
        _ => return Err(BadRequest("Invalid blinding"))
    };
    
    let pedersen_gen = PedersenGens::default();
    let final_point = commitment.decompress().ok_or(BadRequest("Decompression failed"))?;
    let diff = pedersen_gen.commit(balance, blinding);
    
    let result_point = final_point - diff; 
    let mut rng = thread_rng();
    let scalar1 = Scalar::random(&mut rng);
    let min_value = Scalar::from(1337u128);
    let forge = pedersen_gen.commit(min_value, scalar1);
    let forge_point = forge + result_point; 


    let updated_wallet = Wallet {
        commitment: forge_point.compress().as_bytes().encode_hex::<String>(),
        blinding: scalar1.as_bytes().encode_hex::<String>(),
        balance: 1337,
    };

    Ok(BASE64_STANDARD.encode(&serde_json::to_string(&updated_wallet).unwrap().as_bytes()))
}

fn main() {
    let wallet_str = ""; //input wallet string
    match checkout(wallet_str) {
        Ok(updated_wallet_base64) => println!("Updated Wallet: {}", updated_wallet_base64),
        Err(e) => println!("Error: {:?}", e),
    }
}