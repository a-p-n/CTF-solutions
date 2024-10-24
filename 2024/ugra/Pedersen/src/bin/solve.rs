use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar};
use bulletproofs::PedersenGens;
use hex::ToHex;

fn main() {
    let commitment_hex = "5a0575e6d89a2b21db5d50a59e723b5a418e5926e3d858bc905a89038dc9b97d";

    let commitment = match hex::decode(commitment_hex) {
        Ok(bytes) if bytes.len() == 32 => CompressedRistretto::from_slice(bytes.as_slice()),
        _ => return
    }.decompress().unwrap();

    let constant = Scalar::from(1237u128);
    let new_commitment = commitment + PedersenGens::default().B * constant;

    println!("Set commitment to {}", new_commitment.compress().as_bytes().encode_hex::<String>());
}