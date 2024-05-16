use sha2::{Sha256, Digest};
use serde::Serialize;

pub type Hash = [u8; 32];

pub trait Hashable {
    fn hash(&self) -> Hash;
}

pub trait HashViaSerialize : Serialize {}


impl<T> Hashable for T where T : HashViaSerialize {
    fn hash(&self) -> Hash {
        let mut sha = Sha256::new();  
        bincode::serialize_into(&mut sha, self).expect("Could not serialize for hashing");
        let digest = sha.finalize();
        digest.into()
    }
}