use std::io::{Read, Write};

use rand::Rng as _;
use rsa::{traits::{PublicKeyParts, PrivateKeyParts}, RsaPrivateKey, RsaPublicKey};

use crate::{garble::{GarbledWire, GarbledWireValue}, rng::Rng};
use num_bigint_dig::{BigUint, RandBigInt};
use std::io::Error;

const RSA_BITS: usize = 1024;

pub struct OTServer {
    pub rng: Rng,
    pub key: RsaPrivateKey,
}

fn bytes_to_rsamessage(rng: &mut Rng, bytes: &[u8]) -> BigUint {
    // PKCS #1 v1.5 padding
    let mut v: Vec<u8> = Vec::with_capacity(RSA_BITS/8);
    v.extend(bytes);
    v.push(0);
    while v.len() < (RSA_BITS/8)-2 {
        let pad = rng.gen_range(1..=255u8);
        v.push(pad);
    }
    v.push(2);

    BigUint::from_bytes_le(&v)

}

impl OTServer {
    pub fn new(mut rng: Rng) -> Self {
        let key = RsaPrivateKey::new(&mut rng, RSA_BITS).expect("Couldn't generate RSA key");
        Self {key, rng}
    }

    pub fn run<C>(&mut self, mut channel: C, wires: &[GarbledWire]) -> bincode::Result<()>
        where C : Read + Write {
            let pubkey = self.key.to_public_key();
            let n = pubkey.n();
            let d = self.key.d();

            let mut xs = Vec::with_capacity(wires.len());

            for _ in 0..wires.len() {
                let x0 = self.rng.gen_biguint_below(n);
                let x1 = self.rng.gen_biguint_below(n);
                xs.push((x0, x1));
            }

            bincode::serialize_into(&mut channel, &pubkey)?;
            bincode::serialize_into(&mut channel, &xs)?;

            let vs: Vec<BigUint> = bincode::deserialize_from(&mut channel)?;

            if vs.len() != wires.len() {
                return Err(Error::other("Received incorrect number of v values").into());
            }

            let mut ms = Vec::with_capacity(wires.len());
            for i in 0..wires.len() {
                let k0 = (vs[i].clone()+n-&xs[i].0).modpow(d, n);
                let k1 = (vs[i].clone()+n-&xs[i].1).modpow(d, n);
                let mut m0 = bytes_to_rsamessage(&mut self.rng, &wires[i].0);
                let mut m1 = bytes_to_rsamessage(&mut self.rng, &wires[i].1);
                m0 += k0;
                m0 %= n;
                m1 += k1;
                m1 %= n;
                ms.push((m0, m1));
            }
            bincode::serialize_into(&mut channel, &ms)?;

            Ok(())    
        }
}

pub struct OTClient {
    pub rng: Rng,
}

impl OTClient {
    pub fn new(rng: Rng) -> Self {
        Self {rng}
    }

    pub fn run<C>(&mut self, mut channel: C, bits: &[bool]) -> bincode::Result<Vec<GarbledWireValue>>
        where C : Read + Write {
        let pubkey: RsaPublicKey = bincode::deserialize_from(&mut channel)?;
        let n = pubkey.n();
        let e = pubkey.e();
        if n.bits() != RSA_BITS || e != &BigUint::from(65537u64) {
            return Err(Error::other("Invalid RSA key").into());
        }
        let xs: Vec<(BigUint, BigUint)> = bincode::deserialize_from(&mut channel)?;
        
        if xs.len() != bits.len() {
            return Err(Error::other("Number of received (x0,x1) pairs does not match number of input bits").into());
        }

        let mut ks = Vec::with_capacity(bits.len());
        let mut vs = Vec::with_capacity(bits.len());
        for i in 0..bits.len() {
            let k = self.rng.gen_biguint_below(n);
            let (x0, x1) = &xs[i];
            if x0.ge(n) || x1.ge(n) {
                return Err(Error::other("BigInt input exceeds n").into());
            }
            let mut v = k.modpow(e, n);
            v += if bits[i] {x1} else {x0};
            v %= n;
            ks.push(k);
            vs.push(v);
        }

        bincode::serialize_into(&mut channel, &vs)?;
        let ms: Vec<(BigUint, BigUint)> = bincode::deserialize_from(&mut channel)?;
        if ms.len() != bits.len() {
            return Err(Error::other("Number of received (m0,m1) pairs does not match number of input bits").into());
        }

        let mut res = Vec::with_capacity(bits.len());
        let mask16 = (BigUint::from(1u8) << 128)-BigUint::from(1u8);
        for i in 0..bits.len() {
            let mut m = (if bits[i] {&ms[i].1} else {&ms[i].0}).clone();
            m -= &ks[i];
            let mut mb = (m & (&mask16)).to_bytes_le();
            while mb.len() < 16 {
                mb.push(0);
            }
            res.push(mb.try_into().unwrap());
        }
        Ok(res)

    }
}
