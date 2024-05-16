use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand::Fill;

pub type Rng = ChaCha20Rng;
pub type Seed = <Rng as SeedableRng>::Seed;


pub trait RngGenerateWith<T> {
    fn generate_with(rng: &mut Rng, data: T) -> Self;
    fn from_seed_with(seed: Seed, data: T) -> Self where Self: Sized {
        let mut rng = Rng::from_seed(seed);
        Self::generate_with(&mut rng, data)
    }
}


pub trait RngGenerate {
    fn generate(rng: &mut Rng) -> Self;
    #[allow(dead_code)]
    fn from_seed(seed: Seed) -> Self where Self: Sized {
        let mut rng = Rng::from_seed(seed);
        Self::generate(&mut rng)
    }
}

impl<T> RngGenerate for T where T: RngGenerateWith<()> {
    fn generate(rng: &mut Rng) -> Self {
        Self::generate_with(rng, ())
    }
}

impl<T> RngGenerateWith<()> for T where T: Fill + Default {
    fn generate_with(rng: &mut Rng, _data: ()) -> Self {
        let mut r = Self::default();
        r.try_fill(rng).unwrap();
        r
    }
}