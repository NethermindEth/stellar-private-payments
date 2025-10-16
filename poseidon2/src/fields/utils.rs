use ark_ff::PrimeField;
use hex::FromHex;
// use rand::Rng; // unused import

pub fn from_hex<F: PrimeField>(s: &str) -> F {
    let a = Vec::from_hex(&s[2..]).expect("Invalid Hex String");
    F::from_be_bytes_mod_order(&a as &[u8])
}

pub fn random_scalar<F: PrimeField>() -> F {
    let mut rng = ark_std::rand::thread_rng();
    F::rand(&mut rng)
}

pub fn random_scalar_without_0<F: PrimeField>() -> F {
    loop {
        let element = random_scalar::<F>();
        if !element.is_zero() {
            return element;
        }
    }
}
