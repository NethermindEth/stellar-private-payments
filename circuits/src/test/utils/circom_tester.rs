use anyhow::{Result, anyhow};
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use std::fmt::Display;
use std::{collections::HashMap, fmt, path::Path};

#[derive(Clone, Debug)]
pub struct SignalKey(String);

impl SignalKey {
    pub fn new(base: impl Into<String>) -> Self {
        Self(base.into())
    }

    pub fn idx(mut self, i: usize) -> Self {
        self.0.push('[');
        self.0.push_str(&i.to_string());
        self.0.push(']');
        self
    }

    pub fn field(mut self, name: &str) -> Self {
        self.0.push('.');
        self.0.push_str(name);
        self
    }
}

impl Display for SignalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Allow common types to be converted into InputValue.
pub trait IntoInputValue {
    fn into_input_value(self) -> InputValue;
}

impl IntoInputValue for BigInt {
    fn into_input_value(self) -> InputValue {
        InputValue::Single(self)
    }
}
impl IntoInputValue for &BigInt {
    fn into_input_value(self) -> InputValue {
        InputValue::Single(self.clone())
    }
}
impl IntoInputValue for Vec<BigInt> {
    fn into_input_value(self) -> InputValue {
        InputValue::Array(self)
    }
}

#[derive(Default)]
pub struct Inputs {
    inner: HashMap<String, InputValue>,
}

impl Inputs {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Set with a plain string key (e.g., "root").
    pub fn set<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: IntoInputValue,
    {
        self.inner.insert(key.into(), value.into_input_value());
    }

    /// Set using a SignalKey path (e.g., membershipProofs[0][0].leaf).
    pub fn set_key<V>(&mut self, key: &SignalKey, value: V)
    where
        V: IntoInputValue,
    {
        self.inner.insert(key.to_string(), value.into_input_value());
    }
}

impl Inputs {
    pub fn into_map(self) -> HashMap<String, InputValue> {
        self.inner
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum InputValue {
    Single(BigInt),
    Array(Vec<BigInt>),
}
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CircomResult {
    pub verified: bool,
    pub public_inputs: Vec<Fr>, /* this can be a trait but we dont care about generalising that
                                 * much now */
    pub proof: Proof<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

fn push_value(builder: &mut CircomBuilder<Fr>, path: &str, value: &InputValue) {
    match value {
        InputValue::Single(v) => {
            builder.push_input(path, v.clone());
        }
        InputValue::Array(arr) => {
            for v in arr.iter() {
                builder.push_input(path, v.clone())
            }
        }
    }
}

pub fn prove_and_verify(
    wasm_path: impl AsRef<Path>,
    r1cs_path: impl AsRef<Path>,
    inputs: &HashMap<String, InputValue>,
) -> Result<CircomResult> {
    let cfg = CircomConfig::<Fr>::new(wasm_path.as_ref(), r1cs_path.as_ref())
        .map_err(|e| anyhow!("CircomConfig error: {e}"))?;

    let mut builder = CircomBuilder::new(cfg);

    for (signal, value) in inputs {
        push_value(&mut builder, signal, value);
    }

    let empty = builder.setup();
    let mut rng = thread_rng();

    let (pk, vk) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(empty, &mut rng)
        .map_err(|e| anyhow!("circuit_specific_setup failed: {e}"))?;

    let circuit = builder.build().map_err(|e| anyhow!("build failed: {e}"))?;

    let proof = Groth16::<Bn254, CircomReduction>::prove(&pk, circuit.clone(), &mut rng)
        .map_err(|e| anyhow!("prove failed: {e}"))?;

    // Extract public inputs and verify
    let public_inputs = circuit
        .get_public_inputs()
        .ok_or_else(|| anyhow!("get_public_inputs returned None"))?;
    let pvk = Groth16::<Bn254, CircomReduction>::process_vk(&vk)
        .map_err(|e| anyhow!("process_vk failed: {e}"))?;
    let verified =
        Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
            .map_err(|e| anyhow!("verify_with_processed_vk failed: {e}"))?;

    Ok(CircomResult {
        verified,
        public_inputs,
        proof,
        vk,
    })
}
