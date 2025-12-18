use super::general::scalar_to_bigint;
use anyhow::{Result, anyhow};
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use std::fmt::Display;
use std::{collections::HashMap, fmt, path::Path};
use zkhash::fields::bn256::FpBN256 as Scalar;

#[derive(Clone, Debug)]
pub struct SignalKey(String);

/// Represents a Circom-style hierarchical signal path.
impl SignalKey {
    /// Creates a new base signal key.
    pub fn new(base: impl Into<String>) -> Self {
        Self(base.into())
    }

    /// Appends an array index (`[...]`) to the key.
    pub fn idx(mut self, i: usize) -> Self {
        self.0.push('[');
        self.0.push_str(&i.to_string());
        self.0.push(']');
        self
    }

    /// Appends a field accessor (`.field`) to the key.
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
impl From<BigInt> for InputValue {
    fn from(value: BigInt) -> Self {
        InputValue::Single(value)
    }
}

impl From<&BigInt> for InputValue {
    fn from(value: &BigInt) -> Self {
        InputValue::Single(value.clone())
    }
}

impl From<Vec<BigInt>> for InputValue {
    fn from(value: Vec<BigInt>) -> Self {
        InputValue::Array(value)
    }
}

impl From<Scalar> for InputValue {
    fn from(value: Scalar) -> Self {
        InputValue::Single(scalar_to_bigint(value))
    }
}

impl From<&Scalar> for InputValue {
    fn from(value: &Scalar) -> Self {
        InputValue::Single(scalar_to_bigint(*value))
    }
}

impl From<Vec<Scalar>> for InputValue {
    fn from(values: Vec<Scalar>) -> Self {
        InputValue::Array(values.into_iter().map(scalar_to_bigint).collect())
    }
}

/// Storage for Circom input signals.
/// Wraps a hashmap of `String → InputValue`.
///
/// Example:
///
/// ```
/// use circuits::test::utils::circom_tester::{Inputs, SignalKey};
/// use zkhash::fields::bn256::FpBN256 as Scalar;
/// let mut inputs = Inputs::new();
/// inputs.set("root", Scalar::from(5));
/// inputs.set_key(&SignalKey::new("arr").idx(0), Scalar::from(10));
/// ```
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

    /// Sets an input using a plain string key.
    pub fn set<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<InputValue>,
    {
        self.inner.insert(key.into(), value.into());
    }

    /// Set using a SignalKey path (e.g., membershipProofs[0][0].leaf).
    pub fn set_key<V>(&mut self, key: &SignalKey, value: V)
    where
        V: Into<InputValue>,
    {
        self.inner.insert(key.to_string(), value.into());
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &InputValue)> {
        self.inner.iter()
    }
}

/// Represents a single Circom input value
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum InputValue {
    Single(BigInt),
    Array(Vec<BigInt>),
}

/// Contains the Groth16 proving key (pk),
/// verifying key (vk), and the *processed* verifying key (pvk).
#[derive(Clone)]
pub struct CircuitKeys {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
    pub pvk: PreparedVerifyingKey<Bn254>,
}

/// Result of proving + verifying a Circom circuit
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CircomResult {
    pub verified: bool,
    pub public_inputs: Vec<Fr>, /* this can be a trait but we dont care about generalising that
                                 * much now */
    pub proof: Proof<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

/// Generates Groth16 proving + verifying keys for a Circom circuit.
/// This operation is expensive and should be done once when testing
/// many input combinations.
pub fn generate_keys(
    wasm_path: impl AsRef<Path>,
    r1cs_path: impl AsRef<Path>,
) -> Result<CircuitKeys> {
    let cfg = CircomConfig::<Fr>::new(wasm_path.as_ref(), r1cs_path.as_ref())
        .map_err(|e| anyhow!("CircomConfig error: {e}"))?;

    let builder = CircomBuilder::new(cfg);

    // No inputs: just the empty circuit for setup
    let empty = builder.setup();
    let mut rng = thread_rng();

    let (pk, vk) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(empty, &mut rng)
        .map_err(|e| anyhow!("circuit_specific_setup failed: {e}"))?;

    let pvk = Groth16::<Bn254, CircomReduction>::process_vk(&vk)
        .map_err(|e| anyhow!("process_vk failed: {e}"))?;

    Ok(CircuitKeys { pk, vk, pvk })
}

/// Proves and verifies a Circom circuit using precomputed Groth16 keys.
/// This is the preferred function when repeated proofs must be generated.
///
/// Steps:
/// 1. Load Circom config (WASM + R1CS)
/// 2. Build circuit with provided inputs
/// 3. Generate Groth16 proof using precomputed `pk`
/// 4. Verify the proof using fast `pvk`
///
/// Returns `CircomResult`.
pub fn prove_and_verify_with_keys(
    wasm_path: impl AsRef<Path>,
    r1cs_path: impl AsRef<Path>,
    inputs: &Inputs,
    keys: &CircuitKeys,
) -> Result<CircomResult> {
    let cfg = CircomConfig::<Fr>::new(wasm_path.as_ref(), r1cs_path.as_ref())
        .map_err(|e| anyhow!("CircomConfig error: {e}"))?;

    let mut builder = CircomBuilder::new(cfg);

    for (signal, value) in inputs.iter() {
        push_value(&mut builder, signal, value);
    }

    let circuit = builder.build().map_err(|e| anyhow!("build failed: {e}"))?;

    let mut rng = thread_rng();

    let proof = Groth16::<Bn254, CircomReduction>::prove(&keys.pk, circuit.clone(), &mut rng)
        .map_err(|e| anyhow!("prove failed: {e}"))?;

    let public_inputs = circuit
        .get_public_inputs()
        .ok_or_else(|| anyhow!("get_public_inputs returned None"))?;

    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &keys.pvk,
        &public_inputs,
        &proof,
    )
    .map_err(|e| anyhow!("verify_with_processed_vk failed: {e}"))?;

    Ok(CircomResult {
        verified,
        public_inputs,
        proof,
        vk: keys.vk.clone(),
    })
}

/// Internal helper for adding input values into the Circom builder.
/// Arrays are pushed element-by-element.
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

/// Proves and verifies a Circom circuit, generating keys on each call
///
/// Convenience function that generates Groth16 keys and then proves and verifies
/// the circuit. This is simpler to use but less efficient for repeated proofs
/// since key generation is expensive. For multiple proofs with the same circuit,
/// use `generate_keys` once and then call `prove_and_verify_with_keys` repeatedly.
///
/// # Arguments
///
/// * `wasm_path` - Path to the compiled WASM file for witness generation
/// * `r1cs_path` - Path to the R1CS constraint system file
/// * `inputs` - Circuit input values to use for proving
///
/// # Returns
///
/// Returns `Ok(CircomResult)` containing the verification result, proof, public inputs,
/// and verifying key, or an error if key generation, proving, or verification fails.
pub fn prove_and_verify(
    wasm_path: impl AsRef<Path>,
    r1cs_path: impl AsRef<Path>,
    inputs: &Inputs,
) -> Result<CircomResult> {
    let keys = generate_keys(&wasm_path, &r1cs_path)?;
    prove_and_verify_with_keys(wasm_path, r1cs_path, inputs, &keys)
}
