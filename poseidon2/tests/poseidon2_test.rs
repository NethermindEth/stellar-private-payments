use zkhash::{
    fields::bn256::FpBN256,
    poseidon2::{
        poseidon2::Poseidon2,
        poseidon2_instance_bn256::{
            POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3, POSEIDON2_BN256_PARAMS_4,
        },
    },
};

#[test]
fn bn256_instances() {
    type Scalar = FpBN256;
    // T = 2
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let t = poseidon2.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
    let perm = poseidon2.permutation(&input);
    assert_eq!(perm.len(), t);
    // T = 3
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
    let t = poseidon2.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
    let perm = poseidon2.permutation(&input);
    assert_eq!(perm.len(), t);
    // T = 4
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_4);
    let t = poseidon2.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
    let perm = poseidon2.permutation(&input);
    assert_eq!(perm.len(), t);
}
