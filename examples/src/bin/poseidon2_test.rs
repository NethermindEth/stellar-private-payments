use zkhash::{
    fields::bn256::FpBN256,
    poseidon2::{
        poseidon2::Poseidon2,
        poseidon2_instance_bn256::{
            POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3, POSEIDON2_BN256_PARAMS_4,
        },
    },
};

fn main() {
    type Scalar = FpBN256;
    // T = 2
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let t = poseidon2.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
    let perm = poseidon2.permutation(&input);
    println!(
        "POSEIDON2 (t={t}) HASH(0,1): { }",
        perm.iter()
            .map(|x| format!("{x}"))
            .collect::<Vec<String>>()
            .join(", ")
    );

    // T = 3
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
    let t = poseidon2.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
    let perm = poseidon2.permutation(&input);
    println!(
        "POSEIDON2 (t={t}) HASH(0, 1, 2): { }",
        perm.iter()
            .map(|x| format!("{x}"))
            .collect::<Vec<String>>()
            .join(", ")
    );

    // T = 4
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_4);
    let t = poseidon2.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
    let perm = poseidon2.permutation(&input);
    println!(
        "POSEIDON2 (t={t}) HASH(0, 1, 2, 3): { }",
        perm.iter()
            .map(|x| format!("{x}"))
            .collect::<Vec<String>>()
            .join(", ")
    );
}
