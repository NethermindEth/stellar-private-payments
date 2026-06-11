//! Off-chain Soroban `ScVal` encoding for pool contract calls.

use anyhow::{Result, anyhow};
use stellar_xdr::curr::{self as xdr, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal};
use types::{ExtData, Field};

use crate::conversions::{bytes_to_scval, field_to_scval_u256, i128_to_i256_scval};

/// Stellar base fee (stroops) used as the classic component before resource
/// fees.
pub const BASE_FEE: u32 = 100;

fn map_entry(key: &str, val: ScVal) -> Result<ScMapEntry> {
    let sym: xdr::StringM<32> = key.try_into().map_err(|_| anyhow!("invalid map key"))?;
    Ok(ScMapEntry {
        key: ScVal::Symbol(ScSymbol(sym)),
        val,
    })
}

fn sorted_map(entries: Vec<ScMapEntry>) -> Result<ScVal> {
    let mut entries = entries;
    entries.sort_by(|a, b| {
        let ScVal::Symbol(ka) = &a.key else {
            return std::cmp::Ordering::Equal;
        };
        let ScVal::Symbol(kb) = &b.key else {
            return std::cmp::Ordering::Equal;
        };
        ka.to_string().cmp(&kb.to_string())
    });
    Ok(ScVal::Map(Some(ScMap(entries.try_into()?))))
}

/// Encodes an uncompressed Groth16 proof (256 bytes) as a contract
/// `Groth16Proof` map.
pub fn groth16_proof_to_scval(proof_uncompressed: &[u8]) -> Result<ScVal> {
    if proof_uncompressed.len() != 256 {
        return Err(anyhow!(
            "proof_uncompressed must be 256 bytes, got {}",
            proof_uncompressed.len()
        ));
    }
    sorted_map(vec![
        map_entry("a", bytes_to_scval(&proof_uncompressed[0..64])?)?,
        map_entry("b", bytes_to_scval(&proof_uncompressed[64..192])?)?,
        map_entry("c", bytes_to_scval(&proof_uncompressed[192..256])?)?,
    ])
}

/// Encodes pool `Proof` public inputs + embedded proof for `transact`.
#[allow(clippy::too_many_arguments)]
pub fn pool_proof_to_scval(
    proof_uncompressed: &[u8],
    root: Field,
    input_nullifiers: &[Field],
    output_commitment0: Field,
    output_commitment1: Field,
    public_amount: Field,
    ext_data_hash_be: [u8; 32],
    asp_membership_root: Field,
    asp_non_membership_root: Field,
) -> Result<ScVal> {
    let nullifiers = xdr::ScVec::try_from(
        input_nullifiers
            .iter()
            .copied()
            .map(field_to_scval_u256)
            .collect::<Vec<_>>(),
    )?;

    sorted_map(vec![
        map_entry(
            "asp_membership_root",
            field_to_scval_u256(asp_membership_root),
        )?,
        map_entry(
            "asp_non_membership_root",
            field_to_scval_u256(asp_non_membership_root),
        )?,
        map_entry("ext_data_hash", bytes_to_scval(ext_data_hash_be)?)?,
        map_entry("input_nullifiers", ScVal::Vec(Some(nullifiers)))?,
        map_entry(
            "output_commitment0",
            field_to_scval_u256(output_commitment0),
        )?,
        map_entry(
            "output_commitment1",
            field_to_scval_u256(output_commitment1),
        )?,
        map_entry("proof", groth16_proof_to_scval(proof_uncompressed)?)?,
        map_entry("public_amount", field_to_scval_u256(public_amount))?,
        map_entry("root", field_to_scval_u256(root))?,
    ])
}

/// Encodes pool `ExtData` for `transact`.
pub fn pool_ext_data_to_scval(ext: &ExtData) -> Result<ScVal> {
    sorted_map(vec![
        map_entry("encrypted_output0", bytes_to_scval(&ext.encrypted_output0)?)?,
        map_entry("encrypted_output1", bytes_to_scval(&ext.encrypted_output1)?)?,
        map_entry("ext_amount", i128_to_i256_scval(ext.ext_amount.into()))?,
        map_entry(
            "recipient",
            ScVal::Address(ext.recipient.parse::<ScAddress>()?),
        )?,
    ])
}

/// Encodes pool `Account` for `register`.
pub fn pool_account_to_scval(
    owner: &str,
    encryption_key: [u8; 32],
    note_key: [u8; 32],
) -> Result<ScVal> {
    sorted_map(vec![
        map_entry("encryption_key", bytes_to_scval(encryption_key)?)?,
        map_entry("note_key", bytes_to_scval(note_key)?)?,
        map_entry("owner", ScVal::Address(owner.parse::<ScAddress>()?))?,
    ])
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::ext_data_hash::hash_ext_data_offchain;
    use contract_types::Groth16Proof;
    use pool::{Account, ExtData as PoolExtData, Proof};
    use soroban_sdk::{
        Address, Bytes, BytesN, Env, I256, U256 as SorobanU256, Vec,
        crypto::bn254::{Bn254G1Affine as G1Affine, Bn254G2Affine as G2Affine},
        xdr::ToXdr,
    };

    const TEST_ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    use stellar_xdr::curr::{Limits, WriteXdr};
    use types::{ExtAmount, U256};

    fn scval_xdr(sc: &ScVal) -> std::vec::Vec<u8> {
        WriteXdr::to_xdr(sc, Limits::none()).expect("scval xdr")
    }

    fn soroban_xdr_to_vec(bytes: soroban_sdk::Bytes) -> std::vec::Vec<u8> {
        bytes.to_alloc_vec()
    }

    fn soroban_bytes32(bytes: &soroban_sdk::Bytes) -> [u8; 32] {
        bytes.to_alloc_vec().try_into().expect("32 bytes")
    }

    fn mk_mock_groth16_proof(env: &Env) -> Groth16Proof {
        let g1_bytes = {
            let mut bytes = [0u8; 64];
            bytes[31] = 1;
            bytes[63] = 2;
            bytes
        };
        let g2_bytes = {
            let mut bytes = [0u8; 128];
            bytes[31] = 1;
            bytes[63] = 1;
            bytes[95] = 1;
            bytes[127] = 1;
            bytes
        };
        Groth16Proof {
            a: G1Affine::from_array(env, &g1_bytes),
            b: G2Affine::from_array(env, &g2_bytes),
            c: G1Affine::from_array(env, &g1_bytes),
        }
    }

    fn proof_uncompressed_from_contract(proof: &Groth16Proof) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::with_capacity(256);
        out.extend_from_slice(&proof.a.to_bytes().to_array());
        out.extend_from_slice(&proof.b.to_bytes().to_array());
        out.extend_from_slice(&proof.c.to_bytes().to_array());
        out
    }

    fn field_from_u32(v: u32) -> Field {
        Field(U256::from(v))
    }

    fn map_symbol_keys(sc: &ScVal) -> std::vec::Vec<String> {
        let ScVal::Map(Some(map)) = sc else {
            panic!("expected map");
        };
        map.iter()
            .map(|entry| {
                let ScVal::Symbol(sym) = &entry.key else {
                    panic!("expected symbol key");
                };
                sym.to_string()
            })
            .collect::<std::vec::Vec<_>>()
    }

    #[test]
    fn groth16_proof_encoding_matches_contracttype_xdr() {
        let env = Env::default();
        let on_chain = mk_mock_groth16_proof(&env);
        let uncompressed = proof_uncompressed_from_contract(&on_chain);
        let expected = on_chain.to_xdr(&env);
        let ours = scval_xdr(&groth16_proof_to_scval(&uncompressed).expect("encode"));
        assert_eq!(ours, soroban_xdr_to_vec(expected));
    }

    #[test]
    fn pool_ext_data_encoding_matches_contracttype_xdr() {
        let env = Env::default();
        let recipient = Address::from_str(&env, TEST_ACCOUNT);
        let on_chain = PoolExtData {
            recipient: recipient.clone(),
            ext_amount: I256::from_i32(&env, -42),
            encrypted_output0: Bytes::from_slice(&env, &[1, 2, 3]),
            encrypted_output1: Bytes::from_slice(&env, &[4, 5]),
        };
        let expected = on_chain.to_xdr(&env);

        let app = ExtData {
            recipient: TEST_ACCOUNT.to_string(),
            ext_amount: ExtAmount::from(-42),
            encrypted_output0: vec![1, 2, 3],
            encrypted_output1: vec![4, 5],
        };
        let ours = scval_xdr(&pool_ext_data_to_scval(&app).expect("encode"));
        assert_eq!(ours, soroban_xdr_to_vec(expected));
    }

    #[test]
    fn pool_ext_data_encoding_matches_hash_ext_data_payload() {
        let app = ExtData {
            recipient: TEST_ACCOUNT.to_string(),
            ext_amount: ExtAmount::from(0),
            encrypted_output0: vec![9, 8, 7],
            encrypted_output1: vec![],
        };
        let ours = scval_xdr(&pool_ext_data_to_scval(&app).expect("encode"));

        let mut entries: std::vec::Vec<(&str, ScVal)> = std::vec![
            (
                "encrypted_output0",
                ScVal::Bytes(app.encrypted_output0.clone().try_into().expect("bytes")),
            ),
            (
                "encrypted_output1",
                ScVal::Bytes(app.encrypted_output1.clone().try_into().expect("bytes")),
            ),
            ("ext_amount", i128_to_i256_scval(app.ext_amount.into())),
            (
                "recipient",
                ScVal::Address(app.recipient.parse().expect("address")),
            ),
        ];
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let map_entries: std::vec::Vec<ScMapEntry> = entries
            .into_iter()
            .map(|(k, v)| {
                let sym: xdr::StringM<32> = k.try_into().expect("symbol");
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol(sym)),
                    val: v,
                }
            })
            .collect();
        let hash_payload = WriteXdr::to_xdr(
            &ScVal::Map(Some(ScMap(map_entries.try_into().expect("map")))),
            Limits::none(),
        )
        .expect("hash payload");

        assert_eq!(ours, hash_payload);
        let _ = hash_ext_data_offchain(&app).expect("hash");
    }

    #[test]
    fn pool_account_encoding_matches_contracttype_xdr() {
        let env = Env::default();
        let owner = Address::from_str(&env, TEST_ACCOUNT);
        let encryption_key = Bytes::from_array(&env, &[0xEE; 32]);
        let note_key = Bytes::from_array(&env, &[0xAB; 32]);
        let on_chain = Account {
            owner: owner.clone(),
            encryption_key: encryption_key.clone(),
            note_key: note_key.clone(),
        };
        let expected = on_chain.to_xdr(&env);

        let ours = scval_xdr(
            &pool_account_to_scval(
                TEST_ACCOUNT,
                soroban_bytes32(&encryption_key),
                soroban_bytes32(&note_key),
            )
            .expect("encode"),
        );
        assert_eq!(ours, soroban_xdr_to_vec(expected));
    }

    #[test]
    fn pool_proof_encoding_matches_contracttype_xdr() {
        let env = Env::default();
        let mut nullifiers = Vec::new(&env);
        nullifiers.push_back(SorobanU256::from_u32(&env, 0xAA));
        nullifiers.push_back(SorobanU256::from_u32(&env, 0xBB));

        let proof = mk_mock_groth16_proof(&env);
        let proof_uncompressed = proof_uncompressed_from_contract(&proof);
        let on_chain = Proof {
            proof,
            root: SorobanU256::from_u32(&env, 0x01),
            input_nullifiers: nullifiers,
            output_commitment0: SorobanU256::from_u32(&env, 0x02),
            output_commitment1: SorobanU256::from_u32(&env, 0x03),
            public_amount: SorobanU256::from_u32(&env, 0x04),
            ext_data_hash: BytesN::from_array(&env, &[0xCD; 32]),
            asp_membership_root: SorobanU256::from_u32(&env, 0x05),
            asp_non_membership_root: SorobanU256::from_u32(&env, 0x06),
        };
        let expected = on_chain.to_xdr(&env);
        let ours = scval_xdr(
            &pool_proof_to_scval(
                &proof_uncompressed,
                field_from_u32(1),
                &[field_from_u32(0xAA), field_from_u32(0xBB)],
                field_from_u32(2),
                field_from_u32(3),
                field_from_u32(4),
                [0xCD; 32],
                field_from_u32(5),
                field_from_u32(6),
            )
            .expect("encode"),
        );
        assert_eq!(ours, soroban_xdr_to_vec(expected));
    }

    #[test]
    fn pool_proof_map_keys_are_sorted() {
        let proof_uncompressed = vec![0u8; 256];
        let sc = pool_proof_to_scval(
            &proof_uncompressed,
            Field::ZERO,
            &[Field::ZERO, Field::ZERO],
            Field::ZERO,
            Field::ZERO,
            Field::ZERO,
            [0u8; 32],
            Field::ZERO,
            Field::ZERO,
        )
        .expect("encode");
        let keys = map_symbol_keys(&sc);
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }
}
