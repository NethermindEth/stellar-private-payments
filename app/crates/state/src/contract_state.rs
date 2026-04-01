use futures::try_join;
use anyhow::{anyhow, Result, Context};
use log::{info, error, debug};


// {
//   "success": true,
//   "network": "testnet",
//   "timestamp": "2026-04-01T00:39:54.714Z",
//   "pool": {
//     "success": true,
//     "contractId": "CA2TZYEXHGWWJJYYETDQBAUNJF7F2J4GVLDLW6LM5W32IIT4AO5SMPWQ",
//     "contractType": "Privacy Pool",
//     "admin": "GDKG6HKZVVL7QMAJTETYVNFNGBEU3KKIEDPS45PPPRYWOYH5QKBHMHFL",
//     "token": "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
//     "verifier": "CD3S2BFTZP7HIF7CKOAA5UUZEKL4WDTUDJOIPQAMTWF6QHYFRYCIGA6U",
//     "aspmembership": "CAC7YUZGC65TXX4I6LGBUVGEZW767LAP5JVZT5O2I6DIA3NGL6WKQOGH",
//     "aspnonmembership": "CBVFZJBBASMAOXWFQ63IZPQHFES7MZNB5ZAPE2CR2KLJD3DNTFTN4REX",
//     "merkleLevels": 10,
//     "merkleCurrentRootIndex": 5,
//     "merkleNextIndex": "10",
//     "maximumDepositAmount": "1000000000",
//     "merkleRoot": "0x20e8f01004bcd8822c0f4da57b156b2c7015ff10c7830aae1397cc045b8c650e",
//     "merkleRootRaw": "14885576524674421798718372801588381750575651689391702400183312580099508561166",
//     "merkleCapacity": 1024,
//     "totalCommitments": "10"
//   },
//   "aspMembership": {
//     "success": true,
//     "contractId": "CAC7YUZGC65TXX4I6LGBUVGEZW767LAP5JVZT5O2I6DIA3NGL6WKQOGH",
//     "contractType": "ASP Membership",
//     "root": "0x08c1475ba440b720e627897ed8dbed1712a88d5e0b4cc56501f81bc501747d0e",
//     "rootRaw": "3959996766811966306066542215696728549545304777615549736881113009222598294798",
//     "levels": 10,
//     "nextIndex": "1",
//     "admin": "GDKG6HKZVVL7QMAJTETYVNFNGBEU3KKIEDPS45PPPRYWOYH5QKBHMHFL",
//     "adminInsertOnly": true,
//     "capacity": 1024,
//     "usedSlots": "1"
//   },
//   "aspNonMembership": {
//     "success": true,
//     "contractId": "CBVFZJBBASMAOXWFQ63IZPQHFES7MZNB5ZAPE2CR2KLJD3DNTFTN4REX",
//     "contractType": "ASP Non-Membership (Sparse Merkle Tree)",
//     "root": "0x0000000000000000000000000000000000000000000000000000000000000000",
//     "rootRaw": "0",
//     "isEmpty": true,
//     "admin": "GDKG6HKZVVL7QMAJTETYVNFNGBEU3KKIEDPS45PPPRYWOYH5QKBHMHFL"
//   }
// }

pub async fn all_contracts_data(client: &stellar::Client, config: &types::ContractConfig) -> Result<()> {
    // for merkle keys 'Levels', 'CurrentRootIndex', 'NextIndex' prepend "merkle.."
    // results[key.toLowerCase()] = result.value;
    let (pool_state, asp_membership_state, asp_non_membership_state) = try_join!(
        client.get_contract_data(&config.pool, &["Admin", "Token", "Verifier", "ASPMembership", "ASPNonMembership", "Levels", "CurrentRootIndex", "NextIndex", "MaximumDepositAmount"], &[]),
        client.get_contract_data(&config.asp_membership, &["Root", "Levels", "NextIndex", "Admin", "AdminInsertOnly"], &[]),
        client.get_contract_data(&config.asp_non_membership, &["Root", "Admin"], &[]),
    )?;

    // // Fetch root current root index
    // if (results.merkleCurrentRootIndex !== undefined) {
    //     const rootResult = await readLedgerEntry(
    //         contractId,
    //         createEnumKey('Root', u32Val(results.merkleCurrentRootIndex))
    //     );
    //     if (rootResult.success) {
    //         results.merkleRoot = formatU256(rootResult.value);
    //         results.merkleRootRaw = rootResult.value;
    //     }
    // }

    // if (results.merkleLevels !== undefined) {
    //     results.merkleCapacity = Math.pow(2, results.merkleLevels);
    //     results.totalCommitments = results.merkleNextIndex || 0;
    // }

    info!("== {pool_state:?} {asp_membership_state:?} {asp_non_membership_state:?}");

    Ok(())
}
