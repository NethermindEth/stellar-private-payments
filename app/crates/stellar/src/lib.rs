// const NETWORKS = {
//     testnet: {
//         name: 'Testnet',
//         horizonUrl: 'https://horizon-testnet.stellar.org',
//         rpcUrl: 'https://soroban-testnet.stellar.org',
//         passphrase: Networks.TESTNET,
//     },
//     futurenet: {
//         name: 'Futurenet',
//         horizonUrl: 'https://horizon-futurenet.stellar.org',
//         rpcUrl: 'https://rpc-futurenet.stellar.org',
//         passphrase: Networks.FUTURENET,
//     },
//     mainnet: {
//         name: 'Mainnet',
//         horizonUrl: 'https://horizon.stellar.org',
//         rpcUrl: 'https://soroban.stellar.org',
//         passphrase: Networks.PUBLIC,
//     }
// };
mod rpc;

pub use rpc::{Client, scval_to_address_string, scval_to_u256, scval_to_u32, scval_to_u64, scval_to_bool};
