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

pub use rpc::Client;
