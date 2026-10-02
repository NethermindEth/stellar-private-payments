export const deploymentDefaults = { explorerUrl: '', rpcUrl: '', displayName: '', network: '', isTestnet: false };

export function validateNetwork(config, passphrase) {
    if (!config.networkPassphrase?.trim()) {
        throw new Error('Deployment config is missing networkPassphrase');
    }
    if (passphrase !== config.networkPassphrase) {
        throw new Error(`Switch Freighter to ${config.displayName || config.network}`);
    }
}
