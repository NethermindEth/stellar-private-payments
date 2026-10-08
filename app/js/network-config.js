import knownNetworks from '../../sdk/native/src/network_defaults.json';

export const deploymentDefaults = { explorerUrl: '', rpcUrl: '', displayName: '', network: '' };

/** Presentation is derived from network identity, never from deployment overrides. */
export function networkPresentation(config) {
    const known = Object.hasOwn(knownNetworks, config.networkPassphrase)
        ? knownNetworks[config.networkPassphrase] : null;
    return {
        displayName: known?.displayName || config.network || 'Custom network',
        explorerUrl: known?.explorerUrl || '',
    };
}

export function validateNetwork(config, passphrase) {
    if (!config.networkPassphrase?.trim()) {
        throw new Error('Deployment config is missing networkPassphrase');
    }
    if (passphrase !== config.networkPassphrase) {
        throw new Error(`Switch Freighter to ${networkPresentation(config).displayName}`);
    }
}
