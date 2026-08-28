// The staged connect() sequence behind ui/navigation.js, extracted so the
// supersession windows can be driven under plain `node --test` with deferred
// promises. No imports; every effect is injected. `superseded()` is checked
// after every await, before anything the next stage publishes or mutates.

/**
 * Run the connect sequence stage by stage.
 *
 * @param {object} stages
 * @param {() => boolean} stages.superseded
 * @param {(state: string) => void} stages.setWalletState
 * @param {() => Promise<string>} stages.connectWallet
 * @param {() => Promise<{network: string|null, networkPassphrase: string|null, sorobanRpcUrl: string}>} stages.getNetwork
 * @param {(published: {address: string, network: string|null, networkPassphrase: string|null, sorobanRpcUrl: string}) => void} stages.publishWallet
 * @param {(rpcUrl: string, address: string) => Promise<{bootnodeRequired: boolean}>} stages.bootnodeCheck
 * @param {(rpcUrl: string, opts: {address: string}) => Promise<void>} stages.initializeRuntime
 * @param {() => void} stages.startWatcher
 * @param {(args: {address: string, networkPassphrase: string|null, bootnodeRequired: boolean}) => Promise<void>} stages.runOnboardingWizard
 * @param {() => string} stages.liveAddress
 * @param {(args: {networkPassphrase: string|null, userAddress: string}) => Promise<void>} stages.openAccount
 * @param {() => Promise<void>} stages.backgroundSync
 * @param {() => Promise<{notePublicKey: unknown, encryptionPublicKey: unknown}>} stages.userPublicKeys
 * @param {(keys: {notePublicKey: unknown, encryptionPublicKey: unknown}) => void} stages.publishKeys
 * @param {() => Promise<void>} stages.loadRuntimeState
 * @param {(detail: {address: string}) => void} stages.publishReady
 * @param {() => Promise<void>} stages.createAppPool
 * @returns {Promise<{connected: boolean, address?: string}>}
 */
export async function runConnectStages({
    superseded,
    setWalletState,
    connectWallet,
    getNetwork,
    publishWallet,
    bootnodeCheck,
    initializeRuntime,
    startWatcher,
    runOnboardingWizard,
    liveAddress,
    openAccount,
    backgroundSync,
    userPublicKeys,
    publishKeys,
    loadRuntimeState,
    publishReady,
    createAppPool,
}) {
    setWalletState('connecting');

    const address = await connectWallet();
    if (superseded()) return { connected: false };
    const { network, networkPassphrase, sorobanRpcUrl } = await getNetwork();
    if (superseded()) return { connected: false };
    publishWallet({ address, network, networkPassphrase, sorobanRpcUrl });

    const { bootnodeRequired } = await bootnodeCheck(sorobanRpcUrl, address);
    if (superseded()) return { connected: false };
    await initializeRuntime(sorobanRpcUrl, { address });
    if (superseded()) return { connected: false };

    startWatcher();

    await runOnboardingWizard({ address, networkPassphrase, bootnodeRequired });
    if (superseded()) return { connected: false };
    setWalletState('binding');

    // The watcher may have re-bound the address while the wizard was open.
    const sessionAddress = liveAddress();
    if (sessionAddress !== address) {
        await initializeRuntime(sorobanRpcUrl, { address: sessionAddress });
        if (superseded()) return { connected: false };
    }
    await openAccount({ networkPassphrase, userAddress: sessionAddress });
    if (superseded()) return { connected: false };

    await backgroundSync();
    if (superseded()) return { connected: false };

    const keys = await userPublicKeys();
    if (superseded()) return { connected: false };
    publishKeys(keys);

    await loadRuntimeState();
    if (superseded()) return { connected: false };
    publishReady({ address: sessionAddress });

    await createAppPool();
    if (superseded()) return { connected: false };
    setWalletState('ready');
    return { connected: true, address: sessionAddress };
}
