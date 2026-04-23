import init, { mainThread, Config } from './web.js';

let handle = null;

export async function initializeWasm(rpcUrl, indexerRpcUrl = null) {
    if (handle) return handle; // Prevent double initialization

    await init();
    const cfgIndexer = indexerRpcUrl || undefined;
    const config = new Config(rpcUrl, cfgIndexer);
    handle = await mainThread(config);

    return handle;
}

// Named export to get the handle after initialization
export const getHandle = () => {
    if (!handle) throw new Error("WASM not initialized. Call initializeWasm first.");
    return handle;
};
