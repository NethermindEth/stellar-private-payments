import init, { mainThread, Config } from './web.js';

let handle = null;

export async function initializeWasm(rpcUrl) {
    if (handle) return handle; // Prevent double initialization

    await init();
    const config = new Config(rpcUrl);
    handle = await mainThread(config);

    return handle;
}

// Named export to get the handle after initialization
export const getHandle = () => {
    if (!handle) throw new Error("WASM not initialized. Call initializeWasm first.");
    return handle;
};
