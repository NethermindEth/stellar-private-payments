// The test runner serves this integration test's generated bindings here.
// A separate WASM instance prevents process-local caches from hiding lost data.
export async function runWorker(directory, write) {
    const moduleUrl = new URL('/wasm-bindgen-test.js', self.location.href).href;
    const source = `
        import init, { crashWriter, crashReader } from ${JSON.stringify(moduleUrl)};
        await init({module_or_path: new URL("/wasm-bindgen-test_bg.wasm", ${JSON.stringify(moduleUrl)}).href});
        self.onmessage = async ({data}) => {
            try {
                let result;
                for (let attempt = 0; ; attempt++) {
                    try {
                        result = await (data.write ? crashWriter(data.directory) : crashReader(data.directory));
                        break;
                    } catch (error) {
                        if (attempt >= 20 || !String(error).includes('NoModificationAllowedError')) throw error;
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }
                }
                self.postMessage({ result });
            } catch (error) { self.postMessage({ error: String(error) }); }
        };
        self.postMessage({ ready: true });
    `;
    const url = URL.createObjectURL(new Blob([source], {type: 'text/javascript'}));
    const worker = new Worker(url, {type: 'module'});
    try {
        return await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('worker timeout')), 20000);
            worker.onerror = event => { clearTimeout(timer); reject(new Error(event.message)); };
            worker.onmessage = ({data}) => {
                if (data.ready) { worker.postMessage({directory, write}); return; }
                clearTimeout(timer);
                if (data.error) reject(new Error(data.error)); else resolve(data.result);
            };
        });
    } finally {
        // Deliberately terminate without dropping the writer's open database.
        worker.terminate();
        URL.revokeObjectURL(url);
    }
}

export function storageWorkerUrl() {
    const moduleUrl = new URL('/wasm-bindgen-test.js', self.location.href).href;
    return URL.createObjectURL(new Blob([
        `import init, {startStorageWorker} from ${JSON.stringify(moduleUrl)}; await init({module_or_path: new URL("/wasm-bindgen-test_bg.wasm", ${JSON.stringify(moduleUrl)}).href}); startStorageWorker();`
    ], {type: 'text/javascript'}));
}
export function revokeWorkerUrl(url) { URL.revokeObjectURL(url); }

export async function holdWal(directory) {
    const root = await navigator.storage.getDirectory();
    const dir = await root.getDirectoryHandle(directory, {create: true});
    const file = await dir.getFileHandle('spp.db-wal', {create: true});
    return file.createSyncAccessHandle();
}
export function releaseWal(handle) { handle.close(); }

export async function storedBytes(directory) {
    const root = await navigator.storage.getDirectory();
    const dir = await root.getDirectoryHandle(directory);
    const chunks = [];
    for (const name of ['spp.db', 'spp.db-wal']) {
        const file = await dir.getFileHandle(name);
        chunks.push(new Uint8Array(await (await file.getFile()).arrayBuffer()));
    }
    const bytes = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return bytes;
}

export async function walBytes(directory) {
    const root = await navigator.storage.getDirectory();
    const dir = await root.getDirectoryHandle(directory);
    const file = await dir.getFileHandle('spp.db-wal');
    return new Uint8Array(await (await file.getFile()).arrayBuffer());
}
