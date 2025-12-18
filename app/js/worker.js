/**
 * We run heavy proving operations in the worker
 * to avoid blocking the main UI thread.
 * Communication happens via messages
 */
import initWasmModule, {init, Prover} from '../../dist/js/prover.js';;

(async () => {
    console.log('Worker script initializing...');
    await initWasmModule();
    //const response = await fetch('circuits/prover.circuit');
    //const circuitBuffer = await response.arrayBuffer();
    //const prover = await init(new Uint8Array(circuitBuffer));

    const sampleCircuit = new Uint8Array([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    ]);
    const prover = await init(sampleCircuit );
    console.log(`Wasm prover initialized`);

    self.postMessage({ type: 'READY' });

    self.onmessage = function(event) {
        const message = event.data;
        console.log("== Worker MSG", message);
        const messageId = message.messageId;

        switch (message.type) {
            case "PROVE":
                const startTime = performance.now();
                const proof = prover.prove();
                console.log(`PROVE took ${performance.now() - startTime} ms`);
                self.postMessage({ type: 'PROVE', messageId, payload: proof });
                break;
        }
    }
})();
