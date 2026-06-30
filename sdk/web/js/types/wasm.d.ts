/**
 * wasm-bindgen output (`dist/private_payments_web.js`).
 * Run `npm run build` to generate artifacts before type-checking.
 */
declare module '../../dist/private_payments_web.js' {
  export default function init(
    module_or_path?: string | URL | Request | Response | BufferSource | WebAssembly.Module,
  ): Promise<void>;

  export class Storage {
    static open(options?: unknown): Promise<Storage>;
    fork(): Storage;
    call(request: unknown, timeoutMs?: number): Promise<unknown>;
  }

  export class Client {
    static connect(options: unknown, signer: unknown): Promise<Client>;
    static contractConfig(): unknown;
    initialize(): Promise<void>;
    registerPublicKeys(options?: unknown): Promise<string>;
    lookupRegisteredPublicKey(address: string): Promise<unknown>;
    allContractsData(): Promise<unknown>;
    pool(options: unknown): Promise<PrivatePool>;
  }

  export class PrivatePool {
    sync(): Promise<void>;
    getBalance(): Promise<string>;
    notes(): Promise<unknown>;
    estimate(amount: string): Promise<unknown>;
    deposit(amount: string): Promise<unknown>;
    transfer(recipient: string, amount: string): Promise<unknown>;
    withdraw(amount: string, recipient?: string): Promise<unknown>;
    transact(config: unknown): Promise<unknown>;
    disclose(config: unknown): Promise<unknown>;
    verifyDisclosure(receipt: unknown, expectedVkHash: string): Promise<unknown>;
  }
}
