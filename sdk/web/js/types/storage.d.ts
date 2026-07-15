/** Options for {@link Storage.open}. */
export interface StorageOpenOptions {
  workerUrl?: string;
}

/**
 * Worker-backed local persistence (`spp.db` on OPFS).
 *
 * Open once per page. {@link Storage.fork} for additional handles (e.g. app
 * code alongside {@link Client.new}).
 */
export declare class Storage {
  static open(options?: StorageOpenOptions | null): Promise<Storage>;
  fork(): Storage;
  /**
   * Raw storage-worker RPC. Shapes match the worker protocol (externally tagged
   * enums, e.g. `{ DisclaimerState: "G..." }`).
   */
  call(request: unknown, timeoutMs?: number): Promise<unknown>;
}
