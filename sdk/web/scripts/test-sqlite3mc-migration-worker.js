// Test-only worker bootstrap. Never copied into dist or used by application code.
// Inject I/O failures below SQLite, without adding diagnostic RPCs to the SDK.
const initialFault = new URL(import.meta.url).searchParams;
let mode = initialFault.get('fault') || '';
let target = initialFault.get('target') || '';
let fired = false;
const names = new WeakMap();
function hit(point) {
  if (fired || mode !== point) return false;
  fired = true;
  self.postMessage({ migrationFault: point });
  return true;
}
function stop(point) {
  if (hit(point)) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
}
const getDirectory = FileSystemDirectoryHandle.prototype.getDirectoryHandle;
FileSystemDirectoryHandle.prototype.getDirectoryHandle = async function (name, options) {
  const setup = name.startsWith('.setup-v1-') && options?.create;
  if (setup) stop('setup-before-marker');
  const result = await getDirectory.call(this, name, options);
  if (setup) stop('setup-marker-created');
  return result;
};
const removeEntry = FileSystemDirectoryHandle.prototype.removeEntry;
FileSystemDirectoryHandle.prototype.removeEntry = async function (name, options) {
  if (name.startsWith('.setup-v1-')) {
    stop('setup-before-retire');
    if (hit('setup-retire-error')) throw new DOMException('test marker retirement failure', 'UnknownError');
  }
  const result = await removeEntry.call(this, name, options);
  if (name.startsWith('.setup-v1-')) stop('setup-after-retire');
  return result;
};
self.addEventListener('message', e => {
  if (!e.data?.armMigrationFault) return;
  e.stopImmediatePropagation();
  ({ mode, target } = e.data.armMigrationFault);
  fired = false;
  self.postMessage({ migrationArmed: mode });
});
const create = FileSystemFileHandle.prototype.createSyncAccessHandle;
FileSystemFileHandle.prototype.createSyncAccessHandle = async function (...args) {
  const handle = await create.apply(this, args);
  const header = new Uint8Array(512);
  handle.read(header, { at: 0 });
  names.set(handle, new TextDecoder().decode(header).split('\0')[0]);
  return handle;
};
const write = FileSystemSyncAccessHandle.prototype.write;
FileSystemSyncAccessHandle.prototype.write = function (buffer, options) {
  const bytes = new Uint8Array(buffer.buffer || buffer, buffer.byteOffset || 0, buffer.byteLength);
  const at = options?.at || 0;
  let name = names.get(this) || '';
  if (at === 0 && bytes.length >= 512) {
    const nextName = new TextDecoder().decode(bytes.subarray(0, 512)).split('\0')[0];
    if (name === target && !nextName && hit('delete-header-error')) {
      throw new DOMException('test deletion mapping failure', 'UnknownError');
    }
    name = nextName;
    names.set(this, name);
  }
  if (name === target && at >= 4096) {
    if (hit('quota')) throw new DOMException('test quota exhaustion', 'QuotaExceededError');
    if (mode === 'during-write' && !fired) {
      const result = write.call(this, bytes.subarray(0, Math.floor(bytes.length / 2)), options);
      stop('during-write');
      return result;
    }
  }
  return write.call(this, buffer, options);
};
const flush = FileSystemSyncAccessHandle.prototype.flush;
FileSystemSyncAccessHandle.prototype.flush = function () {
  const name = names.get(this) || '';
  if (name === target && hit('flush-error')) throw new DOMException('test flush error', 'UnknownError');
  const result = flush.call(this);
  if (name === target) stop('after-sync');
  return result;
};
const truncate = FileSystemSyncAccessHandle.prototype.truncate;
FileSystemSyncAccessHandle.prototype.truncate = function (size) {
  const name = names.get(this) || '';
  if (size === 4096 && name === target + '-journal') stop('before-commit');
  const result = truncate.call(this, size);
  if (size === 4096 && name === target + '-journal') stop('after-commit');
  if (size === 4096 && name === target) stop('after-delete');
  return result;
};
const { default: init } = await import('../dist/workers/storage-worker-module.js');
await init();
