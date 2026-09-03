// Remove Chrome's single-instance locks from a user-data-dir, but only when
// nothing still holds them.
//
// Chrome writes SingletonLock — a symlink to "<hostname>-<pid>" — plus
// SingletonSocket and SingletonCookie while a profile is open, and removes
// them on a clean exit. A killed run leaves them behind, and the next launch
// reads them as "open elsewhere" and quietly switches to a throwaway profile:
// the extension loads with no wallet.
//
// The rule enforced here: locks are removed only when the target names a dead
// pid or a different host. A live owner, or a target that cannot be read as
// "<hostname>-<pid>", throws — an aborted launch is diagnosable, two browsers
// on one profile is not.
import { lstatSync, readlinkSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const SINGLETON_NAMES = ['SingletonLock', 'SingletonSocket', 'SingletonCookie'];

function defaultIsProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: it exists and belongs to someone else.
    return err.code === 'EPERM';
  }
}

function readOwner(lockPath, stats) {
  if (!stats.isSymbolicLink()) throw new Error('SingletonLock is not a symlink');
  const target = readlinkSync(lockPath);
  const match = /^(.+)-(\d+)$/.exec(target);
  if (!match) throw new Error(`SingletonLock target '${target}' is not <hostname>-<pid>`);
  return { host: match[1], pid: Number(match[2]) };
}

export function clearSingletonLocks(userDataDir, {
  hostname = os.hostname(),
  isProcessAlive = defaultIsProcessAlive,
} = {}) {
  if (!userDataDir) return [];

  const lockPath = path.join(userDataDir, 'SingletonLock');
  const lockStats = lstatSync(lockPath, { throwIfNoEntry: false });
  if (lockStats) {
    let owner;
    try {
      owner = readOwner(lockPath, lockStats);
    } catch (err) {
      throw new Error(`refusing to clear ${lockPath}: ${err.message}`);
    }
    if (owner.host === hostname && isProcessAlive(owner.pid)) {
      throw new Error(
        `refusing to clear ${lockPath}: pid ${owner.pid} on ${owner.host} still holds this profile`,
      );
    }
  }

  const removed = [];
  for (const name of SINGLETON_NAMES) {
    const target = path.join(userDataDir, name);
    // lstat, not exists: the SingletonLock symlink does not resolve.
    if (lstatSync(target, { throwIfNoEntry: false })) removed.push(name);
    rmSync(target, { force: true });
  }
  return removed;
}
