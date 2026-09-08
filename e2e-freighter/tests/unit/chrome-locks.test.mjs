import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { clearSingletonLocks } from '../../src/chrome-locks.mjs';

const ALL_THREE = ['SingletonLock', 'SingletonSocket', 'SingletonCookie'];

function profileDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome-locks-'));
  t.after(() => fs.rmSync(dir, { force: true, recursive: true }));
  return dir;
}

function plantLocks(dir, owner) {
  fs.symlinkSync(owner, path.join(dir, 'SingletonLock'));
  fs.writeFileSync(path.join(dir, 'SingletonSocket'), '');
  fs.writeFileSync(path.join(dir, 'SingletonCookie'), '');
}

test('removes locks whose owning process is gone', (t) => {
  const dir = profileDir(t);
  plantLocks(dir, 'thishost-12345');

  const removed = clearSingletonLocks(dir, { hostname: 'thishost', isProcessAlive: () => false });

  assert.deepEqual(removed, ALL_THREE);
  assert.deepEqual(fs.readdirSync(dir), []);
});

test('removes locks belonging to another host, live pid or not', (t) => {
  const dir = profileDir(t);
  plantLocks(dir, 'someotherhost-12345');

  const removed = clearSingletonLocks(dir, { hostname: 'thishost', isProcessAlive: () => true });

  assert.deepEqual(removed, ALL_THREE);
  assert.deepEqual(fs.readdirSync(dir), []);
});

test('refuses, and removes nothing, while a live process on this host holds the profile', (t) => {
  const dir = profileDir(t);
  plantLocks(dir, 'thishost-12345');

  assert.throws(
    () => clearSingletonLocks(dir, { hostname: 'thishost', isProcessAlive: () => true }),
    /pid 12345 on thishost still holds this profile/,
  );
  assert.deepEqual(fs.readdirSync(dir).sort(), [...ALL_THREE].sort());
});

test('the real liveness check refuses on a lock naming this process', (t) => {
  const dir = profileDir(t);
  plantLocks(dir, `${os.hostname()}-${process.pid}`);

  assert.throws(() => clearSingletonLocks(dir), /still holds this profile/);
  assert.deepEqual(fs.readdirSync(dir).sort(), [...ALL_THREE].sort());
});

test('refuses when the lock is not a symlink naming a host and pid', (t) => {
  const asFile = profileDir(t);
  fs.writeFileSync(path.join(asFile, 'SingletonLock'), 'thishost-12345');
  assert.throws(() => clearSingletonLocks(asFile), /is not a symlink/);
  assert.deepEqual(fs.readdirSync(asFile), ['SingletonLock']);

  const asDir = profileDir(t);
  fs.mkdirSync(path.join(asDir, 'SingletonLock'));
  fs.writeFileSync(path.join(asDir, 'SingletonLock', 'surprise'), '');
  assert.throws(() => clearSingletonLocks(asDir), /is not a symlink/);
  assert.deepEqual(fs.readdirSync(path.join(asDir, 'SingletonLock')), ['surprise']);

  const unparsable = profileDir(t);
  fs.symlinkSync('no-pid-here', path.join(unparsable, 'SingletonLock'));
  assert.throws(() => clearSingletonLocks(unparsable), /is not <hostname>-<pid>/);
  assert.deepEqual(fs.readdirSync(unparsable), ['SingletonLock']);
});

test('a socket and cookie with no lock claim no owner and are removed', (t) => {
  const dir = profileDir(t);
  fs.writeFileSync(path.join(dir, 'SingletonSocket'), '');
  fs.writeFileSync(path.join(dir, 'SingletonCookie'), '');

  const removed = clearSingletonLocks(dir, { hostname: 'thishost', isProcessAlive: () => true });

  assert.deepEqual(removed, ['SingletonSocket', 'SingletonCookie']);
  assert.deepEqual(fs.readdirSync(dir), []);
});

test('leaves the rest of the profile alone', (t) => {
  const dir = profileDir(t);
  plantLocks(dir, 'thishost-12345');
  fs.writeFileSync(path.join(dir, 'Local State'), '{}');
  fs.mkdirSync(path.join(dir, 'Default'));
  fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), '{}');

  clearSingletonLocks(dir, { hostname: 'thishost', isProcessAlive: () => false });

  assert.deepEqual(fs.readdirSync(dir).sort(), ['Default', 'Local State']);
  assert.equal(fs.readFileSync(path.join(dir, 'Default', 'Preferences'), 'utf8'), '{}');
});

test('a profile with no locks and a profile that does not exist are both no-ops', (t) => {
  const dir = profileDir(t);
  assert.deepEqual(clearSingletonLocks(dir), []);
  assert.deepEqual(fs.readdirSync(dir), []);

  assert.deepEqual(clearSingletonLocks(path.join(dir, 'never-provisioned')), []);
});
