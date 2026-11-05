// nextTx() is stateful; a filter drain (ensureFullyLoaded in admin-gvk.js) can overlap a user fetch.
let cursorQueue = Promise.resolve();

export function queueCursorOp(fn) {
  const run = cursorQueue.then(fn, fn);
  cursorQueue = run.then(() => {}, () => {});
  return run;
}

// free() during a pending nextTx() throws and leaks the cursor, key included.
export function releaseCursor(audit) {
  queueCursorOp(() => audit.free())
    .catch((err) => console.warn('[global-view] cursor free failed:', err));
}
