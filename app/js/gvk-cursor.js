// nextTx() is stateful; a filter drain (ensureFullyLoaded in admin-gvk.js) can overlap a user fetch.
let cursorQueue = Promise.resolve();

export function queueCursorOp(fn) {
  const run = cursorQueue.then(fn, fn);
  cursorQueue = run.then(() => {}, () => {});
  return run;
}
