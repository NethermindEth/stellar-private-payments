import assert from 'node:assert/strict';
import test from 'node:test';

const guard = new URL('../../../app/js/frame-guard.js', import.meta.url);

async function load(framed, t) {
    const previousWindow = globalThis.window;
    const previousDocument = globalThis.document;
    t.after(() => {
        globalThis.window = previousWindow;
        globalThis.document = previousDocument;
    });
    const self = {};
    globalThis.window = { self, top: framed ? {} : self };
    globalThis.document = { documentElement: { style: {} } };
    // A fresh query string re-evaluates the module.
    return import(`${guard.href}?framed=${framed}`);
}

test('a framed page is hidden and stops before app code runs', async t => {
    await assert.rejects(load(true, t), /inside a frame/);
    assert.equal(document.documentElement.style.display, 'none');
});

test('a top-level page loads normally', async t => {
    await load(false, t);
    assert.equal(document.documentElement.style.display, undefined);
});
