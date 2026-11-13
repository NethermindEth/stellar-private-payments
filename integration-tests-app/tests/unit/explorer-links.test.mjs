import assert from 'node:assert/strict';
import test from 'node:test';
import { StrKey } from '@stellar/stellar-sdk';
import { App, Utils } from '../../../app/js/ui/core.js';

const hash = 'ab'.repeat(32);
const contract = StrKey.encodeContract(Buffer.alloc(32));
const account = StrKey.encodeEd25519PublicKey(Buffer.alloc(32));

function withExplorer(baseUrl, fn) {
    const previous = App.state.settings.explorerBaseUrl;
    App.state.settings.explorerBaseUrl = baseUrl;
    try { fn(); } finally { App.state.settings.explorerBaseUrl = previous; }
}

class Link {
    attributes = new Map([['href', '#'], ['target', '_blank']]);
    set href(value) { this.attributes.set('href', value); }
    set target(value) { this.attributes.set('target', value); }
    set rel(value) { this.attributes.set('rel', value); }
    removeAttribute(name) { this.attributes.delete(name); }
}

test('without an explorer, explorer URLs are null rather than "#"', () => {
    withExplorer('', () => {
        assert.equal(Utils.explorerBaseUrl(), '');
        assert.equal(Utils.explorerTxUrl(hash), null);
        assert.equal(Utils.explorerLedgerUrl(42), null);
        assert.equal(Utils.explorerAddressUrl(account), null);
        assert.equal(Utils.explorerContractUrl(contract), null);
        assert.equal(Utils.explorerContractStorageUrl(contract), null);
    });
});

test('with an explorer, valid ids get links and invalid ids get none', () => {
    withExplorer('https://explorer.example', () => {
        assert.equal(Utils.explorerTxUrl(hash), `https://explorer.example/tx/${hash}`);
        assert.equal(Utils.explorerLedgerUrl(42), 'https://explorer.example/ledger/42');
        assert.equal(Utils.explorerContractStorageUrl(contract), `https://explorer.example/contract/${contract}/storage`);
        assert.equal(Utils.explorerTxUrl('not-a-hash'), null);
        assert.equal(Utils.explorerContractUrl('C123'), null);
    });
});

test('a link without a URL becomes plain text instead of opening the app again', () => {
    const link = new Link();
    Utils.setExplorerLink(link, null);
    assert.equal(link.attributes.has('href'), false);
    assert.equal(link.attributes.has('target'), false);

    Utils.setExplorerLink(link, 'https://explorer.example/tx/1');
    assert.equal(link.attributes.get('href'), 'https://explorer.example/tx/1');
    assert.equal(link.attributes.get('target'), '_blank');
});
