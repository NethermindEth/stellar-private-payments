import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { build } from '../node_modules/esbuild/lib/main.js';

const fixtures = {
    '../wallet.js': `export const connectWallet = async () => 'OWNER', getWalletNetwork = async () => ({ network:'testnet', networkPassphrase:'test', sorobanRpcUrl:'https://testnet.example' }), startWalletWatcher = () => () => {};`,
    'stellar-private-payments/freighter': 'export class FreighterSigner {}',
    '../app-storage.js': "export const DEFAULT_BOOTNODE_URL = 'https://archive.example';",
    '../wasm-facade.js': `export const client = () => sdk, ensureStorage = async () => store,
      initializeRuntime = async () => {}, disposeClient = () => { counts.disposed++; },
      bootnodeRequired = async () => false, configureTelemetrySettings = async () => {},
      dumpTelemetryLogs = async () => {}, debugLogsEnabled = () => true, isRuntimeReady = () => true,
      isStorageUnlocked = () => state.unlocked, STORAGE_UNLOCKED_EVENT = 'spp:storage-unlocked',
      ensurePrivateStorage = async () => { counts.prompts++; if (!state.unlocked) throw Object.assign(Error('cancelled'), { code:'unlock-cancelled' }); };`,
    './core.js': 'export const App = app, Utils = utils, Toast = { show: message => messages.push(message) };',
    './pool.js': 'export const closeAppPool = () => {}, createAppPool = async () => {}',
    './onboarding-wizard.js': 'export const runOnboardingWizard = async options => { counts.onboard++; counts.publicOnboard += Number(options.publicOnly); };',
    './confirm.js': 'export const confirmAction = async () => false;',
    '../db-locked.js': 'export const isDbLockedError = () => false, showDbLockedModal = () => {};',
    '../signing-account.js': 'export const rememberedSigners = () => [];',
    '../account-session.js': `export const accountSession = wallet => wallet, forgetNoteOwner = () => {}, rememberNoteOwner = address => { state.remembered = address; }, rememberedNoteOwner = () => state.remembered;`,
    '../disclosure.js': 'export const initDisclosure = () => {};',
};
const { outputFiles } = await build({
    stdin: { contents: "export { Wallet } from './js/ui/navigation.js';", resolveDir: new URL('../', import.meta.url).pathname },
    bundle: true, write: false, format: 'iife', globalName: 'navigation',
    plugins: [{ name: 'navigation-dependencies', setup(b) {
        b.onResolve({ filter: /.*/ }, args => args.importer.endsWith('/navigation.js') ? { path: args.path, namespace: 'fixture' } : undefined);
        b.onLoad({ filter: /.*/, namespace: 'fixture' }, args => { if (!fixtures[args.path]) throw Error(`Missing fixture ${args.path}`); return { contents: fixtures[args.path] }; });
    } }],
});

function harness() {
    const state = { unlocked: false, remembered: null };
    const counts = { prompts: 0, background: 0, onboard: 0, publicOnboard: 0, disposed: 0, privateReads: 0, privateWrites: 0 };
    const store = {
        getStoredBootnodeUrl: async () => null, getBootnodeConfig: async () => null, getExplorerSetting: async () => null,
        getSetting: async () => { counts.privateReads++; if (!state.unlocked) throw Error('Unexpected private read'); return null; },
        setSetting: async key => { if (key === 'telemetry_config') counts.privateWrites++; },
    };
    const app = { state: { wallet: {}, pools: [], settings: {}, keys: {}, profile: {}, ui: {} }, events: new EventTarget() };
    const sdk = { storage: () => store, contractConfig: () => ({ pools: [] }), backgroundSync: async () => { counts.background++; }, openAccount: async () => {}, account: () => ({ privacyKeys: async () => ({ notePublicKey:'NOTE', encryptionPublicKey:'ENCRYPTION' }) }) };
    const nodes = new Map();
    const document = { body: { dataset: {} }, querySelectorAll: () => [], getElementById: id => {
        if (!nodes.has(id)) nodes.set(id, Object.assign(new EventTarget(), { dataset:{}, value:'', classList:{ toggle() {}, add() {}, remove() {} }, querySelector() { return null; } }));
        return nodes.get(id);
    } };
    const context = vm.createContext({ state, counts, store, sdk, app, document, messages:[], console,
        utils: { shortAddress: s => s, defaultExplorerBaseUrl:'https://explorer.example' },
        window: new EventTarget(), Event, CustomEvent: class extends Event { constructor(name, options) { super(name); this.detail = options?.detail; } },
    });
    vm.runInContext(outputFiles[0].text, context);
    return context;
}

for (const auto of [false, true]) {
    test(`${auto ? 'automatic' : 'manual'} wallet connection syncs publicly with public onboarding and without reading private preferences`, async () => {
        const c = harness();
        await c.navigation.Wallet.connect({ auto });
        assert.equal(c.document.body.dataset.walletState, 'locked');
        assert.equal(c.counts.background, 1);
        assert.equal(c.counts.prompts, 0);
        assert.equal(c.counts.privateReads, 0);
        assert.equal(c.counts.onboard, 1);
        assert.equal(c.counts.publicOnboard, 1);
        await c.navigation.Wallet.saveSettings();
        assert.equal(c.counts.privateWrites, 0, 'ordinary settings must not write private telemetry preferences while locked');
    });

}

test('first connection keeps private setup deferred; an explicit unlock resumes the selected owner', async () => {
    const c = harness();
    c.navigation.Wallet.init();
    await c.navigation.Wallet.connect();
    assert.equal(c.counts.prompts, 0);
    assert.equal(c.counts.disposed, 0);
    assert.equal(c.app.state.wallet.connected, true);
    assert.equal(c.state.remembered, null, 'first-time owner is not remembered before onboarding');
    const ready = new Promise(resolve => c.app.events.addEventListener('wallet:ready', resolve, { once:true }));
    c.state.unlocked = true;
    c.window.dispatchEvent(new Event('spp:storage-unlocked'));
    await ready;
    assert.equal(c.counts.onboard, 2);
    assert.equal(c.counts.publicOnboard, 1);
    // Let the remainder of connect() record the successful owner.
    await c.navigation.Wallet._connectPromise;
    assert.equal(c.state.remembered, 'OWNER');
    assert.equal(c.document.body.dataset.walletState, 'ready');
});
