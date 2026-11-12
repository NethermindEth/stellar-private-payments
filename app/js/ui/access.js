import { describeAccess } from '../access-state.js';
import { STORAGE_MODE, STORAGE_STATE_EVENT, idleLockMinutes, isStorageUnlocked, loadDeploymentConfig, localStoreExists } from '../wasm-facade.js';
import { networkPresentation } from '../network-config.js';
import { isWalletInstalled } from '../wallet.js';
import { App } from './core.js';
import { LocalData } from './local-data.js';
import { Wallet } from './navigation.js';

// Facts the access state needs that only async checks can answer.
let storeExists = false;
// Without waiting for the store check, a returning user would briefly see the welcome.
let storeChecked = false;
let walletInstalled = null;
let networkName = '';

function currentAccess() {
    return describeAccess({
        mode: STORAGE_MODE,
        storeExists,
        walletState: document.body.dataset.walletState,
        walletConnected: App.state.wallet.connected,
        unlocked: isStorageUnlocked(),
        storageState: document.body.dataset.storageState,
        view: App.state.views.active,
        idleLockMinutes: idleLockMinutes(),
    });
}

function setAction(button, access) {
    button.textContent = access.label;
    button.dataset.accessAction = access.action;
    button.disabled = access.busy;
    button.ariaBusy = access.busy ? 'true' : null;
}

function render() {
    const access = currentAccess();
    document.getElementById('storage-lock-btn').hidden = !access.showLock;
    // Database-backed views stay closed until storage opens; Disclosure
    // verification is public and always available.
    document.querySelectorAll('[data-view-panel]').forEach(panel => {
        const blocked = !access.showViews && panel.dataset.viewPanel !== 'disclosure';
        panel.inert = blocked;
        panel.style.display = blocked ? 'none' : '';
    });
    if (!storeChecked && !access.showViews) return;

    document.body.dataset.accessState = access.state;
    const accountBtn = document.getElementById('wallet-btn');
    setAction(accountBtn, access);
    accountBtn.hidden = access.action === 'none' && !access.busy;
    // When the card offers the same action, its button is the primary one.
    accountBtn.classList.toggle('btn-primary', !access.cardVisible);
    accountBtn.classList.toggle('btn-secondary', access.cardVisible);

    const card = document.getElementById('access-card');
    card.hidden = !access.cardVisible;
    if (!access.card) return;
    card.dataset.accessState = access.state;
    card.querySelector('[data-access-title]').textContent = access.card.title;
    card.querySelector('[data-access-body]').textContent = access.card.body;
    const label = card.querySelector('[data-access-view-label]');
    label.textContent = access.viewLabel || '';
    label.hidden = !access.viewLabel;
    // A single line under the button: the network to use, then what signing involves.
    const startsConnection = access.state === 'welcome' || access.state === 'returning';
    const network = startsConnection && networkName ? `Use Freighter on ${networkName}.` : '';
    const meta = card.querySelector('[data-access-meta]');
    meta.textContent = [network, access.card.note].filter(Boolean).join(' ');
    meta.hidden = !meta.textContent;
    card.querySelector('[data-access-install]').hidden = !startsConnection || walletInstalled !== false;
    card.querySelector('[data-access-intro]').hidden = access.state !== 'welcome';
    const cta = card.querySelector('[data-access-cta]');
    setAction(cta, access);
    cta.hidden = access.action === 'none' && !access.busy;
}

async function act(action) {
    if (action === 'connect') await Wallet.connect({ auto: false }).catch(() => {});
    else if (action === 'unlock') await LocalData.unlock();
}

export const Access = {
    init() {
        for (const button of [document.getElementById('wallet-btn'), document.querySelector('#access-card [data-access-cta]')]) {
            button.addEventListener('click', () => void act(button.dataset.accessAction));
        }
        document.querySelectorAll('[data-access-goto]').forEach(link => link.addEventListener('click', () => {
            document.querySelector(`[data-view="${link.dataset.accessGoto}"]`)?.click();
        }));

        window.addEventListener(STORAGE_STATE_EVENT, () => {
            if (isStorageUnlocked()) storeExists = true;
            render();
        });
        App.events.addEventListener('view:changed', render);
        // Wallet transitions are published on body; follow them from one place.
        new MutationObserver(render).observe(document.body, { attributeFilter: ['data-wallet-state'] });
        render();

        void localStoreExists().catch(() => false).then(exists => {
            storeExists = storeExists || exists;
            storeChecked = true;
            render();
        });
        void isWalletInstalled().then(installed => { walletInstalled = installed; render(); });
        void loadDeploymentConfig().then(config => { networkName = networkPresentation(config).displayName; render(); }).catch(() => {});
    },
};
