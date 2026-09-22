/** Recipient choices share the accounts already saved in wallet settings. */
import { App, Utils } from './core.js';

const OTHER = '__other__';

function picker(scope) {
    const root = document.querySelector(`[data-recipient-account="${scope}"]`);
    return {
        select: root?.querySelector('[data-recipient-select]'),
        input: root?.querySelector('[data-recipient-input]'),
    };
}

function savedAccounts() {
    const { address, signers = [] } = App.state.wallet;
    return address ? [...new Set(signers)].filter(account => account !== address) : [];
}

function render(scope, reset = false) {
    const { select, input } = picker(scope);
    if (!select || !input) return;
    const selected = reset ? '' : select.value;
    const owner = App.state.wallet.address;
    const saved = savedAccounts();
    const options = [new Option('Choose a recipient…', '')];
    for (const address of saved) {
        options.push(new Option(Utils.shortAddress(address), address));
    }
    if (owner) options.push(new Option(`Deposit account · ${Utils.shortAddress(owner)}`, owner));
    options.push(new Option('Enter another address…', OTHER));
    select.replaceChildren(...options);
    select.disabled = !owner;
    select.value = owner && (selected === OTHER || selected === owner || saved.includes(selected)) ? selected : '';
    input.classList.toggle('hidden', select.value !== OTHER);
    input.disabled = !owner || select.value !== OTHER;
    if (reset || select.value !== OTHER) input.value = '';
}

export const RecipientAccount = {
    init() {
        for (const scope of ['withdraw', 'advanced']) {
            const { select, input } = picker(scope);
            select?.addEventListener('change', () => {
                render(scope);
                if (select.value === OTHER) input?.focus();
            });
        }
        const reset = () => {
            render('withdraw', true);
            render('advanced', true);
        };
        App.events.addEventListener('wallet:ready', reset);
        App.events.addEventListener('wallet:disconnected', reset);
        App.events.addEventListener('wallet:signers-changed', () => {
            render('withdraw');
            render('advanced');
        });
        reset();
    },

    value(scope) {
        const { select, input } = picker(scope);
        if (!App.state.wallet.address) return '';
        const selected = select?.value;
        if (selected === OTHER) return input?.value.trim() || '';
        return selected === App.state.wallet.address || savedAccounts().includes(selected) ? selected : '';
    },

    reset(scope) {
        render(scope, true);
    },
};
