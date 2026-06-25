import { App, Utils } from './core.js';

export const Templates = {
    init() {
        App.templates = {
            noteInputRow: document.getElementById('tpl-note-input-row'),
            outputRow: document.getElementById('tpl-output-row'),
            noteRow: document.getElementById('tpl-note-row'),
            feedCard: document.getElementById('tpl-feed-card'),
            balanceCard: document.getElementById('tpl-balance-card'),
            toast: document.getElementById('tpl-toast'),
        };
    },

    createNoteInputRow(index) {
        const row = App.templates.noteInputRow.content.cloneNode(true).firstElementChild;
        row.dataset.index = index;
        return row;
    },

    createOutputRow(index) {
        const row = App.templates.outputRow.content.cloneNode(true).firstElementChild;
        row.dataset.index = index;
        return row;
    },

    createBalanceCard(balance) {
        const el = App.templates.balanceCard.content.cloneNode(true).firstElementChild;
        const tokenLink = el.querySelector('.balance-token');
        tokenLink.textContent = balance.tokenLabel;
        tokenLink.href = Utils.explorerContractUrl(balance.tokenContractId);
        tokenLink.title = balance.tokenContractId;
        el.querySelector('.balance-amount').textContent = Utils.formatTokenAmount(balance.amount, balance.tokenLabel);
        el.querySelector('.balance-notes').textContent = `${balance.noteCount} note${balance.noteCount === 1 ? '' : 's'}`;
        const poolLink = el.querySelector('.balance-pool');
        poolLink.textContent = Utils.shortAddress(balance.poolContractId, 6, 4);
        poolLink.href = Utils.explorerContractUrl(balance.poolContractId);
        poolLink.title = balance.poolContractId;

        el.querySelectorAll('[data-quick-flow], [data-view-notes], [data-view-history]').forEach(btn => {
            btn.dataset.poolId = balance.poolContractId;
        });
        return el;
    },

    createFeedCard(item, poolLabel) {
        const el = App.templates.feedCard.content.cloneNode(true).firstElementChild;
        el.querySelector('.feed-title').textContent = item.title;
        el.querySelector('.feed-body').textContent = item.body;
        el.querySelector('.feed-meta').textContent = poolLabel
            ? `${poolLabel} · Ledger ${item.ledger}`
            : `Ledger ${item.ledger}`;
        return el;
    },

    createNoteRow(note, opts = {}) {
        const row = App.templates.noteRow.content.cloneNode(true).firstElementChild;
        row.dataset.noteId = note.id;
        row.querySelector('.note-token').textContent = note.tokenLabel || 'Token';
        row.querySelector('.note-id').textContent = Utils.truncateHex(note.id, 10, 8);
        row.querySelector('.note-id').title = note.id;
        row.querySelector('.note-amount').textContent = Utils.formatTokenAmount(note.amount, note.tokenLabel || 'XLM');
        row.querySelector('.note-ledger').textContent = `Ledger ${note.createdAtLedger || 0}`;
        row.querySelector('.note-pool').textContent = Utils.shortAddress(note.poolContractId, 6, 4);

        const status = row.querySelector('.note-status');
        if (note.spent) {
            status.textContent = 'Spent';
            status.className = 'note-status inline-flex rounded-full border border-rose-400/30 bg-rose-400/10 px-2 py-1 text-[11px] font-medium text-rose-200';
        } else {
            status.textContent = 'Available';
            status.className = 'note-status inline-flex rounded-full border border-cyan-400/30 bg-cyan-400/10 px-2 py-1 text-[11px] font-medium text-cyan-100';
        }

        // A spent note can't be used as a transact input — hide its Use button.
        const useBtn = row.querySelector('.note-use');
        if (useBtn) {
            if (note.spent) {
                useBtn.classList.add('hidden');
            } else {
                useBtn.addEventListener('click', () => opts.onUse?.(note));
            }
        }
        row.querySelector('.note-copy')?.addEventListener('click', () => opts.onCopy?.(note));
        const disclose = row.querySelector('.note-disclose');
        if (disclose) {
            disclose.href = `disclosure.html?commitment=${encodeURIComponent(note.id)}`;
        }
        return row;
    },
};
