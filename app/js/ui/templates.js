import { App, Utils } from './core.js';
import { createStatusBadge } from './notes-view.js';

export const Templates = {
    init() {
        App.templates = {
            noteInputRow: document.getElementById('tpl-note-input-row'),
            outputRow: document.getElementById('tpl-output-row'),
            noteRow: document.getElementById('tpl-note-row'),
            feedCard: document.getElementById('tpl-feed-card'),
            balanceCard: document.getElementById('tpl-balance-card'),
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
        this.updateBalanceCard(el, balance);
        return el;
    },

    updateBalanceCard(el, balance) {
        el.dataset.poolId = balance.poolContractId;
        const tokenLink = el.querySelector('.balance-token');
        tokenLink.textContent = balance.tokenLabel;
        Utils.setExplorerLink(tokenLink, Utils.explorerContractUrl(balance.tokenContractId));
        tokenLink.title = balance.tokenContractId;
        el.querySelector('.balance-amount').textContent = Utils.formatPoolAmount(balance.amount, balance.poolContractId);
        const pending = el.querySelector('.balance-pending');
        const pendingAmount = BigInt(balance.pendingAmount ?? 0);
        pending.hidden = pendingAmount === 0n;
        pending.querySelector('.balance-pending-text').textContent = pending.hidden
            ? ''
            : `${Utils.formatPoolAmount(pendingAmount, balance.poolContractId)} being verified…`;
        // Pending notes are listed with the rest, so count them too.
        const pendingNotes = balance.pendingNoteCount ?? 0;
        const notes = balance.noteCount + pendingNotes;
        el.querySelector('.balance-notes').textContent = `${notes} note${notes === 1 ? '' : 's'}`
            + (pendingNotes > 0 ? ` · ${pendingNotes} pending` : '');
        const poolLink = el.querySelector('.balance-pool');
        poolLink.textContent = Utils.shortAddress(balance.poolContractId, 6, 4);
        Utils.setExplorerLink(poolLink, Utils.explorerContractUrl(balance.poolContractId));
        poolLink.title = balance.poolContractId;
    },

    createFeedCard(item, poolLabel) {
        const el = App.templates.feedCard.content.cloneNode(true).firstElementChild;
        el.querySelector('.feed-title').textContent = item.title;
        el.querySelector('.feed-body').textContent = item.body;
        const feedMeta = el.querySelector('.feed-meta');
        feedMeta.textContent = poolLabel
            ? `${poolLabel} · Ledger ${item.ledger}`
            : `Ledger ${item.ledger}`;
        Utils.setExplorerLink(feedMeta, Utils.explorerLedgerUrl(item.ledger));
        return el;
    },

    createNoteRow(note, opts = {}) {
        const row = App.templates.noteRow.content.cloneNode(true).firstElementChild;
        row.dataset.noteId = note.id;
        row.dataset.noteState = note.spent ? 'spent' : note.pending ? 'pending' : 'available';
        row.dataset.noteLedger = String(note.createdAtLedger || 0);
        row.querySelector('.note-token').textContent = note.tokenLabel || 'Token';
        row.querySelector('.note-id').textContent = Utils.truncateHex(note.id, 10, 8);
        row.querySelector('.note-id').title = note.id;
        row.querySelector('.note-amount').textContent = Utils.formatPoolAmount(note.amount, note.poolContractId);
        row.querySelector('.note-ledger').textContent = `Ledger ${note.createdAtLedger || 0}`;
        row.querySelector('.note-pool').textContent = Utils.shortAddress(note.poolContractId, 6, 4);

        row.querySelector('.note-status').replaceWith(createStatusBadge(note.spent, note.pending));

        // A spent or pending note can't be used as a transact input — hide its Use button.
        const useBtn = row.querySelector('.note-use');
        if (useBtn) {
            if (note.spent || note.pending) {
                useBtn.hidden = true;
            } else {
                useBtn.addEventListener('click', () => opts.onUse?.(note));
            }
        }
        row.querySelector('.note-copy')?.addEventListener('click', () => opts.onCopy?.(note));
        const disclose = row.querySelector('.note-disclose');
        if (disclose) {
            disclose.addEventListener('click', (e) => {
                e.preventDefault();
                App.events.dispatchEvent(new CustomEvent('dashboard:view-receipt', { detail: { noteId: note.id, poolId: note.poolContractId } }));
            });
        }
        return row;
    },
};
