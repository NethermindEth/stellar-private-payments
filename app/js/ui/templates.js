/**
 * Template Manager - handles DOM template cloning and population.
 * @module ui/templates
 */

import { App, Utils, Toast } from './core.js';
import { AddressBook } from './address-book.js';

// Forward reference - set by navigation.js after it loads
let TabsRef = null;

/**
 * Sets the Tabs reference for use in template event handlers.
 * Called by navigation.js during initialization.
 * @param {Object} tabs - The Tabs module
 */
export function setTabsRef(tabs) {
    TabsRef = tabs;
}

export const Templates = {
    init() {
        App.templates = {
            outputRow: document.getElementById('tpl-output-row'),
            advancedOutputRow: document.getElementById('tpl-advanced-output-row'),
            inputRow: document.getElementById('tpl-input-row'),
            txItem: document.getElementById('tpl-tx-item'),
            noteRow: document.getElementById('tpl-note-row'),
            addressBookRow: document.getElementById('tpl-addressbook-row'),
            toast: document.getElementById('tpl-toast')
        };
    },
    
    createOutputRow(index, initialValue = 0) {
        const row = App.templates.outputRow.content.cloneNode(true).firstElementChild;
        row.dataset.index = index;
        
        const amountInput = row.querySelector('.output-amount');
        amountInput.value = initialValue;
        
        // Update dummy badge on value change
        amountInput.addEventListener('input', () => {
            const val = parseFloat(amountInput.value) || 0;
            row.querySelector('.dummy-badge').classList.toggle('hidden', val !== 0);
        });
        
        // Mini spinner buttons
        row.querySelector('.mini-up').addEventListener('click', () => {
            amountInput.value = (parseFloat(amountInput.value) || 0) + 1;
            amountInput.dispatchEvent(new Event('input', { bubbles: true }));
        });
        
        row.querySelector('.mini-down').addEventListener('click', () => {
            amountInput.value = Math.max(0, (parseFloat(amountInput.value) || 0) - 1);
            amountInput.dispatchEvent(new Event('input', { bubbles: true }));
        });
        
        // Copy button
        row.querySelector('.copy-btn').addEventListener('click', () => {
            const noteId = row.querySelector('.output-note-id');
            if (noteId.dataset.fullId) {
                Utils.copyToClipboard(noteId.dataset.fullId);
            }
        });
        
        // Initial dummy state
        if (initialValue === 0) {
            row.querySelector('.dummy-badge').classList.remove('hidden');
        }
        
        return row;
    },
    
    /**
     * Creates an advanced output row with per-output recipient selection.
     * Used in Transact mode where each output can go to a different recipient.
     * Each output requires two keys: BN254 note key and X25519 encryption key.
     * Empty keys = self, filled = other recipient.
     * @param {number} index - Row index
     * @param {number} initialValue - Initial amount value
     * @returns {HTMLElement}
     */
    createAdvancedOutputRow(index, initialValue = 0) {
        const row = App.templates.advancedOutputRow.content.cloneNode(true).firstElementChild;
        row.dataset.index = index;
        
        const amountInput = row.querySelector('.output-amount');
        const noteKeyInput = row.querySelector('.output-note-key');
        const encKeyInput = row.querySelector('.output-enc-key');
        const lookupBtn = row.querySelector('.output-lookup-btn');
        
        amountInput.value = initialValue;
        
        // Update dummy badge on value change
        amountInput.addEventListener('input', () => {
            const val = parseFloat(amountInput.value) || 0;
            row.querySelector('.dummy-badge').classList.toggle('hidden', val !== 0);
        });
        
        // Mini spinner buttons
        row.querySelector('.mini-up').addEventListener('click', () => {
            amountInput.value = (parseFloat(amountInput.value) || 0) + 1;
            amountInput.dispatchEvent(new Event('input', { bubbles: true }));
        });
        
        row.querySelector('.mini-down').addEventListener('click', () => {
            amountInput.value = Math.max(0, (parseFloat(amountInput.value) || 0) - 1);
            amountInput.dispatchEvent(new Event('input', { bubbles: true }));
        });
        
        // Address book lookup - scroll to address book section
        lookupBtn?.addEventListener('click', () => {
            AddressBook.switchSection('addressbook');
            const section = document.getElementById('section-panel-addressbook');
            if (section) {
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            setTimeout(() => {
                document.getElementById('addressbook-search')?.focus();
            }, 300);
            Toast.show('Select a recipient from the address book', 'info');
        });
        
        // Copy button
        row.querySelector('.copy-btn').addEventListener('click', () => {
            const noteId = row.querySelector('.output-note-id');
            if (noteId.dataset.fullId) {
                Utils.copyToClipboard(noteId.dataset.fullId);
            }
        });
        
        // Initial dummy state
        if (initialValue === 0) {
            row.querySelector('.dummy-badge').classList.remove('hidden');
        }
        
        return row;
    },
    
    createInputRow(index) {
        const row = App.templates.inputRow.content.cloneNode(true).firstElementChild;
        row.dataset.index = index;
        
        const noteInput = row.querySelector('.note-input');
        const valueDisplay = row.querySelector('.value-display');
        
        // Update value display when note ID changes
        noteInput.addEventListener('input', () => {
            const noteId = noteInput.value.trim();
            const note = App.state.notes.find(n => n.id === noteId && !n.spent);
            
            if (note) {
                // Convert stroops to XLM for display
                const amountXLM = Number(note.amount) / 1e7;
                valueDisplay.textContent = `${amountXLM} XLM`;
                valueDisplay.classList.remove('text-dark-500');
                valueDisplay.classList.add('text-brand-400');
            } else {
                valueDisplay.textContent = '0 XLM';
                valueDisplay.classList.add('text-dark-500');
                valueDisplay.classList.remove('text-brand-400', 'italic');
                valueDisplay.title = '';
            }
        });
        
        return row;
    },
    
    createTxItem(hash, time) {
        const item = App.templates.txItem.content.cloneNode(true).firstElementChild;
        item.querySelector('.tx-hash').textContent = hash;
        item.querySelector('.tx-time').textContent = time;
        return item;
    },
    
    createNoteRow(note) {
        const row = App.templates.noteRow.content.cloneNode(true).firstElementChild;
        row.dataset.status = note.spent ? 'spent' : 'unspent';
        row.dataset.id = note.id;
        row.dataset.received = 'false';
        
        row.querySelector('.note-id').textContent = Utils.truncateHex(note.id, 10, 8);
        // Note.amount is in stroops - convert to XLM for display
        const amountXLM = Number(note.amount) / 1e7;
        row.querySelector('.note-amount').textContent = `${amountXLM.toFixed(7).replace(/\.?0+$/, '')} XLM`;
        row.querySelector('.note-date').textContent = note.createdAtText || '';
        
        const badge = row.querySelector('.status-badge');
        if (note.spent) {
            badge.textContent = 'Spent';
            badge.classList.add('bg-red-500/20', 'text-red-400');
            row.classList.add('opacity-50');
            row.querySelector('.use-btn')?.remove();
        } else {
            badge.textContent = 'Unspent';
            badge.classList.add('bg-emerald-500/20', 'text-emerald-400');
        }
        
        // Use button - fills note in current tab's input (or switches to withdraw if in deposit)
        const useBtn = row.querySelector('.use-btn');
        if (useBtn) {
            useBtn.addEventListener('click', () => {
                // Determine which tab to use
                let targetTab = App.state.activeTab;
                
                // Deposit doesn't have input notes, redirect to withdraw
                if (targetTab === 'deposit') {
                    targetTab = 'withdraw';
                    if (TabsRef) {
                        TabsRef.switch('withdraw');
                    }
                }
                
                // Map tab to input container ID
                const containerIds = {
                    withdraw: 'withdraw-inputs',
                    transfer: 'transfer-inputs',
                    transact: 'transact-inputs',
                };
                
                const containerId = containerIds[targetTab];
                if (!containerId) return;
                
                const inputs = document.querySelectorAll(`#${containerId} .note-input`);
                if (!inputs.length) return;
                
                // Find first empty input, or use first if all filled
                let targetInput = inputs[0];
                for (const input of inputs) {
                    if (!input.value.trim()) {
                        targetInput = input;
                        break;
                    }
                }
                
                targetInput.value = note.id;
                targetInput.dispatchEvent(new Event('input', { bubbles: true }));
                Toast.show('Note added to input', 'success');
            });
        }
        
        // Copy button
        row.querySelector('.copy-btn').addEventListener('click', () => {
            Utils.copyToClipboard(note.id);
        });
        
        return row;
    }
};
