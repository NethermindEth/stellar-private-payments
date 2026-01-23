/**
 * Template Manager - handles DOM template cloning and population.
 * @module ui/templates
 */

import { App, Utils, Toast } from './core.js';
import { StateManager } from '../state/index.js';

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
        
        // Download button
        row.querySelector('.download-btn').addEventListener('click', () => {
            const noteId = row.querySelector('.output-note-id');
            if (noteId.dataset.noteData) {
                Utils.downloadFile(noteId.dataset.noteData, `note-${Date.now()}.json`);
                Toast.show('Note downloaded!', 'success');
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
     * Empty recipient = self, filled = other recipient.
     * @param {number} index - Row index
     * @param {number} initialValue - Initial amount value
     * @returns {HTMLElement}
     */
    createAdvancedOutputRow(index, initialValue = 0) {
        const row = App.templates.advancedOutputRow.content.cloneNode(true).firstElementChild;
        row.dataset.index = index;
        
        const amountInput = row.querySelector('.output-amount');
        const recipientKey = row.querySelector('.output-recipient-key');
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
        
        // Address book lookup for recipient
        lookupBtn?.addEventListener('click', async () => {
            const address = prompt('Enter Stellar address to look up (G...):');
            if (!address) return;
            
            if (!address.startsWith('G') || address.length !== 56) {
                Toast.show('Invalid Stellar address format', 'error');
                return;
            }
            
            Toast.show('Searching...', 'info');
            
            try {
                const result = await StateManager.searchPublicKey(address);
                
                if (result.found) {
                    recipientKey.value = result.record.publicKey;
                    recipientKey.dispatchEvent(new Event('input', { bubbles: true }));
                    Toast.show(`Found public key (${result.source})`, 'success');
                } else {
                    Toast.show('No registered public key found for this address', 'error');
                }
            } catch (e) {
                console.error('[Templates] Address lookup failed:', e);
                Toast.show('Lookup failed: ' + e.message, 'error');
            }
        });
        
        // Copy button
        row.querySelector('.copy-btn').addEventListener('click', () => {
            const noteId = row.querySelector('.output-note-id');
            if (noteId.dataset.fullId) {
                Utils.copyToClipboard(noteId.dataset.fullId);
            }
        });
        
        // Download button
        row.querySelector('.download-btn').addEventListener('click', () => {
            const noteId = row.querySelector('.output-note-id');
            if (noteId.dataset.noteData) {
                Utils.downloadFile(noteId.dataset.noteData, `note-${Date.now()}.json`);
                Toast.show('Note downloaded!', 'success');
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
        const fileInput = row.querySelector('.file-input');
        const uploadBtn = row.querySelector('.upload-btn');
        
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
                valueDisplay.classList.remove('text-brand-400');
            }
        });
        
        // Shared file processing function
        const processFile = async (file) => {
            try {
                const text = await file.text();
                try {
                    const data = JSON.parse(text);
                    noteInput.value = data.id || text.trim();
                } catch {
                    noteInput.value = text.trim();
                }
                noteInput.dispatchEvent(new Event('input', { bubbles: true }));
                Toast.show('Note loaded from file', 'success');
            } catch {
                Toast.show('Failed to read file', 'error');
            }
        };
        
        // File upload button
        uploadBtn.addEventListener('click', () => fileInput.click());
        
        fileInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            await processFile(file);
            fileInput.value = '';
        });
        
        // Drag and drop support
        row.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            row.classList.add('border-brand-500', 'bg-brand-500/10');
        });
        
        row.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            row.classList.remove('border-brand-500', 'bg-brand-500/10');
        });
        
        row.addEventListener('drop', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            row.classList.remove('border-brand-500', 'bg-brand-500/10');
            
            const files = e.dataTransfer?.files;
            if (files && files.length > 0) {
                await processFile(files[0]);
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
        
        row.querySelector('.note-id').textContent = Utils.truncateHex(note.id, 10, 8);
        // Note.amount is in stroops - convert to XLM for display
        const amountXLM = Number(note.amount) / 1e7;
        row.querySelector('.note-amount').textContent = `${amountXLM.toFixed(7).replace(/\.?0+$/, '')} XLM`;
        row.querySelector('.note-date').textContent = Utils.formatDate(note.createdAt);
        
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
        
        // Download button (export note as file for later use)
        const downloadBtn = row.querySelector('.download-btn');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', () => {
                const noteData = {
                    id: note.id,
                    commitment: note.commitment || note.id,
                    amount: note.amount, // Stored in stroops
                    blinding: note.blinding,
                    leafIndex: note.leafIndex,
                    createdAt: note.createdAt,
                    version: 1,
                };
                const blob = new Blob([JSON.stringify(noteData, null, 2)], { type: 'application/json' });
                const amountXLM = Number(note.amount) / 1e7;
                const filename = `note_${note.id.slice(0, 8)}_${amountXLM}xlm.json`;
                Utils.downloadFile(blob, filename);
                Toast.show('Note file downloaded', 'success');
            });
        }
        
        // Copy button
        row.querySelector('.copy-btn').addEventListener('click', () => {
            Utils.copyToClipboard(note.id);
        });
        
        return row;
    }
};
