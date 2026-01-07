/**
 * PoolStellar Compliant Private System
 * Vanilla JS with template-based DOM manipulation
 */
import { pingTestnet } from './stellar.js';
import { connectWallet, getWalletNetwork } from './wallet.js';

// ============================================
// Application State
// ============================================
const App = {
    state: {
        wallet: { connected: false, address: null },
        notes: [],
        activeTab: 'deposit'
    },
    
    // Template references (cached on init)
    templates: {},
    
    // DOM element references
    els: {}
};

// ============================================
// Utilities
// ============================================
const Utils = {
    generateHex(length = 64) {
        const chars = '0123456789abcdef';
        let result = '0x';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    },

    truncateHex(hex, start = 8, end = 8) {
        if (!hex || hex.length <= start + end + 3) return hex;
        return `${hex.slice(0, start)}...${hex.slice(-end)}`;
    },

    formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    formatDate(dateStr) {
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    },

    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            Toast.show('Copied to clipboard!', 'success');
            return true;
        } catch {
            Toast.show('Failed to copy', 'error');
            return false;
        }
    },

    downloadFile(data, filename) {
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
};

// ============================================
// Storage
// ============================================
const Storage = {
    KEY: 'poolstellar_notes',
    
    save() {
        try {
            localStorage.setItem(this.KEY, JSON.stringify(App.state.notes));
        } catch (e) {
            console.error('Storage save failed:', e);
        }
    },
    
    load() {
        try {
            const data = localStorage.getItem(this.KEY);
            if (data) App.state.notes = JSON.parse(data);
        } catch (e) {
            console.error('Storage load failed:', e);
            App.state.notes = [];
        }
    }
};

// ============================================
// Toast Notifications
// ============================================
const Toast = {
    show(message, type = 'success', duration = 4000) {
        const container = document.getElementById('toast-container');
        const template = App.templates.toast;
        const toast = template.content.cloneNode(true).firstElementChild;
        
        // Set content
        toast.querySelector('.toast-message').textContent = message;
        
        // Set icon
        const icon = toast.querySelector('.toast-icon');
        if (type === 'success') {
            icon.innerHTML = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
            toast.classList.add('border-emerald-500/50');
            icon.classList.add('text-emerald-500');
        } else {
            icon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>';
            toast.classList.add('border-red-500/50');
            icon.classList.add('text-red-500');
        }
        
        // Close button handler
        toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());
        
        container.appendChild(toast);
        
        // Auto-remove
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 200);
        }, duration);
    }
};

// ============================================
// Template Manager
// ============================================
const Templates = {
    init() {
        App.templates = {
            outputRow: document.getElementById('tpl-output-row'),
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
                valueDisplay.textContent = `${note.amount} XLM`;
                valueDisplay.classList.remove('text-dark-500');
                valueDisplay.classList.add('text-brand-400');
            } else {
                valueDisplay.textContent = '0 XLM';
                valueDisplay.classList.add('text-dark-500');
                valueDisplay.classList.remove('text-brand-400');
            }
        });
        
        // File upload
        uploadBtn.addEventListener('click', () => fileInput.click());
        
        fileInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            
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
            fileInput.value = '';
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
        row.querySelector('.note-amount').textContent = `${note.amount} XLM`;
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
        
        // Use button
        const useBtn = row.querySelector('.use-btn');
        if (useBtn) {
            useBtn.addEventListener('click', () => {
                Tabs.switch('withdraw');
                const inputs = document.querySelectorAll('#withdraw-inputs .note-input');
                if (inputs[0]) {
                    inputs[0].value = note.id;
                    inputs[0].dispatchEvent(new Event('input', { bubbles: true }));
                }
            });
        }
        
        // Copy button
        row.querySelector('.copy-btn').addEventListener('click', () => {
            Utils.copyToClipboard(note.id);
        });
        
        return row;
    }
};

// ============================================
// Tabs
// ============================================
const Tabs = {
    init() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => this.switch(btn.dataset.tab));
        });
    },
    
    switch(tabId) {
        App.state.activeTab = tabId;
        
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            const isActive = btn.dataset.tab === tabId;
            btn.setAttribute('aria-selected', isActive);
            
            if (isActive) {
                btn.classList.add('bg-dark-800', 'text-brand-500', 'border', 'border-brand-500/30', 'shadow-lg', 'shadow-brand-500/10');
                btn.classList.remove('text-dark-400', 'hover:text-dark-200', 'hover:bg-dark-800');
            } else {
                btn.classList.remove('bg-dark-800', 'text-brand-500', 'border', 'border-brand-500/30', 'shadow-lg', 'shadow-brand-500/10');
                btn.classList.add('text-dark-400', 'hover:text-dark-200', 'hover:bg-dark-800');
            }
        });
        
        // Update panels
        document.querySelectorAll('.tab-panel').forEach(panel => {
            const isActive = panel.id === `panel-${tabId}`;
            panel.classList.toggle('hidden', !isActive);
        });
    }
};

// ============================================
// Wallet
// ============================================
const Wallet = {
    init() {
        document.getElementById('wallet-btn').addEventListener('click', () => this.toggle());
    },
    
    async toggle() {
        if (App.state.wallet.connected) {
            this.disconnect();
        } else {
            await this.connect();
        }
    },
    
    async connect() {
        const btn = document.getElementById('wallet-btn');
        const text = document.getElementById('wallet-text');
        const network = document.getElementById('network-name');
        
        try {
            const publicKey = await connectWallet();
            App.state.wallet = { connected: true, address: publicKey };
            
            btn.classList.add('border-emerald-500', 'bg-emerald-500/10');
            text.textContent = Utils.truncateHex(App.state.wallet.address, 7, 6);

            if (network) {
                const details = await getWalletNetwork();
                network.textContent = details.network || 'Unknown';
            }

            Toast.show('Wallet connected!', 'success');
        } catch (e) {
            console.error('Wallet connection error:', e);
            const message = e?.code === 'USER_REJECTED'
                ? 'Wallet connection cancelled'
                : (e?.message || 'Failed to connect wallet');
            Toast.show(message, 'error');
        }
    },
    
    disconnect() {
        const btn = document.getElementById('wallet-btn');
        const text = document.getElementById('wallet-text');
        const network = document.getElementById('network-name');
        
        App.state.wallet = { connected: false, address: null };
        btn.classList.remove('border-emerald-500', 'bg-emerald-500/10');
        text.textContent = 'Connect Freighter';
        if (network) {
            network.textContent = 'Network';
        }
        Toast.show('Wallet disconnected', 'success');
    }
};

// ============================================
// Deposit Module
// ============================================
const Deposit = {
    init() {
        const slider = document.getElementById('deposit-slider');
        const amount = document.getElementById('deposit-amount');
        const outputs = document.getElementById('deposit-outputs');
        const btn = document.getElementById('btn-deposit');
        
        // Create initial output rows
        outputs.appendChild(Templates.createOutputRow(0, 10));
        outputs.appendChild(Templates.createOutputRow(1, 0));
        
        // Sync slider and input
        slider.addEventListener('input', () => {
            amount.value = slider.value;
            this.updateBalance();
        });
        
        amount.addEventListener('input', () => {
            slider.value = Math.min(Math.max(0, amount.value), 1000);
            this.updateBalance();
        });
        
        // Update balance on output change
        outputs.addEventListener('input', () => this.updateBalance());
        
        // Spinner buttons
        this.initSpinners();
        
        // Submit
        btn.addEventListener('click', () => this.submit());
        
        this.updateBalance();
    },
    
    initSpinners() {
        document.querySelectorAll('[data-target="deposit-amount"]').forEach(btn => {
            btn.addEventListener('click', () => {
                const input = document.getElementById('deposit-amount');
                const val = parseFloat(input.value) || 0;
                input.value = btn.classList.contains('spinner-up') ? val + 1 : Math.max(0, val - 1);
                input.dispatchEvent(new Event('input', { bubbles: true }));
            });
        });
    },
    
    updateBalance() {
        const depositVal = parseFloat(document.getElementById('deposit-amount').value) || 0;
        
        let outputsTotal = 0;
        document.querySelectorAll('#deposit-outputs .output-amount').forEach(input => {
            outputsTotal += parseFloat(input.value) || 0;
        });
        
        const eq = document.getElementById('deposit-balance');
        eq.querySelector('[data-eq="input"]').textContent = `Deposit: ${depositVal}`;
        eq.querySelector('[data-eq="outputs"]').textContent = `Outputs: ${outputsTotal}`;
        
        const isBalanced = Math.abs(depositVal - outputsTotal) < 0.0000001 && depositVal > 0;
        const status = eq.querySelector('[data-eq="status"]');
        
        if (depositVal > 0 || outputsTotal > 0) {
            if (isBalanced) {
                status.innerHTML = '<svg class="w-5 h-5 text-emerald-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
                eq.classList.remove('border-red-500/50', 'bg-red-500/5');
                eq.classList.add('border-emerald-500/50', 'bg-emerald-500/5');
            } else {
                status.innerHTML = '<svg class="w-5 h-5 text-red-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
                eq.classList.add('border-red-500/50', 'bg-red-500/5');
                eq.classList.remove('border-emerald-500/50', 'bg-emerald-500/5');
            }
        } else {
            status.innerHTML = '';
            eq.classList.remove('border-red-500/50', 'bg-red-500/5', 'border-emerald-500/50', 'bg-emerald-500/5');
        }
        
        return isBalanced;
    },
    
    async submit() {
        if (!App.state.wallet.connected) {
            Toast.show('Please connect your wallet first', 'error');
            return;
        }
        
        if (!this.updateBalance()) {
            Toast.show('Deposit amount must equal sum of outputs', 'error');
            return;
        }
        
        const totalAmount = parseFloat(document.getElementById('deposit-amount').value);
        const btn = document.getElementById('btn-deposit');
        
        btn.disabled = true;
        btn.querySelector('.btn-text').classList.add('hidden');
        btn.querySelector('.btn-loading').classList.remove('hidden');
        
        try {
            await new Promise(r => setTimeout(r, 2000));
            
            document.querySelectorAll('#deposit-outputs .output-row').forEach(row => {
                const amount = parseFloat(row.querySelector('.output-amount').value) || 0;
                const isDummy = amount === 0;
                const noteId = Utils.generateHex(64);
                
                const note = {
                    id: noteId,
                    commitment: Utils.generateHex(64),
                    nullifier: Utils.generateHex(64),
                    amount,
                    blinding: Utils.generateHex(64),
                    spent: false,
                    isDummy,
                    createdAt: new Date().toISOString()
                };
                
                if (!isDummy) App.state.notes.push(note);
                
                const display = row.querySelector('.output-note-id');
                display.value = Utils.truncateHex(noteId, 8, 8);
                display.dataset.fullId = noteId;
                display.dataset.noteData = JSON.stringify(note, null, 2);
                
                row.querySelector('.copy-btn').disabled = false;
                row.querySelector('.download-btn').disabled = false;
            });
            
            Storage.save();
            NotesTable.render();
            Toast.show(`Successfully deposited ${totalAmount} XLM!`, 'success');
        } catch (e) {
            Toast.show('Deposit failed: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btn.querySelector('.btn-text').classList.remove('hidden');
            btn.querySelector('.btn-loading').classList.add('hidden');
        }
    }
};

// ============================================
// Withdraw Module
// ============================================
const Withdraw = {
    init() {
        const inputs = document.getElementById('withdraw-inputs');
        const btn = document.getElementById('btn-withdraw');
        
        // Create 2 input rows
        inputs.appendChild(Templates.createInputRow(0));
        inputs.appendChild(Templates.createInputRow(1));
        
        // Update total on input change
        inputs.addEventListener('input', () => this.updateTotal());
        
        btn.addEventListener('click', () => this.submit());
    },
    
    updateTotal() {
        let total = 0;
        document.querySelectorAll('#withdraw-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const note = App.state.notes.find(n => n.id === noteId && !n.spent);
            if (note) total += note.amount;
        });
        document.getElementById('withdraw-total').textContent = `${total} XLM`;
        return total;
    },
    
    async submit() {
        if (!App.state.wallet.connected) {
            Toast.show('Please connect your wallet first', 'error');
            return;
        }
        
        const total = this.updateTotal();
        if (total === 0) {
            Toast.show('Please enter at least one note with value > 0', 'error');
            return;
        }
        
        const recipient = document.getElementById('withdraw-recipient').value.trim();
        if (!recipient) {
            Toast.show('Please enter a recipient address', 'error');
            return;
        }
        
        const btn = document.getElementById('btn-withdraw');
        btn.disabled = true;
        btn.querySelector('.btn-text').classList.add('hidden');
        btn.querySelector('.btn-loading').classList.remove('hidden');
        
        try {
            await new Promise(r => setTimeout(r, 2500));
            
            document.querySelectorAll('#withdraw-inputs .note-input').forEach(input => {
                const noteId = input.value.trim();
                const note = App.state.notes.find(n => n.id === noteId);
                if (note && note.amount > 0) note.spent = true;
            });
            
            Storage.save();
            NotesTable.render();
            Toast.show('Withdrawal successful!', 'success');
            
            // Clear
            document.querySelectorAll('#withdraw-inputs .note-input').forEach(i => { i.value = ''; });
            document.querySelectorAll('#withdraw-inputs .value-display').forEach(d => {
                d.textContent = '0 XLM';
                d.classList.add('text-dark-500');
                d.classList.remove('text-brand-400');
            });
            document.getElementById('withdraw-recipient').value = '';
            this.updateTotal();
        } catch (e) {
            Toast.show('Withdrawal failed: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btn.querySelector('.btn-text').classList.remove('hidden');
            btn.querySelector('.btn-loading').classList.add('hidden');
        }
    }
};

// ============================================
// Transact Module
// ============================================
const Transact = {
    init() {
        const slider = document.getElementById('transact-slider');
        const amount = document.getElementById('transact-amount');
        const inputs = document.getElementById('transact-inputs');
        const outputs = document.getElementById('transact-outputs');
        const btn = document.getElementById('btn-transact');
        
        // Create rows
        inputs.appendChild(Templates.createInputRow(0));
        inputs.appendChild(Templates.createInputRow(1));
        outputs.appendChild(Templates.createOutputRow(0, 0));
        outputs.appendChild(Templates.createOutputRow(1, 0));
        
        // Sync slider and input
        slider.addEventListener('input', () => {
            amount.value = slider.value;
            this.updateBalance();
        });
        
        amount.addEventListener('input', () => {
            slider.value = Math.min(Math.max(-500, amount.value), 500);
            this.updateBalance();
        });
        
        // Update on changes
        inputs.addEventListener('input', () => this.updateBalance());
        outputs.addEventListener('input', () => this.updateBalance());
        
        // Spinners
        document.querySelectorAll('[data-target="transact-amount"]').forEach(btn => {
            btn.addEventListener('click', () => {
                const input = document.getElementById('transact-amount');
                const val = parseFloat(input.value) || 0;
                input.value = btn.classList.contains('spinner-up') ? val + 1 : val - 1;
                input.dispatchEvent(new Event('input', { bubbles: true }));
            });
        });
        
        btn.addEventListener('click', () => this.submit());
        
        this.updateBalance();
    },
    
    updateBalance() {
        let inputsTotal = 0;
        document.querySelectorAll('#transact-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const note = App.state.notes.find(n => n.id === noteId && !n.spent);
            if (note) inputsTotal += note.amount;
        });
        
        const publicAmount = parseFloat(document.getElementById('transact-amount').value) || 0;
        
        let outputsTotal = 0;
        document.querySelectorAll('#transact-outputs .output-amount').forEach(input => {
            outputsTotal += parseFloat(input.value) || 0;
        });
        
        const eq = document.getElementById('transact-balance');
        eq.querySelector('[data-eq="inputs"]').textContent = `Inputs: ${inputsTotal}`;
        eq.querySelector('[data-eq="public"]').textContent = `Public: ${publicAmount >= 0 ? '+' : ''}${publicAmount}`;
        eq.querySelector('[data-eq="outputs"]').textContent = `Outputs: ${outputsTotal}`;
        
        const leftSide = inputsTotal + publicAmount;
        const isBalanced = Math.abs(leftSide - outputsTotal) < 0.0000001;
        const hasValues = inputsTotal > 0 || publicAmount !== 0 || outputsTotal > 0;
        
        const validIcon = eq.querySelector('[data-icon="valid"]');
        const invalidIcon = eq.querySelector('[data-icon="invalid"]');
        
        validIcon.classList.toggle('hidden', !hasValues || !isBalanced);
        invalidIcon.classList.toggle('hidden', !hasValues || isBalanced);
        
        eq.classList.toggle('border-emerald-500/50', hasValues && isBalanced);
        eq.classList.toggle('bg-emerald-500/5', hasValues && isBalanced);
        eq.classList.toggle('border-red-500/50', hasValues && !isBalanced);
        eq.classList.toggle('bg-red-500/5', hasValues && !isBalanced);
        
        return isBalanced;
    },
    
    async submit() {
        if (!App.state.wallet.connected) {
            Toast.show('Please connect your wallet first', 'error');
            return;
        }
        
        if (!this.updateBalance()) {
            Toast.show('Equation must balance: Inputs + Public = Outputs', 'error');
            return;
        }
        
        const btn = document.getElementById('btn-transact');
        btn.disabled = true;
        btn.querySelector('.btn-text').classList.add('hidden');
        btn.querySelector('.btn-loading').classList.remove('hidden');
        
        try {
            await new Promise(r => setTimeout(r, 3000));
            
            // Get output recipient (if different from self)
            const outputRecipient = document.getElementById('transact-outputs-recipient').value.trim();
            const isForSelf = !outputRecipient || outputRecipient === App.state.wallet.address;
            
            // Create output notes
            document.querySelectorAll('#transact-outputs .output-row').forEach(row => {
                const amount = parseFloat(row.querySelector('.output-amount').value) || 0;
                const isDummy = amount === 0;
                const noteId = Utils.generateHex(64);
                
                const note = {
                    id: noteId,
                    commitment: Utils.generateHex(64),
                    nullifier: Utils.generateHex(64),
                    amount,
                    blinding: Utils.generateHex(64),
                    spent: false,
                    isDummy,
                    owner: outputRecipient || App.state.wallet.address,
                    createdAt: new Date().toISOString()
                };
                
                // Only store locally if for self
                if (!isDummy && isForSelf) App.state.notes.push(note);
                
                const display = row.querySelector('.output-note-id');
                display.value = Utils.truncateHex(noteId, 8, 8);
                display.dataset.fullId = noteId;
                display.dataset.noteData = JSON.stringify(note, null, 2);
                
                row.querySelector('.copy-btn').disabled = false;
                row.querySelector('.download-btn').disabled = false;
            });
            
            // Mark inputs as spent
            document.querySelectorAll('#transact-inputs .note-input').forEach(input => {
                const noteId = input.value.trim();
                const note = App.state.notes.find(n => n.id === noteId);
                if (note && note.amount > 0) note.spent = true;
            });
            
            Storage.save();
            NotesTable.render();
            
            if (isForSelf) {
                Toast.show('Transaction successful!', 'success');
            } else {
                Toast.show('Transaction successful! Share note files with recipient.', 'success');
            }
        } catch (e) {
            Toast.show('Transaction failed: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btn.querySelector('.btn-text').classList.remove('hidden');
            btn.querySelector('.btn-loading').classList.add('hidden');
        }
    }
};

// ============================================
// Notes Table
// ============================================
const NotesTable = {
    filter: 'all',
    
    init() {
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.filter = btn.dataset.filter;
                
                document.querySelectorAll('.filter-btn').forEach(b => {
                    const isActive = b === btn;
                    b.setAttribute('aria-selected', isActive);
                    b.classList.toggle('bg-dark-700', isActive);
                    b.classList.toggle('text-dark-50', isActive);
                    b.classList.toggle('text-dark-400', !isActive);
                });
                
                this.render();
            });
        });
        
        this.render();
    },
    
    render() {
        const tbody = document.getElementById('notes-tbody');
        const empty = document.getElementById('empty-notes');
        
        // Clear
        tbody.replaceChildren();
        
        // Filter and sort
        let notes = [...App.state.notes];
        if (this.filter === 'unspent') notes = notes.filter(n => !n.spent);
        if (this.filter === 'spent') notes = notes.filter(n => n.spent);
        notes.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        
        if (notes.length === 0) {
            empty.classList.remove('hidden');
            empty.classList.add('flex');
            return;
        }
        
        empty.classList.add('hidden');
        empty.classList.remove('flex');
        
        notes.forEach(note => {
            tbody.appendChild(Templates.createNoteRow(note));
        });
    }
};

// ============================================
// Transfer Module
// ============================================
const Transfer = {
    init() {
        const inputs = document.getElementById('transfer-inputs');
        const outputs = document.getElementById('transfer-outputs');
        const btn = document.getElementById('btn-transfer');
        
        // Create 2 input rows and 2 output rows
        inputs.appendChild(Templates.createInputRow(0));
        inputs.appendChild(Templates.createInputRow(1));
        outputs.appendChild(Templates.createOutputRow(0, 0));
        outputs.appendChild(Templates.createOutputRow(1, 0));
        
        // Update balance on changes
        inputs.addEventListener('input', () => this.updateBalance());
        outputs.addEventListener('input', () => this.updateBalance());
        
        btn.addEventListener('click', () => this.submit());
        
        this.updateBalance();
    },
    
    updateBalance() {
        let inputsTotal = 0;
        document.querySelectorAll('#transfer-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const note = App.state.notes.find(n => n.id === noteId && !n.spent);
            if (note) inputsTotal += note.amount;
        });
        
        let outputsTotal = 0;
        document.querySelectorAll('#transfer-outputs .output-amount').forEach(input => {
            outputsTotal += parseFloat(input.value) || 0;
        });
        
        const eq = document.getElementById('transfer-balance');
        eq.querySelector('[data-eq="inputs"]').textContent = `Inputs: ${inputsTotal}`;
        eq.querySelector('[data-eq="outputs"]').textContent = `Outputs: ${outputsTotal}`;
        
        const isBalanced = Math.abs(inputsTotal - outputsTotal) < 0.0000001;
        const hasValues = inputsTotal > 0 || outputsTotal > 0;
        
        const validIcon = eq.querySelector('[data-icon="valid"]');
        const invalidIcon = eq.querySelector('[data-icon="invalid"]');
        
        validIcon.classList.toggle('hidden', !hasValues || !isBalanced);
        invalidIcon.classList.toggle('hidden', !hasValues || isBalanced);
        
        eq.classList.toggle('border-emerald-500/50', hasValues && isBalanced);
        eq.classList.toggle('bg-emerald-500/5', hasValues && isBalanced);
        eq.classList.toggle('border-red-500/50', hasValues && !isBalanced);
        eq.classList.toggle('bg-red-500/5', hasValues && !isBalanced);
        
        return isBalanced;
    },
    
    async submit() {
        if (!App.state.wallet.connected) {
            Toast.show('Please connect your wallet first', 'error');
            return;
        }
        
        const recipientKey = document.getElementById('transfer-recipient-key').value.trim();
        if (!recipientKey) {
            Toast.show('Please enter recipient public key', 'error');
            return;
        }
        
        if (!this.updateBalance()) {
            Toast.show('Input notes must equal output notes', 'error');
            return;
        }
        
        // Check at least one input has value
        let hasInput = false;
        document.querySelectorAll('#transfer-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const note = App.state.notes.find(n => n.id === noteId && !n.spent);
            if (note && note.amount > 0) hasInput = true;
        });
        
        if (!hasInput) {
            Toast.show('Please enter at least one input note with value > 0', 'error');
            return;
        }
        
        const btn = document.getElementById('btn-transfer');
        btn.disabled = true;
        btn.querySelector('.btn-text').classList.add('hidden');
        btn.querySelector('.btn-loading').classList.remove('hidden');
        
        try {
            await new Promise(r => setTimeout(r, 3000));
            
            // Create output notes (owned by recipient, not stored locally)
            document.querySelectorAll('#transfer-outputs .output-row').forEach(row => {
                const amount = parseFloat(row.querySelector('.output-amount').value) || 0;
                const isDummy = amount === 0;
                const noteId = Utils.generateHex(64);
                
                const note = {
                    id: noteId,
                    commitment: Utils.generateHex(64),
                    nullifier: Utils.generateHex(64),
                    amount,
                    blinding: Utils.generateHex(64),
                    spent: false,
                    isDummy,
                    owner: recipientKey,
                    createdAt: new Date().toISOString()
                };
                
                // Note: We don't store these locally as they belong to the recipient
                
                const display = row.querySelector('.output-note-id');
                display.value = Utils.truncateHex(noteId, 8, 8);
                display.dataset.fullId = noteId;
                display.dataset.noteData = JSON.stringify(note, null, 2);
                
                row.querySelector('.copy-btn').disabled = false;
                row.querySelector('.download-btn').disabled = false;
            });
            
            // Mark input notes as spent
            document.querySelectorAll('#transfer-inputs .note-input').forEach(input => {
                const noteId = input.value.trim();
                const note = App.state.notes.find(n => n.id === noteId);
                if (note && note.amount > 0) note.spent = true;
            });
            
            Storage.save();
            NotesTable.render();
            Toast.show('Transfer successful! Share the note files with the recipient.', 'success');
        } catch (e) {
            Toast.show('Transfer failed: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btn.querySelector('.btn-text').classList.remove('hidden');
            btn.querySelector('.btn-loading').classList.add('hidden');
        }
    }
};

// ============================================
// Stats
// ============================================
const Stats = {
    init() {
        const txList = document.getElementById('recent-tx');
        const transactions = [
            { hash: '0x3f2a...8b1c', time: '2m ago' },
            { hash: '0x7d9e...4a2f', time: '15m ago' },
            { hash: '0xc4b8...9e3d', time: '1h ago' }
        ];
        
        transactions.forEach(tx => {
            txList.appendChild(Templates.createTxItem(tx.hash, tx.time));
        });
    }
};

// ============================================
// Initialize
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    Templates.init();
    Storage.load();
    
    Tabs.init();
    Wallet.init();
    Deposit.init();
    Withdraw.init();
    Transfer.init();
    Transact.init();
    NotesTable.init();
    Stats.init();
    
    console.log('PoolStellar initialized');
});

async function initializeWorker() {
    return new Promise((resolve, reject) => {
        const worker = new Worker('js/worker.js', { type: 'module' });

        worker.onmessage = (event) => {
            const { type, error } = event.data;

            if (type === 'READY') {
                console.log("Worker is ready.");
                resolve(worker);
            } else if (type === 'ERROR') {
                reject(new Error(error));
            }
        };

        worker.onerror = (err) => reject(err);
    });
}

async function main() {
    // Initialize worker with a prover
    let worker = null;
    try {
        worker = await initializeWorker();
        console.log("Initialization complete!");
    } catch (err) {
        console.error("Critical Failure:", err);
    }

    worker.onmessage = (event) => {
        const { type, result, error } = event.data;
        if (type === 'PROVE') {
            const decoder = new TextDecoder();
            const str = decoder.decode(event.data.payload);
            console.log(`Proof ${str}`);
        }
        
    };

    worker.postMessage({ 
        type: 'PROVE' 
    });
    console.log("Ping Stellar");
    // Test Stellar network
    pingTestnet();
}

main();
