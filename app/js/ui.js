/**
 * PoolStellar Compliant Private System
 * Vanilla JS with template-based DOM manipulation
 */
import { connectWallet, getWalletNetwork, signWalletMessage, signWalletTransaction, signWalletAuthEntry } from './wallet.js';
import { 
    readAllContractStates,
    readPoolState,
    readASPMembershipState,
    readASPNonMembershipState,
    getPoolEvents,
    formatAddress,
    loadDeployedContracts,
    getDeployedContracts,
    validateWalletNetwork,
    submitDeposit,
    submitPoolTransaction,
} from './stellar.js';
import { StateManager, poolStore } from './state/index.js';
import * as ProverClient from './prover-client.js';
import { generateDepositProof, generateWithdrawProof, generateTransferProof } from './transaction-builder.js';
import { 
    deriveNotePrivateKeyFromSignature, 
    deriveEncryptionKeypairFromSignature,
    derivePublicKey,
    generateBlinding, 
    fieldToHex,
    bigintToField,
    poseidon2Hash2,
} from './bridge.js';


// Application State
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

/**
 * Derives spending and encryption keys from Freighter wallet signatures.
 * Consolidates the repeated pattern used by Deposit, Withdraw, Transact, and Transfer modules.
 * 
 * @param {Object} options
 * @param {function} options.onStatus - Callback for status updates (e.g., setLoadingText)
 * @param {Object} [options.signOptions] - Options to pass to signWalletMessage
 * @param {number} [options.signDelay=300] - Delay between signature requests (ms)
 * @returns {Promise<{privKeyBytes: Uint8Array, pubKeyBytes: Uint8Array, encryptionKeypair: Object}>}
 * @throws {Error} If user rejects signature requests
 */
async function deriveKeysFromWallet({ onStatus, signOptions = {}, signDelay = 300 }) {
    onStatus?.('Sign message to derive keys (1/2)...');
    
    let spendingResult;
    try {
        spendingResult = await signWalletMessage('Privacy Pool Spending Key [v1]', signOptions);
    } catch (e) {
        if (e.code === 'USER_REJECTED') {
            throw new Error('Please approve the message signature to derive your spending key');
        }
        throw e;
    }
    
    if (!spendingResult?.signedMessage) {
        throw new Error('Spending key signature rejected');
    }
    
    if (signDelay > 0) {
        await new Promise(r => setTimeout(r, signDelay));
    }
    
    onStatus?.('Sign message to derive keys (2/2)...');
    
    let encryptionResult;
    try {
        encryptionResult = await signWalletMessage('Sign to access Privacy Pool [v1]', signOptions);
    } catch (e) {
        if (e.code === 'USER_REJECTED') {
            throw new Error('Please approve the message signature to derive your encryption key');
        }
        throw e;
    }
    
    if (!encryptionResult?.signedMessage) {
        throw new Error('Encryption key signature rejected');
    }
    
    const spendingSigBytes = Uint8Array.from(atob(spendingResult.signedMessage), c => c.charCodeAt(0));
    const encryptionSigBytes = Uint8Array.from(atob(encryptionResult.signedMessage), c => c.charCodeAt(0));
    
    const privKeyBytes = deriveNotePrivateKeyFromSignature(spendingSigBytes);
    const pubKeyBytes = derivePublicKey(privKeyBytes);
    const encryptionKeypair = deriveEncryptionKeypairFromSignature(encryptionSigBytes);
    
    console.log('[KeyDerivation] Derived keys from wallet signatures');
    
    return { privKeyBytes, pubKeyBytes, encryptionKeypair };
}

function getErrorMessage(error) {
    if (!error) return '';
    return error.message || String(error);
}

function isProofVerificationError(message) {
    const msg = (message || '').toLowerCase();
    if (!msg) return false;

    // Pool contract InvalidProof is #7; verifier InvalidProof is #0.
    if (msg.includes('contract') && msg.includes('#7')) return true;
    if (msg.includes('contract') && msg.includes('#0') && msg.includes('verify')) return true;

    return false;
}

function getProofFailureToastMessage(error) {
    const message = getErrorMessage(error);
    if (!message) return '';
    return isProofVerificationError(message) ? 'Tx failed. Proof did not verify.' : '';
}


// Utilities
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

// Storage
const Storage = {
    // Prefix for per-wallet note storage keys.
    KEY_PREFIX: 'poolstellar_notes',

    getKey(address) {
        if (!address) return null;
        return `${this.KEY_PREFIX}:${address}`;
    },

    save(address = App.state.wallet.address) {
        if (!address) return;
        try {
            const key = this.getKey(address);
            localStorage.setItem(key, JSON.stringify(App.state.notes));
        } catch (e) {
            console.error('Storage save failed:', e);
        }
    },

    load(address = App.state.wallet.address) {
        if (!address) {
            App.state.notes = [];
            return;
        }

        try {
            const key = this.getKey(address);
            const data = localStorage.getItem(key);
            App.state.notes = data ? JSON.parse(data) : [];
        } catch (e) {
            console.error('Storage load failed:', e);
            App.state.notes = [];
        }
    },

    clearInMemory() {
        App.state.notes = [];
    }
};

// Toast Notifications
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

// Template Manager
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
        
        // Use button (switch to withdraw and populate input)
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

// Tabs
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

// Wallet
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
        } catch (e) {
            console.error('Wallet connection error:', e);
            const message = e?.code === 'USER_REJECTED'
                ? 'Wallet connection cancelled'
                : (e?.message || 'Failed to connect wallet');
            Toast.show(message, 'error');
            return;
        }

        // Validate wallet is on the correct network
        if (network) {
            try {
                const details = await getWalletNetwork();
                validateWalletNetwork(details.network);
                network.textContent = details.network || 'Unknown';
            } catch (e) {
                console.error('Wallet network error:', e);
                network.textContent = 'Unknown';
                Toast.show(e?.message || 'Failed to fetch wallet network', 'error');
                this.disconnect();
                return;
            }
        }

        // Load notes scoped to this wallet address
        Storage.load(App.state.wallet.address);
        NotesTable.render();

        Toast.show('Wallet connected!', 'success');
        
        // Pre-fill withdrawal recipient fields with wallet address
        Withdraw.prefillRecipient();
        Transact.prefillRecipient();
    },
    
    disconnect() {
        const btn = document.getElementById('wallet-btn');
        const text = document.getElementById('wallet-text');
        const network = document.getElementById('network-name');
        
        App.state.wallet = { connected: false, address: null };
        Storage.clearInMemory();
        NotesTable.render();
        btn.classList.remove('border-emerald-500', 'bg-emerald-500/10');
        text.textContent = 'Connect Freighter';
        if (network) {
            network.textContent = 'Network';
        }
        Toast.show('Wallet disconnected', 'success');
    }
};

// Deposit Module
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
        const btnText = btn.querySelector('.btn-text');
        const btnLoading = btn.querySelector('.btn-loading');
        
        const setLoadingText = (text) => {
            btnLoading.innerHTML = `<svg class="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg><span class="loading-text ml-2">${text}</span>`;
        };
        
        btn.disabled = true;
        btnText.classList.add('hidden');
        btnLoading.classList.remove('hidden');
        
        try {
            // Step 1: Derive keys from wallet signatures
            const { privKeyBytes, pubKeyBytes, encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: setLoadingText,
                signOptions: { address: App.state.wallet.address },
                signDelay: 300,
            });
            const encryptionPubKey = encryptionKeypair.publicKey;
            
            // DEBUG: Compute and print ASP membership leaf for manual contract registration
            const membershipBlindingInput = document.getElementById('deposit-membership-blinding')?.value || '0';
            const membershipBlinding = BigInt(membershipBlindingInput);
            const membershipBlindingBytes = bigintToField(membershipBlinding);
            const membershipLeaf = poseidon2Hash2(pubKeyBytes, membershipBlindingBytes, 1);
            const membershipLeafHex = fieldToHex(membershipLeaf);
            console.log('='.repeat(60));
            console.log('[DEBUG] ASP Membership Leaf Info:');
            console.log('  Public Key (hex):', fieldToHex(pubKeyBytes));
            console.log('  Blinding:', membershipBlinding.toString());
            console.log('  Membership Leaf = poseidon2(pubKey, blinding, domain=1)');
            console.log('  Membership Leaf (hex):', membershipLeafHex);
            console.log('='.repeat(60));
            console.log('To add this leaf to ASP-membership contract via Stellar CLI:');
            console.log(`  stellar contract invoke --id <ASP_MEMBERSHIP_CONTRACT> -- add_leaf --leaf ${membershipLeafHex}`);
            console.log('='.repeat(60));
            
            // Step 2: Fetch on-chain state
            setLoadingText('Fetching on-chain state...');
            const [poolState, membershipState, nonMembershipState] = await Promise.all([
                readPoolState(),
                readASPMembershipState(),
                readASPNonMembershipState(),
            ]);
            
            if (!poolState.success || !membershipState.success || !nonMembershipState.success) {
                throw new Error('Failed to read contract state');
            }
            
            // Parse roots from hex strings to BigInt
            const poolRoot = BigInt(poolState.merkleRoot || '0x0');
            const membershipRoot = BigInt(membershipState.root || '0x0');
            const nonMembershipRoot = BigInt(nonMembershipState.root || '0x0');
            
            console.log('[Deposit] On-chain roots:', {
                pool: poolRoot.toString(16),
                membership: membershipRoot.toString(16),
                nonMembership: nonMembershipRoot.toString(16),
            });
            
            // Step 3: Build output notes (amounts in stroops for circuit/contract)
            const outputs = [];
            document.querySelectorAll('#deposit-outputs .output-row').forEach(row => {
                const amount = parseFloat(row.querySelector('.output-amount').value) || 0;
                // Convert XLM to stroops - required because circuit's publicAmount 
                // must match contract's ext_amount (which transfers tokens in stroops)
                const amountBigInt = BigInt(Math.floor(amount * 1e7));
                const blindingBytes = generateBlinding();
                const blinding = BigInt('0x' + fieldToHex(blindingBytes).slice(2));
                outputs.push({ amount: amountBigInt, blinding });
            });
            
            // Ensure we have exactly 2 outputs (circuit requirement)
            while (outputs.length < 2) {
                const blindingBytes = generateBlinding();
                const blinding = BigInt('0x' + fieldToHex(blindingBytes).slice(2));
                outputs.push({ amount: 0n, blinding });
            }
            
            // Step 4: Generate proof
            const contracts = getDeployedContracts();
            const totalAmountStroops = BigInt(Math.floor(totalAmount * 1_000_000_0));
            
            setLoadingText('Generating ZK proof...');
            const proofResult = await generateDepositProof({
                privKeyBytes,
                encryptionPubKey,
                poolRoot,
                membershipRoot,
                nonMembershipRoot,
                amount: totalAmountStroops,
                outputs,
                poolAddress: contracts.pool,
                stateManager: StateManager,
                membershipLeafIndex: 0, // Fallback. Auto-detected via stateManager.findASPMembershipLeaf()
                membershipBlinding,
            }, {
                onProgress: (progress) => {
                    if (progress.message) {
                        setLoadingText(progress.message);
                    }
                },
            });
            
            console.log('[Deposit] Proof generated:', {
                verified: proofResult.verified,
                timings: proofResult.timings,
            });
            
            // Step 5: Prepare notes (don't save yet - wait for tx success)
            // Get the pool's next leaf index so we can track where our commitments will be
            // Convert to Number since it may come as BigInt from contract
            const poolNextIndex = Number(poolState.merkleNextIndex || 0);
            
            const pendingNotes = [];
            let outputIndex = 0;
            document.querySelectorAll('#deposit-outputs .output-row').forEach(row => {
                const outputNote = proofResult.outputNotes[outputIndex];
                const amountXLM = parseFloat(row.querySelector('.output-amount').value) || 0;
                const isDummy = amountXLM === 0;
                
                // Generate note ID from commitment
                const noteId = fieldToHex(outputNote.commitmentBytes);
                
                // Calculate the leaf index for this output
                // Pool inserts commitments in order: output0 at nextIndex, output1 at nextIndex+1
                const leafIndex = poolNextIndex + outputIndex;
                
                // Store the STROOPS amount (what was used in the commitment)
                // This matches outputNote.amount which is already in stroops
                const amountStroops = Number(outputNote.amount);
                
                const note = {
                    id: noteId,
                    commitment: fieldToHex(outputNote.commitmentBytes),
                    amount: amountStroops, // Store in stroops to match commitment
                    blinding: outputNote.blinding.toString(),
                    leafIndex,
                    spent: false,
                    isDummy,
                    createdAt: new Date().toISOString()
                };
                
                // Store for later - only add to state after tx success
                if (!isDummy) pendingNotes.push(note);
                
                const display = row.querySelector('.output-note-id');
                display.value = Utils.truncateHex(noteId, 8, 8);
                display.dataset.fullId = noteId;
                display.dataset.noteData = JSON.stringify(note, null, 2);
                
                row.querySelector('.copy-btn').disabled = false;
                row.querySelector('.download-btn').disabled = false;
                outputIndex++;
            });
            
            // Step 6: Submit transaction to Soroban
            setLoadingText('Submitting transaction...');
            const submitResult = await submitDeposit(proofResult, {
                publicKey: App.state.wallet.address,
                signTransaction: signWalletTransaction,
                signAuthEntry: signWalletAuthEntry,
            });
            
            if (!submitResult.success) {
                throw new Error(`Transaction failed: ${submitResult.error}`);
            }
            
            console.log('[Deposit] Transaction submitted:', submitResult.txHash);
            
            // Handle warning case (transaction submitted but result parsing failed)
            if (submitResult.warning) {
                console.warn('[Deposit] Warning:', submitResult.warning);
            }
            
            // Now that transaction succeeded, save the notes
            pendingNotes.forEach(note => App.state.notes.push(note));
            Storage.save();
            NotesTable.render();
            
            // Sync pool state to update local merkle tree with new commitments
            // This enables withdrawal of the just-deposited notes
            try {
                setLoadingText('Syncing pool state...');
                await StateManager.startSync({ forceRefresh: true });
                await StateManager.rebuildPoolTree();
                console.log('[Deposit] Pool state synced and tree rebuilt');
            } catch (syncError) {
                console.warn('[Deposit] Pool sync failed:', syncError);
                // Not fatal - user can manually sync later
            }
            
            // Show appropriate message based on whether we have a real tx hash
            const txDisplay = submitResult.txHash?.startsWith('submitted') || submitResult.txHash?.startsWith('pending')
                ? 'Check Stellar Expert for status'
                : `Tx: ${submitResult.txHash?.slice(0, 8)}...`;
            Toast.show(`Deposited ${totalAmount} XLM! ${txDisplay}`, 'success');
        } catch (e) {
            console.error('[Deposit] Error:', e);
            const proofFailureMessage = getProofFailureToastMessage(e);
            Toast.show(proofFailureMessage || ('Deposit failed: ' + getErrorMessage(e)), 'error');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
};

// Withdraw Module
const Withdraw = {
    inputCount: 1,
    
    init() {
        const inputs = document.getElementById('withdraw-inputs');
        const btn = document.getElementById('btn-withdraw');
        const addBtn = document.getElementById('withdraw-add-input');
        const recipientInput = document.getElementById('withdraw-recipient');
        
        // Start with 1 input row (dummy will be auto-added for second slot)
        inputs.appendChild(Templates.createInputRow(0));
        this.inputCount = 1;
        
        // Pre-fill recipient with wallet address if already connected
        if (App.state.wallet.connected && App.state.wallet.address) {
            recipientInput.value = App.state.wallet.address;
        }
        
        // Show "add another note" button
        addBtn.classList.remove('hidden');
        
        // Add second input when button clicked
        addBtn.addEventListener('click', () => {
            if (this.inputCount < 2) {
                inputs.appendChild(Templates.createInputRow(1));
                this.inputCount = 2;
                addBtn.classList.add('hidden'); // Max 2 inputs
                this.updateTotal();
            }
        });
        
        // Update total on input change
        inputs.addEventListener('input', () => this.updateTotal());
        
        btn.addEventListener('click', () => this.submit());
    },
    
    /**
     * Pre-fills the recipient address with the connected wallet address.
     * Called when the wallet connects.
     */
    prefillRecipient() {
        const recipientInput = document.getElementById('withdraw-recipient');
        if (recipientInput && !recipientInput.value && App.state.wallet.address) {
            recipientInput.value = App.state.wallet.address;
        }
    },
    
    updateTotal() {
        let totalStroops = 0n;
        document.querySelectorAll('#withdraw-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const note = App.state.notes.find(n => n.id === noteId && !n.spent);
            if (note) {
                // Handle both old notes (XLM) and new notes (stroops)
                // If amount < 1000, it's likely XLM and needs conversion
                const amountStroops = note.amount < 1000 
                    ? BigInt(Math.round(note.amount * 1e7))
                    : BigInt(note.amount);
                totalStroops += amountStroops;
            }
        });
        // Display in XLM
        const totalXLM = Number(totalStroops) / 1e7;
        document.getElementById('withdraw-total').textContent = `${totalXLM.toFixed(7).replace(/\.?0+$/, '')} XLM`;
        return totalStroops; // Return stroops for calculations
    },
    
    async submit() {
        if (!App.state.wallet.connected) {
            Toast.show('Please connect your wallet first', 'error');
            return;
        }
        
        const totalStroops = this.updateTotal();
        if (totalStroops === 0n) {
            Toast.show('Please enter at least one note with value > 0', 'error');
            return;
        }
        
        const recipient = document.getElementById('withdraw-recipient').value.trim();
        if (!recipient) {
            Toast.show('Please enter a recipient address', 'error');
            return;
        }
        
        const btn = document.getElementById('btn-withdraw');
        const btnText = btn.querySelector('.btn-text');
        const btnLoading = btn.querySelector('.btn-loading');
        btn.disabled = true;
        btnText.classList.add('hidden');
        btnLoading.classList.remove('hidden');
        
        const setLoadingText = (text) => {
            btnLoading.querySelector('span')?.remove();
            const span = document.createElement('span');
            span.textContent = text;
            btnLoading.appendChild(span);
        };
        
        try {
            // Step 1: Derive keys from wallet signatures
            const { privKeyBytes, pubKeyBytes, encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: setLoadingText,
                signDelay: 500,
            });
            
            // Step 2: Sync pool state to ensure we have latest data
            setLoadingText('Syncing pool state...');
            try {
                // Force refresh to bypass cached cursor and get latest events
                await StateManager.startSync({ privateKey: privKeyBytes, forceRefresh: true });
                // Force rebuild tree from DB to ensure it matches synced data
                await StateManager.rebuildPoolTree();
                console.log('[Withdraw] Pool state synced and tree rebuilt');
            } catch (syncError) {
                console.warn('[Withdraw] Sync warning:', syncError.message);
                // Continue even if sync has issues - we'll validate roots later
            }
            
            // Step 3: Collect input notes with merkle proofs
            setLoadingText('Gathering input notes...');
            const inputNotes = [];
            let totalInputAmount = 0n;
            
            const noteInputs = document.querySelectorAll('#withdraw-inputs .note-input');
            for (const input of noteInputs) {
                const noteId = input.value.trim();
                if (!noteId) continue;
                
                const note = App.state.notes.find(n => n.id === noteId && !n.spent);
                if (!note) continue;
                
                // Get merkle proof from pool store (async - builds tree with correct zeros)
                const merkleProof = await poolStore.getMerkleProof(note.leafIndex);
                if (!merkleProof) {
                    throw new Error(`Cannot find merkle proof for note at index ${note.leafIndex}. Pool state may be out of sync.`);
                }
                
                // Handle both old notes (XLM) and new notes (stroops)
                // If amount < 1000, it's likely XLM and needs conversion
                const amountStroops = note.amount < 1000 
                    ? BigInt(Math.round(note.amount * 1e7))
                    : BigInt(note.amount);
                
                inputNotes.push({
                    ...note,
                    amount: amountStroops, // Override with stroops amount for circuit
                    merkleProof,
                });
                totalInputAmount += amountStroops;
            }
            
            if (inputNotes.length === 0) {
                throw new Error('No valid input notes found');
            }
            
            // totalStroops is already in stroops from updateTotal()
            const withdrawAmount = totalStroops;
            
            // Step 4: Get ASP membership blinding
            const membershipBlindingInput = document.getElementById('withdraw-membership-blinding');
            const membershipBlinding = membershipBlindingInput ? BigInt(membershipBlindingInput.value || '0') : 0n;
            console.log('[Withdraw] Using membership blinding:', membershipBlinding.toString());
            
            // Step 5: Get on-chain roots
            setLoadingText('Fetching on-chain state...');
            const states = await readAllContractStates();
            // Pool uses merkleRoot, ASP contracts use root
            // Values already have 0x prefix from formatU256
            const poolRoot = BigInt(states.pool.merkleRoot || '0x0');
            const membershipRoot = BigInt(states.aspMembership.root || '0x0');
            const nonMembershipRoot = BigInt(states.aspNonMembership.root || '0x0');
            
            console.log('[Withdraw] On-chain roots:', {
                pool: states.pool.merkleRoot,
                membership: states.aspMembership.root,
                nonMembership: states.aspNonMembership.root || '0',
            });
            
            // Verify local pool tree is synced with on-chain state
            const localPoolRootLE = poolStore.getRoot();
            const localLeafCount = poolStore.getNextIndex();
            const dbLeafCount = await poolStore.getLeafCount();
            const onChainLeafCount = states.pool.merkleNextIndex || 0;
            console.log('[Withdraw] Local pool state:', {
                treeLeafCount: localLeafCount,
                dbLeafCount: dbLeafCount,
                onChainNextIndex: onChainLeafCount,
            });
            
            if (localPoolRootLE) {
                // Tree returns LE bytes, convert to BE BigInt for comparison with on-chain (BE)
                // Read bytes in reverse order (LE to BE conversion)
                let localRootBigInt = 0n;
                for (let i = 0; i < localPoolRootLE.length; i++) {
                    localRootBigInt = (localRootBigInt << 8n) | BigInt(localPoolRootLE[localPoolRootLE.length - 1 - i]);
                }
                console.log('[Withdraw] Local pool root (BE):', localRootBigInt.toString(16));
                console.log('[Withdraw] On-chain pool root:', poolRoot.toString(16));
                if (localRootBigInt !== poolRoot) {
                    console.error('[Withdraw] Pool root mismatch! Local tree out of sync.');
                    console.error('  Local:    ', localRootBigInt.toString(16));
                    console.error('  On-chain: ', poolRoot.toString(16));
                    console.error('  Local has', localLeafCount, 'leaves, on-chain has', onChainLeafCount);
                    throw new Error(`Pool state out of sync. Local: ${localLeafCount} leaves, On-chain: ${onChainLeafCount} leaves. Try clearing data and refreshing.`);
                }
                console.log('[Withdraw] Pool roots match - local tree is synced');
            }
            
            // Step 6: Generate proof
            setLoadingText('Generating ZK proof...');
            const proofResult = await generateWithdrawProof({
                privKeyBytes,
                encryptionPubKey: encryptionKeypair.publicKey,
                poolRoot,
                membershipRoot,
                nonMembershipRoot,
                inputNotes,
                recipient,
                withdrawAmount,
                stateManager: StateManager,
                membershipBlinding,
            }, {
                onProgress: ({ phase, message }) => {
                    if (message) setLoadingText(message);
                },
            });
            
            console.log('[Withdraw] Proof generated');
            
            // Step 7: Submit transaction
            setLoadingText('Submitting transaction...');
            const submitResult = await submitPoolTransaction({
                proof: proofResult.sorobanProof,
                extData: proofResult.extData,
                sender: App.state.wallet.address,
                signerOptions: {
                    publicKey: App.state.wallet.address,
                    signTransaction: signWalletTransaction,
                    signAuthEntry: signWalletAuthEntry,
                },
            });
            
            if (!submitResult.success) {
                throw new Error(`Transaction failed: ${submitResult.error}`);
            }
            
            console.log('[Withdraw] Transaction submitted:', submitResult.txHash);
            
            // Step 8: Mark input notes as spent (only after success)
            inputNotes.forEach(inputNote => {
                const note = App.state.notes.find(n => n.id === inputNote.id);
                if (note) note.spent = true;
            });
            
            Storage.save();
            NotesTable.render();
            
            // Sync pool state to update local merkle tree
            try {
                setLoadingText('Syncing pool state...');
                await StateManager.startSync({ forceRefresh: true });
                await StateManager.rebuildPoolTree();
                console.log('[Withdraw] Pool state synced and tree rebuilt');
            } catch (syncError) {
                console.warn('[Withdraw] Pool sync failed:', syncError);
            }
            
            // withdrawAmount is in stroops, convert to XLM for display
            const withdrawXLM = Number(withdrawAmount) / 1e7;
            Toast.show(`Withdrew ${withdrawXLM} XLM! Tx: ${submitResult.txHash?.slice(0, 8)}...`, 'success');
            
            // Clear form
            document.querySelectorAll('#withdraw-inputs .note-input').forEach(i => { i.value = ''; });
            document.querySelectorAll('#withdraw-inputs .value-display').forEach(d => {
                d.textContent = '0 XLM';
                d.classList.add('text-dark-500');
                d.classList.remove('text-brand-400');
            });
            document.getElementById('withdraw-recipient').value = '';
            this.updateTotal();
        } catch (e) {
            console.error('[Withdraw] Error:', e);
            const proofFailureMessage = getProofFailureToastMessage(e);
            Toast.show(proofFailureMessage || ('Withdrawal failed: ' + getErrorMessage(e)), 'error');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
};

// Transact Module
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
        
        // Pre-fill withdrawal recipient with wallet address if already connected
        if (App.state.wallet.connected && App.state.wallet.address) {
            const recipientInput = document.getElementById('transact-recipient');
            if (recipientInput) recipientInput.value = App.state.wallet.address;
        }
        
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
    
    /**
     * Pre-fills the withdrawal recipient address with the connected wallet address.
     * Called when the wallet connects.
     */
    prefillRecipient() {
        const recipientInput = document.getElementById('transact-recipient');
        if (recipientInput && !recipientInput.value && App.state.wallet.address) {
            recipientInput.value = App.state.wallet.address;
        }
    },
    
    updateBalance() {
        // Calculate inputs total in XLM (note.amount is in stroops)
        let inputsTotalStroops = 0;
        document.querySelectorAll('#transact-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const note = App.state.notes.find(n => n.id === noteId && !n.spent);
            if (note) inputsTotalStroops += Number(note.amount);
        });
        const inputsTotal = inputsTotalStroops / 1e7; // Convert to XLM
        
        const publicAmount = parseFloat(document.getElementById('transact-amount').value) || 0;
        
        let outputsTotal = 0;
        document.querySelectorAll('#transact-outputs .output-amount').forEach(input => {
            outputsTotal += parseFloat(input.value) || 0;
        });
        
        const eq = document.getElementById('transact-balance');
        eq.querySelector('[data-eq="inputs"]').textContent = `Inputs: ${inputsTotal.toFixed(7).replace(/\.?0+$/, '')}`;
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
        const btnText = btn.querySelector('.btn-text');
        const btnLoading = btn.querySelector('.btn-loading');
        btn.disabled = true;
        btnText.classList.add('hidden');
        btnLoading.classList.remove('hidden');
        
        const setLoadingText = (text) => {
            btnLoading.querySelector('span')?.remove();
            const span = document.createElement('span');
            span.textContent = text;
            btnLoading.appendChild(span);
        };
        
        try {
            // Step 1: Derive keys from wallet signatures
            const { privKeyBytes, pubKeyBytes, encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: setLoadingText,
                signDelay: 500,
            });
            
            // Step 2: Collect parameters
            const publicAmount = parseFloat(document.getElementById('transact-amount').value) || 0;
            const publicAmountStroops = BigInt(Math.round(publicAmount * 1e7));
            const outputRecipient = document.getElementById('transact-outputs-recipient')?.value.trim();
            const isForSelf = !outputRecipient || outputRecipient === App.state.wallet.address;
            
            // Step 3: Collect input notes with merkle proofs
            setLoadingText('Gathering input notes...');
            const inputNotes = [];
            
            const transactNoteInputs = document.querySelectorAll('#transact-inputs .note-input');
            for (const input of transactNoteInputs) {
                const noteId = input.value.trim();
                if (!noteId) continue;
                
                const note = App.state.notes.find(n => n.id === noteId && !n.spent);
                if (!note) continue;
                
                const merkleProof = await poolStore.getMerkleProof(note.leafIndex);
                if (!merkleProof) {
                    throw new Error(`Cannot find merkle proof for note at index ${note.leafIndex}`);
                }
                
                inputNotes.push({
                    ...note,
                    merkleProof,
                });
            }
            
            // Step 4: Collect outputs
            const outputs = [];
            document.querySelectorAll('#transact-outputs .output-row').forEach(row => {
                const amount = parseFloat(row.querySelector('.output-amount').value) || 0;
                const blindingBytes = generateBlinding();
                const blinding = BigInt('0x' + fieldToHex(blindingBytes).slice(2));
                outputs.push({
                    amount: BigInt(Math.round(amount * 1e7)),
                    blinding,
                });
            });
            
            // Step 5: Get ASP membership blinding
            const membershipBlindingInput = document.getElementById('transact-membership-blinding');
            const membershipBlinding = membershipBlindingInput ? BigInt(membershipBlindingInput.value || '0') : 0n;
            console.log('[Transact] Using membership blinding:', membershipBlinding.toString());
            
            // Step 6: Get on-chain roots and pool address
            setLoadingText('Fetching on-chain state...');
            const states = await readAllContractStates();
            const contracts = getDeployedContracts();
            const poolRoot = BigInt(states.pool.merkleRoot || '0x0');
            const membershipRoot = BigInt(states.aspMembership.root || '0x0');
            const nonMembershipRoot = BigInt(states.aspNonMembership.root || '0x0');
            
            // Determine recipient based on transaction type
            let recipient;
            if (publicAmountStroops > 0n) {
                // Deposit: recipient is pool
                recipient = contracts.pool;
            } else if (publicAmountStroops < 0n) {
                // Withdrawal: recipient is external address
                const withdrawRecipient = document.getElementById('transact-recipient')?.value.trim();
                recipient = withdrawRecipient || App.state.wallet.address;
            } else {
                // Transfer: recipient is pool
                recipient = contracts.pool;
            }
            
            console.log('[Transact] Transaction parameters:', {
                publicAmount,
                inputCount: inputNotes.length,
                outputCount: outputs.length,
                recipient,
            });
            
            // Step 7: Generate proof using the generic transaction function
            setLoadingText('Generating ZK proof...');
            const { generateTransactionProof } = await import('./transaction-builder.js');
            
            const proofResult = await generateTransactionProof({
                privKeyBytes,
                encryptionPubKey: encryptionKeypair.publicKey,
                poolRoot,
                membershipRoot,
                nonMembershipRoot,
                inputs: inputNotes,
                outputs,
                extData: {
                    recipient,
                    ext_amount: publicAmountStroops,
                },
                stateManager: StateManager,
                membershipBlinding,
            }, {
                onProgress: ({ phase, message }) => {
                    if (message) setLoadingText(message);
                },
            });
            
            console.log('[Transact] Proof generated');
            
            // Step 8: Update UI with generated output notes
            // Get the pool's next leaf index so we can track where our commitments will be
            // Convert to Number since it may come as BigInt from contract
            const poolNextIndex = Number(states.pool.merkleNextIndex || 0);
            
            const pendingNotes = [];
            let outputIndex = 0;
            document.querySelectorAll('#transact-outputs .output-row').forEach(row => {
                const outputNote = proofResult.outputNotes[outputIndex];
                const amountXLM = parseFloat(row.querySelector('.output-amount').value) || 0;
                const isDummy = amountXLM === 0;
                
                const noteId = fieldToHex(outputNote.commitmentBytes);
                const leafIndex = poolNextIndex + outputIndex;
                
                // Store in stroops to match the commitment
                const amountStroops = Number(outputNote.amount);
                
                const note = {
                    id: noteId,
                    commitment: noteId,
                    amount: amountStroops,
                    blinding: outputNote.blinding.toString(),
                    leafIndex,
                    spent: false,
                    isDummy,
                    owner: outputRecipient || App.state.wallet.address,
                    createdAt: new Date().toISOString()
                };
                
                // Only store locally if for self
                if (!isDummy && isForSelf) pendingNotes.push(note);
                
                const display = row.querySelector('.output-note-id');
                display.value = Utils.truncateHex(noteId, 8, 8);
                display.dataset.fullId = noteId;
                display.dataset.noteData = JSON.stringify(note, null, 2);
                
                row.querySelector('.copy-btn').disabled = false;
                row.querySelector('.download-btn').disabled = false;
                outputIndex++;
            });
            
            // Step 9: Submit transaction
            setLoadingText('Submitting transaction...');
            const submitResult = await submitPoolTransaction({
                proof: proofResult.sorobanProof,
                extData: proofResult.extData,
                sender: App.state.wallet.address,
                signerOptions: {
                    publicKey: App.state.wallet.address,
                    signTransaction: signWalletTransaction,
                    signAuthEntry: signWalletAuthEntry,
                },
            });
            
            if (!submitResult.success) {
                throw new Error(`Transaction failed: ${submitResult.error}`);
            }
            
            console.log('[Transact] Transaction submitted:', submitResult.txHash);
            
            // Step 10: Save notes and mark inputs as spent (only after success)
            pendingNotes.forEach(note => App.state.notes.push(note));
            
            inputNotes.forEach(inputNote => {
                const note = App.state.notes.find(n => n.id === inputNote.id);
                if (note) note.spent = true;
            });
            
            Storage.save();
            NotesTable.render();
            
            // Sync pool state to update local merkle tree
            try {
                setLoadingText('Syncing pool state...');
                await StateManager.startSync({ forceRefresh: true });
                await StateManager.rebuildPoolTree();
                console.log('[Transact] Pool state synced and tree rebuilt');
            } catch (syncError) {
                console.warn('[Transact] Pool sync failed:', syncError);
            }
            
            if (isForSelf) {
                Toast.show(`Transaction successful! Tx: ${submitResult.txHash?.slice(0, 8)}...`, 'success');
            } else {
                Toast.show('Transaction successful! Share note files with recipient.', 'success');
            }
        } catch (e) {
            console.error('[Transact] Error:', e);
            const proofFailureMessage = getProofFailureToastMessage(e);
            Toast.show(proofFailureMessage || ('Transaction failed: ' + getErrorMessage(e)), 'error');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
};

// Notes Table
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

// Transfer Module
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
        // Calculate inputs total in XLM (note.amount is in stroops)
        let inputsTotalStroops = 0;
        document.querySelectorAll('#transfer-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const note = App.state.notes.find(n => n.id === noteId && !n.spent);
            if (note) inputsTotalStroops += Number(note.amount);
        });
        const inputsTotal = inputsTotalStroops / 1e7; // Convert to XLM
        
        let outputsTotal = 0;
        document.querySelectorAll('#transfer-outputs .output-amount').forEach(input => {
            outputsTotal += parseFloat(input.value) || 0;
        });
        
        const eq = document.getElementById('transfer-balance');
        eq.querySelector('[data-eq="inputs"]').textContent = `Inputs: ${inputsTotal.toFixed(7).replace(/\.?0+$/, '')}`;
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
        const btnText = btn.querySelector('.btn-text');
        const btnLoading = btn.querySelector('.btn-loading');
        btn.disabled = true;
        btnText.classList.add('hidden');
        btnLoading.classList.remove('hidden');
        
        const setLoadingText = (text) => {
            btnLoading.querySelector('span')?.remove();
            const span = document.createElement('span');
            span.textContent = text;
            btnLoading.appendChild(span);
        };
        
        try {
            // Step 1: Derive keys from wallet signatures
            const { privKeyBytes, pubKeyBytes, encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: setLoadingText,
                signDelay: 500,
            });
            
            // Step 2: Parse recipient public key (hex string to bytes)
            let recipientPubKeyBytes;
            try {
                const cleanHex = recipientKey.startsWith('0x') ? recipientKey.slice(2) : recipientKey;
                recipientPubKeyBytes = new Uint8Array(cleanHex.match(/.{2}/g).map(b => parseInt(b, 16)));
                if (recipientPubKeyBytes.length !== 32) {
                    throw new Error('Invalid length');
                }
            } catch {
                throw new Error('Invalid recipient public key format. Expected 64 hex characters.');
            }
            
            // Step 3: Collect input notes with merkle proofs
            setLoadingText('Gathering input notes...');
            const inputNotes = [];
            
            const transferNoteInputs = document.querySelectorAll('#transfer-inputs .note-input');
            for (const input of transferNoteInputs) {
                const noteId = input.value.trim();
                if (!noteId) continue;
                
                const note = App.state.notes.find(n => n.id === noteId && !n.spent);
                if (!note) continue;
                
                const merkleProof = await poolStore.getMerkleProof(note.leafIndex);
                if (!merkleProof) {
                    throw new Error(`Cannot find merkle proof for note at index ${note.leafIndex}`);
                }
                
                inputNotes.push({
                    ...note,
                    merkleProof,
                });
            }
            
            if (inputNotes.length === 0) {
                throw new Error('No valid input notes found');
            }
            
            // Step 4: Collect output amounts
            const recipientOutputs = [];
            document.querySelectorAll('#transfer-outputs .output-row').forEach(row => {
                const amount = parseFloat(row.querySelector('.output-amount').value) || 0;
                if (amount > 0) {
                    const blindingBytes = generateBlinding();
                    const blinding = BigInt('0x' + fieldToHex(blindingBytes).slice(2));
                    recipientOutputs.push({
                        amount: BigInt(Math.round(amount * 1e7)),
                        blinding,
                    });
                }
            });
            
            // Step 5: Get ASP membership blinding
            const membershipBlindingInput = document.getElementById('transfer-membership-blinding');
            const membershipBlinding = membershipBlindingInput ? BigInt(membershipBlindingInput.value || '0') : 0n;
            console.log('[Transfer] Using membership blinding:', membershipBlinding.toString());
            
            // Step 6: Get on-chain roots and pool address
            setLoadingText('Fetching on-chain state...');
            const states = await readAllContractStates();
            const contracts = getDeployedContracts();
            // Pool uses merkleRoot, ASP contracts use root
            // Values already have 0x prefix from formatU256
            const poolRoot = BigInt(states.pool.merkleRoot || '0x0');
            const membershipRoot = BigInt(states.aspMembership.root || '0x0');
            const nonMembershipRoot = BigInt(states.aspNonMembership.root || '0x0');
            
            console.log('[Transfer] On-chain roots:', {
                pool: states.pool.merkleRoot,
                membership: states.aspMembership.root,
                nonMembership: states.aspNonMembership.root || '0',
            });
            
            // Step 7: Generate proof
            setLoadingText('Generating ZK proof...');
            const proofResult = await generateTransferProof({
                privKeyBytes,
                encryptionPubKey: encryptionKeypair.publicKey,
                recipientPubKey: recipientPubKeyBytes,
                recipientEncryptionPubKey: recipientPubKeyBytes, // For now, use same key
                poolRoot,
                membershipRoot,
                nonMembershipRoot,
                inputNotes,
                recipientOutputs,
                poolAddress: contracts.pool,
                stateManager: StateManager,
                membershipBlinding,
            }, {
                onProgress: ({ phase, message }) => {
                    if (message) setLoadingText(message);
                },
            });
            
            console.log('[Transfer] Proof generated');
            
            // Step 8: Update UI with generated output notes
            let outputIndex = 0;
            document.querySelectorAll('#transfer-outputs .output-row').forEach(row => {
                const outputNote = proofResult.outputNotes[outputIndex];
                const amountXLM = parseFloat(row.querySelector('.output-amount').value) || 0;
                const isDummy = amountXLM === 0;
                
                const noteId = fieldToHex(outputNote.commitmentBytes);
                // Store in stroops to match the commitment
                const amountStroops = Number(outputNote.amount);
                
                const note = {
                    id: noteId,
                    commitment: noteId,
                    amount: amountStroops,
                    blinding: outputNote.blinding.toString(),
                    spent: false,
                    isDummy,
                    owner: recipientKey,
                    createdAt: new Date().toISOString()
                };
                
                const display = row.querySelector('.output-note-id');
                display.value = Utils.truncateHex(noteId, 8, 8);
                display.dataset.fullId = noteId;
                display.dataset.noteData = JSON.stringify(note, null, 2);
                
                row.querySelector('.copy-btn').disabled = false;
                row.querySelector('.download-btn').disabled = false;
                outputIndex++;
            });
            
            // Step 9: Submit transaction
            setLoadingText('Submitting transaction...');
            const submitResult = await submitPoolTransaction({
                proof: proofResult.sorobanProof,
                extData: proofResult.extData,
                sender: App.state.wallet.address,
                signerOptions: {
                    publicKey: App.state.wallet.address,
                    signTransaction: signWalletTransaction,
                    signAuthEntry: signWalletAuthEntry,
                },
            });
            
            if (!submitResult.success) {
                throw new Error(`Transaction failed: ${submitResult.error}`);
            }
            
            console.log('[Transfer] Transaction submitted:', submitResult.txHash);
            
            // Step 10: Mark input notes as spent (only after success)
            inputNotes.forEach(inputNote => {
                const note = App.state.notes.find(n => n.id === inputNote.id);
                if (note) note.spent = true;
            });
            
            Storage.save();
            NotesTable.render();
            Toast.show('Transfer successful! Share the note files with the recipient.', 'success');
        } catch (e) {
            console.error('[Transfer] Error:', e);
            const proofFailureMessage = getProofFailureToastMessage(e);
            Toast.show(proofFailureMessage || ('Transfer failed: ' + getErrorMessage(e)), 'error');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
};

// Reads on-chain state from deployed Pool, ASP Membership, ASP Non-Membership contracts
/**
 * Handles fetching and displaying recent pool events.
 */
const PoolEventsFetcher = {
    isLoading: false,
    events: [],
    maxEvents: 3,
    
    /**
     * Initialize event fetching with auto-refresh.
     */
    init() {
        this.refresh();
        this.refreshIntervalId = setInterval(() => this.refresh(), 30000);
    },

    destroy() {
        if (this.refreshIntervalId) {
            clearInterval(this.refreshIntervalId);
            this.refreshIntervalId = null;
        }
    },
    /**
     * Fetch recent pool events from the contract.
     */
    async refresh() {
        if (this.isLoading) return;
        
        this.isLoading = true;
        this.showLoading();
        
        try {
            const result = await getPoolEvents(this.maxEvents);
            
            if (result.success && result.events.length > 0) {
                this.events = result.events.slice(0, this.maxEvents);
                this.displayEvents();
                this.setStatus('success');
            } else if (result.success) {
                this.events = [];
                this.showEmpty();
                this.setStatus('success', 'No events');
            } else {
                this.setStatus('error', result.error || 'Failed');
                this.showEmpty();
            }
        } catch (err) {
            console.error('[PoolEventsFetcher] Error:', err);
            this.setStatus('error', 'Error');
            this.showEmpty();
        } finally {
            this.isLoading = false;
        }
    },
    
    /**
     * Render the events list in the UI.
     * Groups events by ledger to show one entry per transaction.
     */
    displayEvents() {
        const container = document.getElementById('recent-tx');
        const emptyEl = document.getElementById('recent-tx-empty');
        const loadingEl = document.getElementById('recent-tx-loading');
        const template = document.getElementById('tpl-tx-item');
        
        loadingEl.classList.add('hidden');
        
        if (!this.events.length) {
            this.showEmpty();
            return;
        }
        
        emptyEl.classList.add('hidden');
        container.innerHTML = '';
        
        // Group events by ledger to show one entry per transaction
        const byLedger = new Map();
        for (const event of this.events) {
            const ledger = event.ledger;
            if (!byLedger.has(ledger)) {
                byLedger.set(ledger, { ledger, nullifiers: 0, commitments: 0, events: [] });
            }
            const group = byLedger.get(ledger);
            group.events.push(event);
            
            const topic = event.topic?.[0] || '';
            if (topic.includes('nullif')) group.nullifiers++;
            if (topic.includes('commit')) group.commitments++;
        }
        
        // Display grouped transactions (max 3)
        const groups = Array.from(byLedger.values()).slice(0, this.maxEvents);
        
        for (const group of groups) {
            const clone = template.content.cloneNode(true);
            const li = clone.querySelector('li');
            
            // Determine transaction type based on events
            let txType = 'Transaction';
            if (group.nullifiers === 2 && group.commitments === 2) {
                txType = 'Pool Activity';
            } else if (group.commitments > 0) {
                txType = `+${group.commitments} notes`;
            }
            
            li.querySelector('.tx-hash').textContent = txType;
            li.querySelector('.tx-hash').title = `Ledger ${group.ledger}: ${group.nullifiers} nullifiers, ${group.commitments} commitments`;
            li.querySelector('.tx-time').textContent = `L${group.ledger}`;
            
            container.appendChild(clone);
        }
    },
    
    /**
     * Show the empty state message.
     * For when there are no recent transactions
     */
    showEmpty() {
        const container = document.getElementById('recent-tx');
        const emptyEl = document.getElementById('recent-tx-empty');
        const loadingEl = document.getElementById('recent-tx-loading');
        
        container.innerHTML = '';
        loadingEl.classList.add('hidden');
        emptyEl.classList.remove('hidden');
    },
    
    /**
     * Show loading indicator.
     */
    showLoading() {
        const container = document.getElementById('recent-tx');
        const emptyEl = document.getElementById('recent-tx-empty');
        const loadingEl = document.getElementById('recent-tx-loading');
        
        container.innerHTML = '';
        emptyEl.classList.add('hidden');
        loadingEl.classList.remove('hidden');
    },
    
    /**
     * @param {string} status - 'success', 'error', or default
     * @param {string} text - Optional display text
     */
    setStatus(status, text = '') {
        const el = document.getElementById('recent-tx-status');
        if (!el) return;
        
        switch (status) {
            case 'success':
                el.textContent = text || 'Updated';
                el.className = 'text-[10px] text-emerald-500';
                break;
            case 'error':
                el.textContent = text || 'Error';
                el.className = 'text-[10px] text-red-500';
                break;
            default:
                el.textContent = '—';
                el.className = 'text-[10px] text-dark-500';
        }
    },
    
    /**
     * Format event ID or topic for display.
     * @param {Object} event - Pool event object
     * @returns {string} Formatted hash display
     */
    formatEventHash(event) {
        const topic = event.topic?.[0] || '';
        const prefix = typeof topic === 'string' ? topic.slice(0, 10) : 'Event';
        
        if (event.id) {
            const parts = event.id.split('-');
            const shortId = parts.length > 1 ? parts[1].slice(0, 6) : event.id.slice(0, 8);
            return `${prefix}...${shortId}`;
        }
        return `${prefix}...`;
    },
    
    /**
     * Format event timestamp for display.
     * @param {Object} event - Pool event object
     * @returns {string} Relative time string
     */
    formatEventTime(event) {
        if (event.ledger) {
            return `L${event.ledger}`;
        }
        return '--';
    }
};

const ContractReader = {
    isLoading: false,
    lastUpdate: null,
    refreshIntervalId: null,

    init() {
        const refreshBtn = document.getElementById('btn-refresh-state');
        refreshBtn.addEventListener('click', () => this.refreshAll());
        
        const forceResyncBtn = document.getElementById('btn-force-resync');
        if (forceResyncBtn) {
            forceResyncBtn.addEventListener('click', () => SyncUI.forceResync());
        }

        this.setAddresses();
        document.getElementById('network-name').textContent = 'Testnet';
        document.getElementById('chain-network-badge').textContent = 'Testnet';

        this.refreshAll();
        this.refreshIntervalId = setInterval(() => this.refreshAll(), 30000);
    },

    /**
     * Stop auto-refresh. Call when component is unmounted or on critical errors.
     */
    destroy() {
        if (this.refreshIntervalId) {
            clearInterval(this.refreshIntervalId);
            this.refreshIntervalId = null;
        }
    },
    
    setAddresses() {
        const contracts = getDeployedContracts();
        if (!contracts) {
            console.warn('[ContractReader] Deployed contracts not loaded yet');
            return;
        }
        
        document.getElementById('pool-address').textContent = formatAddress(contracts.pool, 4, 4);
        document.getElementById('pool-address').title = contracts.pool;
        
        document.getElementById('membership-address').textContent = formatAddress(contracts.aspMembership, 4, 4);
        document.getElementById('membership-address').title = contracts.aspMembership;
        
        document.getElementById('nonmembership-address').textContent = formatAddress(contracts.aspNonMembership, 4, 4);
        document.getElementById('nonmembership-address').title = contracts.aspNonMembership;
    },
    
    async refreshAll() {
        if (this.isLoading) return;
        
        this.isLoading = true;
        const refreshBtn = document.getElementById('btn-refresh-state');
        const refreshIcon = refreshBtn.querySelector('.refresh-icon');
        const errorDisplay = document.getElementById('contract-error-display');
        
        refreshIcon.classList.add('animate-spin');
        errorDisplay.classList.add('hidden');
        
        this.setStatus('pool-status', 'loading');
        this.setStatus('membership-status', 'loading');
        this.setStatus('nonmembership-status', 'loading');
        
        try {
            const result = await readAllContractStates();
            
            if (result.success) {
                this.displayPoolState(result.pool);
                this.displayMembershipState(result.aspMembership);
                this.displayNonMembershipState(result.aspNonMembership);
                
                this.lastUpdate = new Date();
                document.getElementById('state-last-updated').textContent = 
                    `Last updated: ${this.lastUpdate.toLocaleTimeString()}`;
            } else {
                this.displayError(result.error);
            }
        } catch (err) {
            console.error('[ContractReader] Error:', err);
            this.displayError(err.message);

            // Stop polling after 5 consecutive failures
            this.errorCount = (this.errorCount || 0) + 1;
            if (this.errorCount >= 5) {
                console.warn('[ContractReader] Too many failures, stopping auto-refresh');
                this.destroy();
            }
        } finally {
            this.isLoading = false;
            refreshIcon.classList.remove('animate-spin');
        }
    },
    
    displayPoolState(state) {
        if (!state || !state.success) {
            this.setStatus('pool-status', 'error', state?.error || 'Failed');
            return;
        }
        
        this.setStatus('pool-status', 'success', 'Connected');
        
        const rootEl = document.getElementById('pool-root');
        if (state.merkleRoot) {
            rootEl.textContent = this.truncateHash(state.merkleRoot);
            rootEl.title = state.merkleRoot;
        } else {
            rootEl.textContent = '—';
        }
        
        const commitmentsEl = document.getElementById('pool-commitments');
        if (state.totalCommitments !== undefined) {
            commitmentsEl.textContent = state.totalCommitments.toLocaleString();
        } else if (state.merkleNextIndex !== undefined) {
            commitmentsEl.textContent = state.merkleNextIndex.toLocaleString();
        } else {
            commitmentsEl.textContent = '0';
        }
        
        const levelsEl = document.getElementById('pool-levels');
        levelsEl.textContent = state.merkleLevels !== undefined ? state.merkleLevels : '—';
        
        // Update total commitments in stats panel
        const totalEl = document.getElementById('pool-total-value');
        if (totalEl) {
            totalEl.textContent = (state.totalCommitments || state.merkleNextIndex || 0).toLocaleString();
        }
    },
    
    displayMembershipState(state) {
        if (!state || !state.success) {
            this.setStatus('membership-status', 'error', state?.error || 'Failed');
            return;
        }
        
        this.setStatus('membership-status', 'success', 'Connected');
        
        const rootEl = document.getElementById('membership-root');
        if (state.root) {
            rootEl.textContent = this.truncateHash(state.root);
            rootEl.title = state.root;
        } else {
            rootEl.textContent = '—';
        }
        
        const countEl = document.getElementById('membership-count');
        if (state.nextIndex !== undefined) {
            countEl.textContent = `${state.nextIndex}${state.capacity ? ` / ${state.capacity.toLocaleString()}` : ''}`;
        } else {
            countEl.textContent = '0';
        }
    },
    
    displayNonMembershipState(state) {
        if (!state || !state.success) {
            this.setStatus('nonmembership-status', 'error', state?.error || 'Failed');
            return;
        }
        
        this.setStatus('nonmembership-status', 'success', 'Connected');
        
        const rootEl = document.getElementById('nonmembership-root');
        if (state.root) {
            rootEl.textContent = this.truncateHash(state.root);
            rootEl.title = state.root;
        } else {
            rootEl.textContent = '0x0...0';
        }
        
        const statusEl = document.getElementById('nonmembership-tree-status');
        if (state.isEmpty) {
            statusEl.textContent = 'Empty tree';
            statusEl.className = 'text-dark-500';
        } else {
            statusEl.textContent = 'Has entries';
            statusEl.className = 'text-emerald-400';
        }
    },
    
    displayError(message) {
        const errorDisplay = document.getElementById('contract-error-display');
        document.getElementById('contract-error-text').textContent = message || 'Failed to read contract state';
        errorDisplay.classList.remove('hidden');
    },
    
    /**
     * @param {string} elementId - DOM element ID for status indicator
     * @param {string} status - 'loading', 'success', 'error', or default
     * @param {string} text - Optional display text
     */
    setStatus(elementId, status, text = '') {
        const el = document.getElementById(elementId);
        if (!el) return;
        
        // Also update the corresponding bullet indicator
        const indicatorId = elementId.replace('-status', '-indicator');
        const indicator = document.getElementById(indicatorId);
        
        switch (status) {
            case 'loading':
                el.textContent = 'Loading...';
                el.className = 'text-[10px] text-dark-400 animate-pulse';
                if (indicator) {
                    indicator.className = 'w-2 h-2 rounded-full bg-dark-400 animate-pulse';
                }
                break;
            case 'success':
                el.textContent = text || 'OK';
                el.className = 'text-[10px] text-emerald-500';
                if (indicator) {
                    indicator.className = 'w-2 h-2 rounded-full bg-emerald-500';
                }
                break;
            case 'error':
                el.textContent = text || 'Error';
                el.className = 'text-[10px] text-red-500';
                if (indicator) {
                    indicator.className = 'w-2 h-2 rounded-full bg-red-500';
                }
                break;
            default:
                el.textContent = text || '—';
                el.className = 'text-[10px] text-dark-500';
                if (indicator) {
                    indicator.className = 'w-2 h-2 rounded-full bg-dark-500';
                }
        }
    },
    
    /**
     * @param {string} hash - Hash string to truncate
     * @returns {string} Truncated hash for display
     */
    truncateHash(hash) {
        if (!hash) return '—';
        if (typeof hash !== 'string') hash = String(hash);
        if (hash.length <= 16) return hash;
        if (hash.startsWith('0x')) {
            return hash.slice(0, 8) + '...' + hash.slice(-6);
        }
        return hash.slice(0, 6) + '...' + hash.slice(-6);
    }
};

// Prover Initialization UI
const ProverUI = {
    statusEl: null,
    progressEl: null,
    isInitializing: false,

    /**
     * Creates the prover status indicator in the UI.
     */
    createStatusIndicator() {
        // Check if already exists
        if (document.getElementById('prover-status')) {
            this.statusEl = document.getElementById('prover-status');
            this.progressEl = document.getElementById('prover-progress');
            return;
        }

        // Create prover status bar (fixed bottom-left)
        const statusBar = document.createElement('div');
        statusBar.id = 'prover-status';
        statusBar.className = 'fixed bottom-4 left-4 bg-dark-800 border border-dark-700 rounded-lg p-3 shadow-lg max-w-xs z-40';
        statusBar.innerHTML = `
            <div class="flex items-center gap-2">
                <div id="prover-spinner" class="w-4 h-4 border-2 border-brand-500 border-t-transparent rounded-full animate-spin"></div>
                <span id="prover-message" class="text-sm text-dark-300">Initializing prover...</span>
            </div>
            <div id="prover-progress" class="mt-2 h-1 bg-dark-700 rounded overflow-hidden">
                <div class="h-full bg-brand-500 transition-all duration-300" style="width: 0%"></div>
            </div>
        `;
        document.body.appendChild(statusBar);

        this.statusEl = statusBar;
        this.progressEl = document.getElementById('prover-progress');
    },

    /**
     * Update the status message.
     * @param {string} message 
     * @param {boolean} showSpinner 
     */
    setMessage(message, showSpinner = true) {
        if (!this.statusEl) return;
        const msgEl = document.getElementById('prover-message');
        const spinnerEl = document.getElementById('prover-spinner');
        if (msgEl) msgEl.textContent = message;
        if (spinnerEl) spinnerEl.classList.toggle('hidden', !showSpinner);
    },

    /**
     * Update the progress bar.
     * @param {number} percent - 0-100
     */
    setProgress(percent) {
        if (!this.progressEl) return;
        const bar = this.progressEl.querySelector('div');
        if (bar) bar.style.width = `${percent}%`;
    },

    /**
     * Show the prover as ready.
     */
    showReady() {
        if (!this.statusEl) return;
        this.setMessage('Prover ready', false);
        this.setProgress(100);
        this.statusEl.classList.add('border-emerald-500/30');
        
        // Hide after delay
        setTimeout(() => {
            if (this.statusEl) {
                this.statusEl.style.opacity = '0';
                this.statusEl.style.transform = 'translateX(-100%)';
                setTimeout(() => {
                    if (this.statusEl) {
                        this.statusEl.classList.add('hidden');
                        this.statusEl.style.opacity = '';
                        this.statusEl.style.transform = '';
                    }
                }, 300);
            }
        }, 2000);
    },

    /**
     * Show an error state.
     * @param {string} error 
     */
    showError(error) {
        if (!this.statusEl) return;
        this.setMessage(`Error: ${error}`, false);
        this.statusEl.classList.add('border-red-500/30');
        const spinnerEl = document.getElementById('prover-spinner');
        if (spinnerEl) spinnerEl.classList.add('hidden');
    },

    /**
     * Initialize the prover in the background.
     * Non-blocking - updates UI with progress.
     */
    async initialize() {
        if (this.isInitializing || ProverClient.isReady()) {
            return;
        }

        this.isInitializing = true;
        this.createStatusIndicator();

        // Register progress listener
        const unsubscribe = ProverClient.onProgress((loaded, total, message, percent) => {
            this.setMessage(message || 'Downloading artifacts...');
            this.setProgress(percent || 0);
        });

        try {
            // Check if cached first
            const cached = await ProverClient.isCached();
            if (cached) {
                this.setMessage('Loading from cache...');
            } else {
                this.setMessage('Downloading proving key...');
            }

            await ProverClient.initializeProver();
            this.showReady();
            console.log('[ProverUI] Prover initialized successfully');
        } catch (e) {
            console.error('[ProverUI] Prover initialization failed:', e);
            this.showError(e.message);
        } finally {
            unsubscribe();
            this.isInitializing = false;
        }
    },

    /**
     * Check if prover is ready.
     * @returns {boolean}
     */
    isReady() {
        return ProverClient.isReady();
    },

    /**
     * Ensure prover is ready, initializing if needed.
     * Shows a toast if initialization is required.
     * @returns {Promise<boolean>}
     */
    async ensureReady() {
        if (ProverClient.isReady()) {
            return true;
        }

        Toast.show('Initializing ZK prover...', 'success');
        await this.initialize();
        return ProverClient.isReady();
    }
};

// Sync Status UI
const SyncUI = {
    statusEl: null,
    messageEl: null,
    progressEl: null,
    warningEl: null,

    init() {
        // Create sync status indicator if not exists
        this.createSyncIndicator();
        
        // Listen to StateManager events
        StateManager.on('syncProgress', (data) => this.onProgress(data));
        StateManager.on('syncComplete', (data) => this.onComplete(data));
        StateManager.on('syncBroken', (data) => this.onBroken(data));
        StateManager.on('retentionDetected', (data) => this.onRetentionDetected(data));
    },

    createSyncIndicator() {
        // Check if sync status element already exists
        if (document.getElementById('sync-status')) {
            this.statusEl = document.getElementById('sync-status');
            this.messageEl = document.getElementById('sync-message');
            this.progressEl = document.getElementById('sync-progress');
            this.warningEl = document.getElementById('sync-warning');
            return;
        }

        // Create sync status bar
        const syncBar = document.createElement('div');
        syncBar.id = 'sync-status';
        syncBar.className = 'fixed bottom-4 right-4 bg-gray-800 border border-gray-700 rounded-lg p-3 shadow-lg max-w-xs z-50 hidden';
        syncBar.innerHTML = `
            <div class="flex items-center gap-2">
                <div id="sync-spinner" class="animate-spin w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full hidden"></div>
                <span id="sync-message" class="text-sm text-gray-300">Syncing...</span>
            </div>
            <div id="sync-progress" class="mt-2 h-1 bg-gray-700 rounded overflow-hidden hidden">
                <div class="h-full bg-emerald-500 transition-all duration-300" style="width: 0%"></div>
            </div>
        `;
        document.body.appendChild(syncBar);

        // Create warning banner
        const warningBanner = document.createElement('div');
        warningBanner.id = 'sync-warning';
        warningBanner.className = 'fixed top-0 left-0 right-0 bg-amber-900/90 border-b border-amber-700 p-3 text-center hidden z-50';
        warningBanner.innerHTML = `
            <div class="flex items-center justify-center gap-2">
                <svg class="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
                <span id="sync-warning-text" class="text-amber-200 text-sm"></span>
                <button id="sync-warning-close" class="ml-4 text-amber-400 hover:text-amber-200">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
        `;
        document.body.appendChild(warningBanner);

        this.statusEl = syncBar;
        this.messageEl = document.getElementById('sync-message');
        this.progressEl = document.getElementById('sync-progress');
        this.warningEl = warningBanner;

        // Warning close button
        document.getElementById('sync-warning-close')?.addEventListener('click', () => {
            this.warningEl.classList.add('hidden');
        });
    },

    show(message, showSpinner = true) {
        if (!this.statusEl) return;
        this.statusEl.classList.remove('hidden');
        this.messageEl.textContent = message;
        const spinner = document.getElementById('sync-spinner');
        if (spinner) {
            spinner.classList.toggle('hidden', !showSpinner);
        }
    },

    hide() {
        if (!this.statusEl) return;
        setTimeout(() => {
            this.statusEl.classList.add('hidden');
        }, 2000);
    },

    setProgress(percent) {
        if (!this.progressEl) return;
        this.progressEl.classList.remove('hidden');
        const bar = this.progressEl.querySelector('div');
        if (bar) bar.style.width = `${percent}%`;
    },

    showWarning(message) {
        if (!this.warningEl) return;
        document.getElementById('sync-warning-text').textContent = message;
        this.warningEl.classList.remove('hidden');
    },

    hideWarning() {
        if (!this.warningEl) return;
        this.warningEl.classList.add('hidden');
    },

    onProgress(data) {
        const messages = {
            pool: 'Syncing pool events...',
            asp_membership: 'Syncing ASP membership...',
            complete: 'Sync complete!',
        };
        this.show(messages[data.phase] || 'Syncing...');
        if (data.progress !== undefined) {
            this.setProgress(data.progress);
        }
    },

    onComplete(data) {
        this.show(`Synced: ${data.poolLeavesCount} pool, ${data.aspMembershipLeavesCount} ASP`, false);
        this.hide();
        this.hideWarning();
        Toast.show('State synchronized successfully', 'success');
    },

    onBroken(data) {
        this.showWarning(data.message);
        Toast.show('Sync gap detected - some notes may be inaccessible', 'error');
    },

    onRetentionDetected(config) {
        console.log(`[SyncUI] RPC retention: ${config.description}`);
    },

    async startSync() {
        this.show('Starting sync...');
        try {
            const status = await StateManager.startSync({
                onProgress: (p) => this.onProgress(p),
                forceRefresh: true, // Always fetch fresh events
            });
            // Rebuild tree to ensure it matches synced data
            await StateManager.rebuildPoolTree();
            if (status.status === 'broken') {
                this.showWarning(status.message);
            }
        } catch (err) {
            console.error('[SyncUI] Sync failed:', err);
            Toast.show('Sync failed: ' + err.message, 'error');
            this.hide();
        }
    },

    async checkGap() {
        const gap = await StateManager.checkSyncGap();
        if (gap.status === 'warning') {
            this.showWarning(gap.message);
        } else if (gap.status === 'broken') {
            this.showWarning(gap.message);
        }
    },

    /**
     * Forces a complete resync by clearing all state and re-fetching from scratch.
     * Use when events are missing or state is corrupted.
     */
    async forceResync() {
        if (!confirm('This will clear all cached state and re-sync from scratch. Continue?')) {
            return;
        }
        
        this.show('Clearing cached state...');
        try {
            await StateManager.clearAll();
            console.log('[SyncUI] State cleared, starting fresh sync...');
            this.show('Re-syncing from scratch...');
            
            const status = await StateManager.startSync({
                onProgress: (p) => this.onProgress(p),
                forceRefresh: true, // Ensure we get all events
            });
            // Rebuild tree after fresh sync
            await StateManager.rebuildPoolTree();
            
            if (status.status === 'complete') {
                Toast.show(`Resynced: ${status.aspMembershipLeavesCount} ASP membership leaves, ${status.poolLeavesCount} pool leaves`, 'success');
            } else if (status.status === 'broken') {
                this.showWarning(status.message);
            }
        } catch (err) {
            console.error('[SyncUI] Force resync failed:', err);
            Toast.show('Force resync failed: ' + err.message, 'error');
            this.hide();
        }
    }
};

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    Templates.init();
    Storage.load();
    
    Tabs.init();
    Wallet.init();
    Deposit.init();
    Withdraw.init();
    Transfer.init();
    Transact.init();
    NotesTable.init();
    
    // Load deployment config before initializing contract readers
    try {
        await loadDeployedContracts();
        ContractReader.init();
        PoolEventsFetcher.init();
        
        // Initialize state management and start sync
        SyncUI.init();
        await StateManager.initialize();
        
        // Check sync gap and show warning if needed
        await SyncUI.checkGap();
        
        // Start background sync
        SyncUI.startSync();
    } catch (err) {
        console.error('[Init] Failed to load deployment config:', err);
        // Display error
        const errorText = document.getElementById('contract-error-text');
        const errorDisplay = document.getElementById('contract-error-display');
        if (errorText && errorDisplay) {
            errorText.textContent = `Failed to load contract config: ${err.message}`;
            errorDisplay.classList.remove('hidden');
        }
    }
    
    // Initialize ZK prover in background
    // This preloads proving artifacts so they're ready when user initiates a transaction
    ProverUI.initialize().catch(err => {
        console.warn('[Init] Background prover init failed (will retry on demand):', err.message);
    });
    
    console.log('PoolStellar initialized');
});
