/**
 * Withdraw Module - handles XLM withdrawals from the privacy pool.
 * @module ui/transactions/withdraw
 */

import { signWalletTransaction, signWalletAuthEntry } from '../../wallet.js';
import { readAllContractStates, submitPoolTransaction } from '../../stellar.js';
import { StateManager, poolStore } from '../../state/index.js';
import { generateWithdrawProof } from '../../transaction-builder.js';
import { App, Toast, Storage, deriveKeysFromWallet } from '../core.js';
import { Templates } from '../templates.js';
import { onWalletConnect } from '../navigation.js';

// Forward reference - set by main init
let NotesTableRef = null;

/**
 * Sets the NotesTable reference for post-withdraw rendering.
 * @param {Object} notesTable
 */
export function setNotesTableRef(notesTable) {
    NotesTableRef = notesTable;
}

export const Withdraw = {
    inputCount: 1,
    
    init() {
        const inputs = document.getElementById('withdraw-inputs');
        const btn = document.getElementById('btn-withdraw');
        const addBtn = document.getElementById('withdraw-add-input');
        const recipientInput = document.getElementById('withdraw-recipient');
        
        inputs.appendChild(Templates.createInputRow(0));
        this.inputCount = 1;
        
        if (App.state.wallet.connected && App.state.wallet.address) {
            recipientInput.value = App.state.wallet.address;
        }
        
        addBtn.classList.remove('hidden');
        
        addBtn.addEventListener('click', () => {
            if (this.inputCount < 2) {
                inputs.appendChild(Templates.createInputRow(1));
                this.inputCount = 2;
                addBtn.classList.add('hidden');
                this.updateTotal();
            }
        });
        
        inputs.addEventListener('input', () => this.updateTotal());
        btn.addEventListener('click', () => this.submit());
        
        // Register for wallet connect events
        onWalletConnect(() => this.prefillRecipient());
    },
    
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
                const amountStroops = note.amount < 1000 
                    ? BigInt(Math.round(note.amount * 1e7))
                    : BigInt(note.amount);
                totalStroops += amountStroops;
            }
        });
        const totalXLM = Number(totalStroops) / 1e7;
        document.getElementById('withdraw-total').textContent = `${totalXLM.toFixed(7).replace(/\.?0+$/, '')} XLM`;
        return totalStroops;
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
            const { privKeyBytes, encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: setLoadingText,
                signDelay: 500,
            });
            
            setLoadingText('Syncing pool state...');
            try {
                await StateManager.startSync({ privateKey: privKeyBytes, forceRefresh: true });
                await StateManager.rebuildPoolTree();
                console.log('[Withdraw] Pool state synced and tree rebuilt');
            } catch (syncError) {
                console.warn('[Withdraw] Sync warning:', syncError.message);
            }
            
            setLoadingText('Gathering input notes...');
            const inputNotes = [];
            let totalInputAmount = 0n;
            
            const noteInputs = document.querySelectorAll('#withdraw-inputs .note-input');
            for (const input of noteInputs) {
                const noteId = input.value.trim();
                if (!noteId) continue;
                
                const note = App.state.notes.find(n => n.id === noteId && !n.spent);
                if (!note) continue;
                
                const merkleProof = await poolStore.getMerkleProof(note.leafIndex);
                if (!merkleProof) {
                    throw new Error(`Cannot find merkle proof for note at index ${note.leafIndex}. Pool state may be out of sync.`);
                }
                
                const amountStroops = note.amount < 1000 
                    ? BigInt(Math.round(note.amount * 1e7))
                    : BigInt(note.amount);
                
                inputNotes.push({
                    ...note,
                    amount: amountStroops,
                    merkleProof,
                });
                totalInputAmount += amountStroops;
            }
            
            if (inputNotes.length === 0) {
                throw new Error('No valid input notes found');
            }
            
            const withdrawAmount = totalStroops;
            
            const membershipBlindingInput = document.getElementById('withdraw-membership-blinding');
            const membershipBlinding = membershipBlindingInput ? BigInt(membershipBlindingInput.value || '0') : 0n;
            console.log('[Withdraw] Using membership blinding:', membershipBlinding.toString());
            
            setLoadingText('Fetching on-chain state...');
            const states = await readAllContractStates();
            const poolRoot = BigInt(states.pool.merkleRoot || '0x0');
            const membershipRoot = BigInt(states.aspMembership.root || '0x0');
            const nonMembershipRoot = BigInt(states.aspNonMembership.root || '0x0');
            
            console.log('[Withdraw] On-chain roots:', {
                pool: states.pool.merkleRoot,
                membership: states.aspMembership.root,
                nonMembership: states.aspNonMembership.root || '0',
            });
            
            // Verify local pool tree sync
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
                let localRootBigInt = 0n;
                for (let i = 0; i < localPoolRootLE.length; i++) {
                    localRootBigInt = (localRootBigInt << 8n) | BigInt(localPoolRootLE[localPoolRootLE.length - 1 - i]);
                }
                console.log('[Withdraw] Local pool root (BE):', localRootBigInt.toString(16));
                console.log('[Withdraw] On-chain pool root:', poolRoot.toString(16));
                if (localRootBigInt !== poolRoot) {
                    console.error('[Withdraw] Pool root mismatch! Local tree out of sync.');
                    throw new Error(`Pool state out of sync. Local: ${localLeafCount} leaves, On-chain: ${onChainLeafCount} leaves. Try clearing data and refreshing.`);
                }
                console.log('[Withdraw] Pool roots match - local tree is synced');
            }
            
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
                onProgress: ({ message }) => {
                    if (message) setLoadingText(message);
                },
            });
            
            console.log('[Withdraw] Proof generated');
            
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
            
            inputNotes.forEach(inputNote => {
                const note = App.state.notes.find(n => n.id === inputNote.id);
                if (note) note.spent = true;
            });
            
            Storage.save();
            if (NotesTableRef) NotesTableRef.render();
            
            try {
                setLoadingText('Syncing pool state...');
                await StateManager.startSync({ forceRefresh: true });
                await StateManager.rebuildPoolTree();
                console.log('[Withdraw] Pool state synced and tree rebuilt');
            } catch (syncError) {
                console.warn('[Withdraw] Pool sync failed:', syncError);
            }
            
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
            Toast.show('Withdrawal failed: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
};
