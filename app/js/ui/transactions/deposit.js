/**
 * Deposit Module - handles XLM deposits into the privacy pool.
 * @module ui/transactions/deposit
 */

import { signWalletTransaction, signWalletAuthEntry } from '../../wallet.js';
import { 
    readPoolState,
    readASPMembershipState,
    readASPNonMembershipState,
    getDeployedContracts,
    submitDeposit,
} from '../../stellar.js';
import { StateManager } from '../../state/index.js';
import { generateDepositProof } from '../../transaction-builder.js';
import { 
    generateBlinding, 
    fieldToHex,
    bigintToField,
    poseidon2Hash2,
} from '../../bridge.js';
import { App, Utils, Toast, Storage, deriveKeysFromWallet } from '../core.js';
import { Templates } from '../templates.js';

// Forward reference - set by main init
let NotesTableRef = null;

/**
 * Sets the NotesTable reference for post-deposit rendering.
 * @param {Object} notesTable
 */
export function setNotesTableRef(notesTable) {
    NotesTableRef = notesTable;
}

export const Deposit = {
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
            
            // Compute ASP membership leaf for debugging
            const membershipBlindingInput = document.getElementById('deposit-membership-blinding')?.value || '0';
            const membershipBlinding = BigInt(membershipBlindingInput);
            const membershipBlindingBytes = bigintToField(membershipBlinding);
            const membershipLeaf = poseidon2Hash2(pubKeyBytes, membershipBlindingBytes, 1);
            const membershipLeafHex = fieldToHex(membershipLeaf);
            console.log('[Deposit] ASP Membership Leaf:', membershipLeafHex);
            
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
            
            const poolRoot = BigInt(poolState.merkleRoot || '0x0');
            const membershipRoot = BigInt(membershipState.root || '0x0');
            const nonMembershipRoot = BigInt(nonMembershipState.root || '0x0');
            
            console.log('[Deposit] On-chain roots:', {
                pool: poolRoot.toString(16),
                membership: membershipRoot.toString(16),
                nonMembership: nonMembershipRoot.toString(16),
            });
            
            // Step 3: Build output notes
            const outputs = [];
            document.querySelectorAll('#deposit-outputs .output-row').forEach(row => {
                const amount = parseFloat(row.querySelector('.output-amount').value) || 0;
                const amountBigInt = BigInt(Math.floor(amount * 1e7));
                const blindingBytes = generateBlinding();
                const blinding = BigInt('0x' + fieldToHex(blindingBytes).slice(2));
                outputs.push({ amount: amountBigInt, blinding });
            });
            
            // Ensure exactly 2 outputs
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
                membershipLeafIndex: 0,
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
            
            // Step 5: Prepare notes
            const poolNextIndex = Number(poolState.merkleNextIndex || 0);
            
            const pendingNotes = [];
            let outputIndex = 0;
            document.querySelectorAll('#deposit-outputs .output-row').forEach(row => {
                const outputNote = proofResult.outputNotes[outputIndex];
                const amountXLM = parseFloat(row.querySelector('.output-amount').value) || 0;
                const isDummy = amountXLM === 0;
                
                const noteId = fieldToHex(outputNote.commitmentBytes);
                const leafIndex = poolNextIndex + outputIndex;
                const amountStroops = Number(outputNote.amount);
                
                const note = {
                    id: noteId,
                    commitment: fieldToHex(outputNote.commitmentBytes),
                    amount: amountStroops,
                    blinding: outputNote.blinding.toString(),
                    leafIndex,
                    spent: false,
                    isDummy,
                    createdAt: new Date().toISOString()
                };
                
                if (!isDummy) pendingNotes.push(note);
                
                const display = row.querySelector('.output-note-id');
                display.value = Utils.truncateHex(noteId, 8, 8);
                display.dataset.fullId = noteId;
                display.dataset.noteData = JSON.stringify(note, null, 2);
                
                row.querySelector('.copy-btn').disabled = false;
                row.querySelector('.download-btn').disabled = false;
                outputIndex++;
            });
            
            // Step 6: Submit transaction
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
            
            if (submitResult.warning) {
                console.warn('[Deposit] Warning:', submitResult.warning);
            }
            
            // Save notes after success
            pendingNotes.forEach(note => App.state.notes.push(note));
            Storage.save();
            if (NotesTableRef) NotesTableRef.render();
            
            // Sync pool state
            try {
                setLoadingText('Syncing pool state...');
                await StateManager.startSync({ forceRefresh: true });
                await StateManager.rebuildPoolTree();
                console.log('[Deposit] Pool state synced and tree rebuilt');
            } catch (syncError) {
                console.warn('[Deposit] Pool sync failed:', syncError);
            }
            
            const txDisplay = submitResult.txHash?.startsWith('submitted') || submitResult.txHash?.startsWith('pending')
                ? 'Check Stellar Expert for status'
                : `Tx: ${submitResult.txHash?.slice(0, 8)}...`;
            Toast.show(`Deposited ${totalAmount} XLM! ${txDisplay}`, 'success');
        } catch (e) {
            console.error('[Deposit] Error:', e);
            Toast.show('Deposit failed: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
};
