/**
 * Transact Module - handles generic pool transactions (deposit/withdraw/transfer).
 * @module ui/transactions/transact
 */

import { signWalletTransaction, signWalletAuthEntry } from '../../wallet.js';
import { readAllContractStates, getDeployedContracts, submitPoolTransaction } from '../../stellar.js';
import { StateManager, poolStore, notesStore } from '../../state/index.js';
import { generateBlinding, fieldToHex, bytesToBigIntLE, bigintToField } from '../../bridge.js';
import { App, Utils, Toast, Storage, deriveKeysFromWallet } from '../core.js';
import { Templates } from '../templates.js';
import { onWalletConnect } from '../navigation.js';
import { getTransactionErrorMessage } from '../errors.js';

// Forward reference - set by main init
let NotesTableRef = null;

/**
 * Sets the NotesTable reference for post-transaction rendering.
 * @param {Object} notesTable
 */
export function setNotesTableRef(notesTable) {
    NotesTableRef = notesTable;
}

export const Transact = {
    init() {
        const slider = document.getElementById('transact-slider');
        const amount = document.getElementById('transact-amount');
        const inputs = document.getElementById('transact-inputs');
        const outputs = document.getElementById('transact-outputs');
        const btn = document.getElementById('btn-transact');
        
        inputs.appendChild(Templates.createInputRow(0));
        inputs.appendChild(Templates.createInputRow(1));
        // Use advanced output rows with per-output recipient selection
        outputs.appendChild(Templates.createAdvancedOutputRow(0, 0));
        outputs.appendChild(Templates.createAdvancedOutputRow(1, 0));
        
        if (App.state.wallet.connected && App.state.wallet.address) {
            const recipientInput = document.getElementById('transact-recipient');
            if (recipientInput) recipientInput.value = App.state.wallet.address;
        }
        
        slider.addEventListener('input', () => {
            amount.value = slider.value;
            this.updateBalance();
        });
        
        amount.addEventListener('input', () => {
            slider.value = Math.min(Math.max(-500, amount.value), 500);
            this.updateBalance();
        });
        
        inputs.addEventListener('input', () => this.updateBalance());
        outputs.addEventListener('input', () => this.updateBalance());
        
        document.querySelectorAll('[data-target="transact-amount"]').forEach(btn => {
            btn.addEventListener('click', () => {
                const input = document.getElementById('transact-amount');
                const val = parseFloat(input.value) || 0;
                input.value = btn.classList.contains('spinner-up') ? val + 1 : val - 1;
                input.dispatchEvent(new Event('input', { bubbles: true }));
            });
        });
        
        btn.addEventListener('click', () => this.submit());
        
        // Register for wallet connect events
        onWalletConnect(() => this.prefillRecipient());
        
        this.updateBalance();
    },
    
    prefillRecipient() {
        const recipientInput = document.getElementById('transact-recipient');
        if (recipientInput && !recipientInput.value && App.state.wallet.address) {
            recipientInput.value = App.state.wallet.address;
        }
    },
    
    /**
     * Gets the recipient configuration for each output.
     * Empty recipient key means "self". Returns array of { isSelf: boolean, publicKey: string|null }.
     */
    getOutputRecipients() {
        const recipients = [];
        document.querySelectorAll('#transact-outputs .advanced-output-row').forEach(row => {
            const recipientKey = row.querySelector('.output-recipient-key');
            const keyValue = recipientKey?.value.trim() || '';
            const isSelf = keyValue === '';
            
            recipients.push({
                isSelf,
                publicKey: isSelf ? null : keyValue,
            });
        });
        return recipients;
    },
    
    updateBalance() {
        let inputsTotalStroops = 0;
        document.querySelectorAll('#transact-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const normalizedId = noteId.toLowerCase();
            const note = App.state.notes.find(n => (n.id === normalizedId || n.id === noteId) && !n.spent);
            if (note) {
                inputsTotalStroops += Number(note.amount);
            } else if (input.dataset.uploadedAmount) {
                // Use amount from uploaded file if note not in local state
                inputsTotalStroops += Number(input.dataset.uploadedAmount);
            }
        });
        const inputsTotal = inputsTotalStroops / 1e7;
        
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
            btnLoading.innerHTML = `<span class="inline-block w-4 h-4 border-2 border-dark-950/30 border-t-dark-950 rounded-full animate-spin"></span><span class="ml-2">${text}</span>`;
        };
        
        try {
            const { privKeyBytes, encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: setLoadingText,
                signDelay: 500,
            });
            
            const publicAmount = parseFloat(document.getElementById('transact-amount').value) || 0;
            const publicAmountStroops = BigInt(Math.round(publicAmount * 1e7));
            
            // Get per-output recipient configuration
            const outputRecipients = this.getOutputRecipients();
            const hasExternalRecipient = outputRecipients.some(r => !r.isSelf && r.publicKey);
            
            setLoadingText('Gathering input notes...');
            const inputNotes = [];
            
            const transactNoteInputs = document.querySelectorAll('#transact-inputs .note-input');
            for (const input of transactNoteInputs) {
                const noteId = input.value.trim();
                if (!noteId) continue;
                
                const normalizedId = noteId.toLowerCase();
                let note = App.state.notes.find(n => (n.id === normalizedId || n.id === noteId) && !n.spent);
                
                // If not found in memory, try fetching directly from database
                if (!note) {
                    console.warn('[Transact] Note not in App.state, trying database lookup:', noteId.slice(0, 20));
                    const dbNote = await notesStore.getNoteByCommitment(noteId);
                    if (dbNote && !dbNote.spent) {
                        note = dbNote;
                        console.log('[Transact] Found note in database:', dbNote.id.slice(0, 20));
                    }
                }
                
                if (!note) {
                    console.warn('[Transact] Note not found anywhere:', noteId);
                    continue;
                }
                
                const merkleProof = await poolStore.getMerkleProof(note.leafIndex);
                if (!merkleProof) {
                    throw new Error(`Cannot find merkle proof for note at index ${note.leafIndex}`);
                }
                
                inputNotes.push({ ...note, merkleProof });
            }
            
            const outputs = [];
            document.querySelectorAll('#transact-outputs .advanced-output-row').forEach((row, idx) => {
                const amount = parseFloat(row.querySelector('.output-amount').value) || 0;
                const blindingBytes = generateBlinding();
                const blinding = bytesToBigIntLE(blindingBytes);
                const recipient = outputRecipients[idx];
                outputs.push({ 
                    amount: BigInt(Math.round(amount * 1e7)), 
                    blinding,
                    isSelf: recipient?.isSelf ?? true,
                    recipientPublicKey: recipient?.publicKey || null,
                });
            });
            
            const membershipBlindingInput = document.getElementById('transact-membership-blinding');
            const membershipBlinding = membershipBlindingInput ? BigInt(membershipBlindingInput.value || '0') : 0n;
            console.log('[Transact] Using membership blinding:', membershipBlinding.toString());
            
            setLoadingText('Fetching on-chain state...');
            const states = await readAllContractStates();
            const contracts = getDeployedContracts();
            const poolRoot = BigInt(states.pool.merkleRoot || '0x0');
            const membershipRoot = BigInt(states.aspMembership.root || '0x0');
            const nonMembershipRoot = BigInt(states.aspNonMembership.root || '0x0');
            
            // Verify local pool tree is in sync with on-chain state
            const localPoolRootLE = poolStore.getRoot();
            const localLeafCount = poolStore.getNextIndex();
            const onChainLeafCount = states.pool.nextIndex || 0;
            
            if (localPoolRootLE) {
                let localRootBigInt = 0n;
                for (let i = 0; i < localPoolRootLE.length; i++) {
                    localRootBigInt = (localRootBigInt << 8n) | BigInt(localPoolRootLE[localPoolRootLE.length - 1 - i]);
                }
                console.log('[Transact] Pool sync check:', {
                    localRoot: localRootBigInt.toString(16),
                    onChainRoot: poolRoot.toString(16),
                    localLeaves: localLeafCount,
                    onChainLeaves: onChainLeafCount,
                });
                
                if (localRootBigInt !== poolRoot) {
                    console.error('[Transact] Pool root mismatch! Local tree out of sync.');
                    setLoadingText('Pool out of sync, rebuilding...');
                    await StateManager.startSync({ forceRefresh: true });
                    await StateManager.rebuildPoolTree();
                    
                    // Re-fetch state and re-check
                    const newStates = await readAllContractStates();
                    const newPoolRoot = BigInt(newStates.pool.merkleRoot || '0x0');
                    const newLocalRootLE = poolStore.getRoot();
                    let newLocalRootBigInt = 0n;
                    for (let i = 0; i < newLocalRootLE.length; i++) {
                        newLocalRootBigInt = (newLocalRootBigInt << 8n) | BigInt(newLocalRootLE[newLocalRootLE.length - 1 - i]);
                    }
                    
                    if (newLocalRootBigInt !== newPoolRoot) {
                        throw new Error(`Pool state still out of sync after rebuild. Try refreshing the page.`);
                    }
                    
                    // Re-build merkle proofs with synced tree
                    setLoadingText('Re-gathering input notes...');
                    inputNotes.length = 0;
                    for (const input of transactNoteInputs) {
                        const noteId = input.value.trim();
                        if (!noteId) continue;
                        const normalizedId = noteId.toLowerCase();
                        let note = App.state.notes.find(n => (n.id === normalizedId || n.id === noteId) && !n.spent);
                        if (!note) {
                            const dbNote = await notesStore.getNoteByCommitment(noteId);
                            if (dbNote && !dbNote.spent) note = dbNote;
                        }
                        if (!note) continue;
                        const merkleProof = await poolStore.getMerkleProof(note.leafIndex);
                        if (merkleProof) inputNotes.push({ ...note, merkleProof });
                    }
                }
            }
            
            let recipient;
            if (publicAmountStroops > 0n) {
                recipient = contracts.pool;
            } else if (publicAmountStroops < 0n) {
                const withdrawRecipient = document.getElementById('transact-recipient')?.value.trim();
                recipient = withdrawRecipient || App.state.wallet.address;
            } else {
                recipient = contracts.pool;
            }
            
            console.log('[Transact] Transaction parameters:', {
                publicAmount,
                inputCount: inputNotes.length,
                outputCount: outputs.length,
                recipient,
                hasExternalRecipient,
            });
            
            setLoadingText('Generating ZK proof...');
            const { generateTransactionProof } = await import('../../transaction-builder.js');
            
            const proofResult = await generateTransactionProof({
                privKeyBytes,
                encryptionPubKey: encryptionKeypair.publicKey,
                poolRoot,
                membershipRoot,
                nonMembershipRoot,
                inputs: inputNotes,
                outputs,
                extData: { recipient, ext_amount: publicAmountStroops },
                stateManager: StateManager,
                membershipBlinding,
            }, {
                onProgress: ({ message }) => {
                    if (message) setLoadingText(message);
                },
            });
            
            console.log('[Transact] Proof generated');
            
            const poolNextIndex = Number(states.pool.merkleNextIndex || 0);
            
            const pendingNotes = [];
            let outputIndex = 0;
            document.querySelectorAll('#transact-outputs .advanced-output-row').forEach(row => {
                const outputNote = proofResult.outputNotes[outputIndex];
                const amountXLM = parseFloat(row.querySelector('.output-amount').value) || 0;
                const isDummy = amountXLM === 0;
                const recipientInfo = outputRecipients[outputIndex];
                
                const noteId = fieldToHex(outputNote.commitmentBytes);
                const leafIndex = poolNextIndex + outputIndex;
                const amountStroops = Number(outputNote.amount);
                
                // Determine note owner - either self or specified recipient
                const noteOwner = recipientInfo?.isSelf 
                    ? App.state.wallet.address 
                    : (recipientInfo?.publicKey || App.state.wallet.address);
                
                const note = {
                    id: noteId,
                    commitment: noteId,
                    amount: amountStroops,
                    blinding: fieldToHex(outputNote.blindingBytes),
                    leafIndex,
                    spent: false,
                    isDummy,
                    owner: noteOwner,
                    createdAt: new Date().toISOString()
                };
                
                // Only add to pending notes if it's for ourselves and not a dummy
                if (!isDummy && recipientInfo?.isSelf) pendingNotes.push(note);
                
                const display = row.querySelector('.output-note-id');
                display.value = Utils.truncateHex(noteId, 8, 8);
                display.dataset.fullId = noteId;
                display.dataset.noteData = JSON.stringify(note, null, 2);
                
                row.querySelector('.copy-btn').disabled = false;
                row.querySelector('.download-btn').disabled = false;
                outputIndex++;
            });
            
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
            
            // Save new notes to IndexedDB
            for (const note of pendingNotes) {
                await notesStore.saveNote({
                    commitment: note.commitment,
                    privateKey: privKeyBytes,
                    blinding: note.blinding,
                    amount: note.amount,
                    leafIndex: note.leafIndex,
                    ledger: submitResult.ledger || 0,
                    owner: note.owner,
                });
            }
            
            // Mark spent notes
            for (const inputNote of inputNotes) {
                await notesStore.markNoteSpent(inputNote.id, submitResult.ledger || 0);
            }
            
            // Reload notes for UI
            await Storage.load();
            if (NotesTableRef) NotesTableRef.render();
            
            try {
                setLoadingText('Syncing pool state...');
                await StateManager.startSync({ forceRefresh: true });
                await StateManager.rebuildPoolTree();
                console.log('[Transact] Pool state synced and tree rebuilt');
            } catch (syncError) {
                console.warn('[Transact] Pool sync failed:', syncError);
            }
            
            if (hasExternalRecipient) {
                Toast.show('Transaction successful! Share note files with recipients.', 'success');
            } else {
                Toast.show(`Transaction successful! Tx: ${submitResult.txHash?.slice(0, 8)}...`, 'success');
            }
        } catch (e) {
            console.error('[Transact] Error:', e);
            Toast.show(getTransactionErrorMessage(e, 'Transaction'), 'error');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
};
