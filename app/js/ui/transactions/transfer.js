/**
 * Transfer Module - handles private note transfers to other users.
 * @module ui/transactions/transfer
 */

import { signWalletTransaction, signWalletAuthEntry } from '../../wallet.js';
import { readAllContractStates, getDeployedContracts, submitPoolTransaction } from '../../stellar.js';
import { StateManager, poolStore, notesStore } from '../../state/index.js';
import { hexToBytes } from '../../state/utils.js';
import { generateTransferProof } from '../../transaction-builder.js';
import { generateBlinding, fieldToHex, bytesToBigIntLE, hexToField } from '../../bridge.js';
import { App, Utils, Toast, Storage, deriveKeysFromWallet } from '../core.js';
import { Templates } from '../templates.js';
import { AddressBook } from '../address-book.js';
import { getTransactionErrorMessage } from '../errors.js';

// Forward reference - set by main init
let NotesTableRef = null;

/**
 * Sets the NotesTable reference for post-transfer rendering.
 * @param {Object} notesTable
 */
export function setNotesTableRef(notesTable) {
    NotesTableRef = notesTable;
}

export const Transfer = {
    init() {
        const inputs = document.getElementById('transfer-inputs');
        const outputs = document.getElementById('transfer-outputs');
        const btn = document.getElementById('btn-transfer');
        
        inputs.appendChild(Templates.createInputRow(0));
        inputs.appendChild(Templates.createInputRow(1));
        outputs.appendChild(Templates.createOutputRow(0, 0));
        outputs.appendChild(Templates.createOutputRow(1, 0));
        
        inputs.addEventListener('input', () => this.updateBalance());
        outputs.addEventListener('input', () => this.updateBalance());
        
        btn.addEventListener('click', () => this.submit());
        
        // Address book lookup button
        document.getElementById('transfer-addressbook-btn')?.addEventListener('click', () => {
            this.openAddressBookLookup();
        });
        
        // Address lookup hint link
        document.getElementById('transfer-lookup-hint')?.addEventListener('click', () => {
            this.openAddressBookLookup();
        });
        
        this.updateBalance();
    },
    
    /**
     * Opens address book by scrolling to the section and switching to the address book tab.
     * User can then search or select an entry to populate the recipient fields.
     */
    openAddressBookLookup() {
        // Switch to address book section
        AddressBook.switchSection('addressbook');
        
        // Scroll to the notes/address book section
        const section = document.getElementById('section-panel-addressbook');
        if (section) {
            section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        
        // Focus the search input
        setTimeout(() => {
            const searchInput = document.getElementById('addressbook-search');
            if (searchInput) {
                searchInput.focus();
            }
        }, 300);
        
        Toast.show('Select a recipient from the address book', 'info');
    },
    
    updateBalance() {
        let inputsTotalStroops = 0;
        document.querySelectorAll('#transfer-inputs .note-input').forEach(input => {
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
        
        // Get recipient note key (BN254 - used for commitment)
        const recipientNoteKey = document.getElementById('transfer-recipient-key').value.trim();
        if (!recipientNoteKey) {
            Toast.show('Please enter recipient note key (BN254)', 'error');
            return;
        }
        
        // Get recipient encryption key (X25519 - used for encrypting note data)
        const recipientEncKey = document.getElementById('transfer-recipient-enc-key')?.value.trim();
        if (!recipientEncKey) {
            Toast.show('Please enter recipient encryption key (X25519)', 'error');
            return;
        }
        
        if (!this.updateBalance()) {
            Toast.show('Input notes must equal output notes', 'error');
            return;
        }
        
        let hasInput = false;
        document.querySelectorAll('#transfer-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const normalizedId = noteId.toLowerCase();
            const note = App.state.notes.find(n => (n.id === normalizedId || n.id === noteId) && !n.spent);
            if (note && note.amount > 0) {
                hasInput = true;
            } else if (input.dataset.uploadedAmount && Number(input.dataset.uploadedAmount) > 0) {
                hasInput = true;
            }
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
            btnLoading.innerHTML = `<span class="inline-block w-4 h-4 border-2 border-dark-950/30 border-t-dark-950 rounded-full animate-spin"></span><span class="ml-2">${text}</span>`;
        };
        
        try {
            const { privKeyBytes, encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: setLoadingText,
                signDelay: 500,
            });
            
            // Parse recipient note key (BN254 - for commitment)
            // We use hexToField to properly convert from BE hex to LE bytes (Soroban uses BE, proofs were generated using arkworks and LE)
            let recipientNoteKeyBytes;
            try {
                recipientNoteKeyBytes = hexToField(recipientNoteKey);
                if (recipientNoteKeyBytes.length !== 32) {
                    throw new Error('Invalid length');
                }
            } catch {
                throw new Error('Invalid recipient note key format. Expected 64 hex characters.');
            }
            
            // Parse recipient encryption key (X25519 - for encryption)
            // X25519 keys are raw bytes (not field elements), so use hexToBytes (no reversal)
            let recipientEncKeyBytes;
            try {
                recipientEncKeyBytes = hexToBytes(recipientEncKey);
                if (recipientEncKeyBytes.length !== 32) {
                    throw new Error('Invalid length');
                }
            } catch {
                throw new Error('Invalid recipient encryption key format. Expected 64 hex characters.');
            }
            
            setLoadingText('Gathering input notes...');
            const inputNotes = [];
            
            const transferNoteInputs = document.querySelectorAll('#transfer-inputs .note-input');
            for (const input of transferNoteInputs) {
                const noteId = input.value.trim();
                if (!noteId) continue;
                
                const normalizedId = noteId.toLowerCase();
                let note = App.state.notes.find(n => (n.id === normalizedId || n.id === noteId) && !n.spent);
                
                // If not found in memory, try fetching directly from database
                if (!note) {
                    console.warn('[Transfer] Note not in App.state, trying database lookup:', noteId.slice(0, 20));
                    const dbNote = await notesStore.getNoteByCommitment(noteId);
                    if (dbNote && !dbNote.spent) {
                        note = dbNote;
                        console.log('[Transfer] Found note in database:', dbNote.id.slice(0, 20));
                    }
                }
                
                if (!note) {
                    console.warn('[Transfer] Note not found anywhere:', noteId);
                    continue;
                }
                
                const merkleProof = await poolStore.getMerkleProof(note.leafIndex);
                if (!merkleProof) {
                    throw new Error(`Cannot find merkle proof for note at index ${note.leafIndex}`);
                }
                
                inputNotes.push({ ...note, merkleProof });
            }
            
            if (inputNotes.length === 0) {
                throw new Error('No valid input notes found');
            }
            
            const recipientOutputs = [];
            document.querySelectorAll('#transfer-outputs .output-row').forEach(row => {
                const amount = parseFloat(row.querySelector('.output-amount').value) || 0;
                if (amount > 0) {
                    const blindingBytes = generateBlinding();
                    const blinding = bytesToBigIntLE(blindingBytes);
                    recipientOutputs.push({ amount: BigInt(Math.round(amount * 1e7)), blinding });
                }
            });
            
            const membershipBlindingInput = document.getElementById('transfer-membership-blinding');
            const membershipBlinding = membershipBlindingInput ? BigInt(membershipBlindingInput.value || '0') : 0n;
            console.log('[Transfer] Using membership blinding:', membershipBlinding.toString());
            
            setLoadingText('Fetching on-chain state...');
            const states = await readAllContractStates();
            const contracts = getDeployedContracts();
            const poolRoot = BigInt(states.pool.merkleRoot || '0x0');
            const membershipRoot = BigInt(states.aspMembership.root || '0x0');
            const nonMembershipRoot = BigInt(states.aspNonMembership.root || '0x0');
            
            console.log('[Transfer] On-chain roots:', {
                pool: states.pool.merkleRoot,
                membership: states.aspMembership.root,
                nonMembership: states.aspNonMembership.root || '0',
            });
            
            console.log('[Transfer] Lengths of hex', {
                pool: states.pool.merkleRoot.length,
                membership: states.aspMembership.root.length,
                nonMembership: states.aspNonMembership.root?.length || 0,
            });
            
            // Verify local pool tree is in sync with on-chain state
            const localPoolRootLE = poolStore.getRoot();
            const localLeafCount = poolStore.getNextIndex();
            const onChainLeafCount = states.pool.nextIndex || 0;
            
            if (localPoolRootLE) {
                let localRootBigInt = 0n;
                for (let i = 0; i < localPoolRootLE.length; i++) {
                    localRootBigInt = (localRootBigInt << 8n) | BigInt(localPoolRootLE[localPoolRootLE.length - 1 - i]);
                }
                console.log('[Transfer] Pool sync check:', {
                    localRoot: localRootBigInt.toString(16),
                    onChainRoot: poolRoot.toString(16),
                    localLeaves: localLeafCount,
                    onChainLeaves: onChainLeafCount,
                });
                
                if (localRootBigInt !== poolRoot) {
                    console.error('[Transfer] Pool root mismatch! Local tree out of sync.');
                    // Try to resync before failing
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
                    inputNotes.length = 0; // Clear and rebuild
                    for (const input of transferNoteInputs) {
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
            
            setLoadingText('Generating ZK proof...');
            const proofResult = await generateTransferProof({
                privKeyBytes,
                encryptionPubKey: encryptionKeypair.publicKey,
                recipientPubKey: recipientNoteKeyBytes,           // BN254 - for commitment
                recipientEncryptionPubKey: recipientEncKeyBytes,  // X25519 - for encryption
                poolRoot,
                membershipRoot,
                nonMembershipRoot,
                inputNotes,
                recipientOutputs,
                poolAddress: contracts.pool,
                stateManager: StateManager,
                membershipBlinding,
            }, {
                onProgress: ({ message }) => {
                    if (message) setLoadingText(message);
                },
            });
            
            console.log('[Transfer] Proof generated');
            
            let outputIndex = 0;
            document.querySelectorAll('#transfer-outputs .output-row').forEach(row => {
                const outputNote = proofResult.outputNotes[outputIndex];
                const amountXLM = parseFloat(row.querySelector('.output-amount').value) || 0;
                const isDummy = amountXLM === 0;
                
                const noteId = fieldToHex(outputNote.commitmentBytes);
                const amountStroops = Number(outputNote.amount);
                
                const note = {
                    id: noteId,
                    commitment: noteId,
                    amount: amountStroops,
                    blinding: fieldToHex(outputNote.blindingBytes),
                    spent: false,
                    isDummy,
                    owner: recipientNoteKey,
                    isReceived: true,
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
            
            // Mark input notes as spent in IndexedDB
            for (const inputNote of inputNotes) {
                await notesStore.markNoteSpent(inputNote.id, submitResult.ledger || 0);
                // Also update in-memory state
                const note = App.state.notes.find(n => n.id === inputNote.id);
                if (note) note.spent = true;
            }
            
            // In a transfer, all outputs in recipientOutputs go to the recipient.
            const recipientOutputCount = recipientOutputs.length;
            const poolNextIndex = states.pool.nextIndex || 0;
            
            for (let i = recipientOutputCount; i < proofResult.outputNotes.length; i++) {
                const outputNote = proofResult.outputNotes[i];
                const noteId = fieldToHex(outputNote.commitmentBytes);
                const leafIndex = poolNextIndex + i;
                
                // Only save non-dummy change outputs (amount > 0)
                if (outputNote.amount > 0n) {
                    await notesStore.saveNote({
                        commitment: noteId,
                        privateKey: privKeyBytes,
                        blinding: outputNote.blindingBytes,
                        amount: Number(outputNote.amount),
                        leafIndex,
                        ledger: submitResult.ledger || 0,
                        isReceived: false,
                    });
                    console.log(`[Transfer] Saved sender's change note ${noteId.slice(0, 10)}... at index ${leafIndex}`);
                }
            }
            
            // Reload notes from storage to ensure consistency
            await Storage.load();
            if (NotesTableRef) NotesTableRef.render();
            Toast.show('Transfer successful! The recipient can scan for new notes.', 'success');
        } catch (e) {
            console.error('[Transfer] Error:', e);
            Toast.show(getTransactionErrorMessage(e, 'Transfer'), 'error');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
};
