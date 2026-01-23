/**
 * Transfer Module - handles private note transfers to other users.
 * @module ui/transactions/transfer
 */

import { signWalletTransaction, signWalletAuthEntry } from '../../wallet.js';
import { readAllContractStates, getDeployedContracts, submitPoolTransaction } from '../../stellar.js';
import { StateManager, poolStore } from '../../state/index.js';
import { generateTransferProof } from '../../transaction-builder.js';
import { generateBlinding, fieldToHex } from '../../bridge.js';
import { App, Utils, Toast, Storage, deriveKeysFromWallet } from '../core.js';
import { Templates } from '../templates.js';

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
        
        this.updateBalance();
    },
    
    updateBalance() {
        let inputsTotalStroops = 0;
        document.querySelectorAll('#transfer-inputs .note-input').forEach(input => {
            const noteId = input.value.trim();
            const note = App.state.notes.find(n => n.id === noteId && !n.spent);
            if (note) inputsTotalStroops += Number(note.amount);
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
        
        const recipientKey = document.getElementById('transfer-recipient-key').value.trim();
        if (!recipientKey) {
            Toast.show('Please enter recipient public key', 'error');
            return;
        }
        
        if (!this.updateBalance()) {
            Toast.show('Input notes must equal output notes', 'error');
            return;
        }
        
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
            const { privKeyBytes, encryptionKeypair } = await deriveKeysFromWallet({
                onStatus: setLoadingText,
                signDelay: 500,
            });
            
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
                    const blinding = BigInt('0x' + fieldToHex(blindingBytes).slice(2));
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
            
            setLoadingText('Generating ZK proof...');
            const proofResult = await generateTransferProof({
                privKeyBytes,
                encryptionPubKey: encryptionKeypair.publicKey,
                recipientPubKey: recipientPubKeyBytes,
                recipientEncryptionPubKey: recipientPubKeyBytes,
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
            
            inputNotes.forEach(inputNote => {
                const note = App.state.notes.find(n => n.id === inputNote.id);
                if (note) note.spent = true;
            });
            
            Storage.save();
            if (NotesTableRef) NotesTableRef.render();
            Toast.show('Transfer successful! Share the note files with the recipient.', 'success');
        } catch (e) {
            console.error('[Transfer] Error:', e);
            Toast.show('Transfer failed: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
};
