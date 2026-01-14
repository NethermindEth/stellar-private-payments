/**
 * ASP Non-Membership Fetcher - fetches SMT non-membership proofs on-demand from RPC.
 * The ASP Non-Membership contract stores all nodes on-chain, so we can query directly
 * without local state sync.
 * @module state/asp-non-membership-fetcher
 */

import { getSorobanServer, getDeployedContracts, scValToNative } from '../stellar.js';
import { xdr, Address } from '@stellar/stellar-sdk';
import { bytesToHex } from './utils.js';

/**
 * @typedef {Object} SMTNonMembershipProof
 * @property {Uint8Array} root - Current SMT root
 * @property {Uint8Array} key - Key being proven
 * @property {Uint8Array[]} siblings - Sibling hashes along the path
 * @property {Uint8Array} notFoundKey - Key at collision point (or zero)
 * @property {Uint8Array} notFoundValue - Value at collision point (or zero)
 * @property {boolean} isOld0 - True if path ended at empty branch
 */

/**
 * Fetches the current root of the ASP Non-Membership SMT.
 * @returns {Promise<{success: boolean, root?: string, error?: string}>}
 */
export async function fetchRoot() {
    const contracts = getDeployedContracts();
    if (!contracts?.aspNonMembership) {
        return { success: false, error: 'Deployments not loaded' };
    }

    try {
        const server = getSorobanServer();
        const contractId = contracts.aspNonMembership;
        
        // Build the ledger key for Root
        const rootKey = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Root')]);
        const ledgerKey = xdr.LedgerKey.contractData(
            new xdr.LedgerKeyContractData({
                contract: new Address(contractId).toScAddress(),
                key: rootKey,
                durability: xdr.ContractDataDurability.persistent(),
            })
        );

        const result = await server.getLedgerEntries(ledgerKey);
        
        if (result.entries && result.entries.length > 0) {
            const entry = result.entries[0];
            const contractData = entry.val.contractData();
            const root = scValToNative(contractData.val());
            return { success: true, root };
        }
        
        return { success: false, error: 'Root not found' };
    } catch (error) {
        console.error('[ASPNonMembershipFetcher] Failed to fetch root:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Fetches a non-membership proof for a key by calling the contract's find_key function.
 * Uses simulateTransaction to call the view function without submitting.
 * @param {Uint8Array|string} key - Key to prove non-membership for
 * @returns {Promise<{success: boolean, proof?: SMTNonMembershipProof, error?: string}>}
 */
export async function fetchNonMembershipProof(key) {
    const contracts = getDeployedContracts();
    if (!contracts?.aspNonMembership) {
        return { success: false, error: 'Deployments not loaded' };
    }

    try {
        const server = getSorobanServer();
        const contractId = contracts.aspNonMembership;
        
        // Convert key to U256 ScVal
        const keyHex = typeof key === 'string' ? key : bytesToHex(key);
        const keyU256 = hexToU256ScVal(keyHex);
        
        // Build the function invocation using simulateTransaction
        // We need to call find_key(key) on the contract
        // TODO: Update with real addresses once we integrate with the UI
        const account = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF'; // Dummy
        
        const invokeArgs = new xdr.InvokeContractArgs({
            contractAddress: new Address(contractId).toScAddress(),
            functionName: 'find_key',
            args: [keyU256],
        });

        const op = xdr.Operation.fromXDR(
            xdr.Operation.invokeHostFunction(
                new xdr.InvokeHostFunctionOp({
                    hostFunction: xdr.HostFunction.hostFunctionTypeInvokeContract(invokeArgs),
                    auth: [],
                })
            ).toXDR(),
            'base64'
        );

        // Build a minimal transaction for simulation
        const txBuilder = new (await import('@stellar/stellar-sdk')).TransactionBuilder(
            new (await import('@stellar/stellar-sdk')).Account(account, '0'),
            {
                fee: '100',
                networkPassphrase: (await import('../stellar.js')).getNetwork().passphrase,
            }
        );
        
        txBuilder.addOperation(op);
        txBuilder.setTimeout(30);
        const tx = txBuilder.build();

        const simulateResult = await server.simulateTransaction(tx);
        
        if ('error' in simulateResult) {
            return { success: false, error: simulateResult.error };
        }

        // Parse FindResult struct
        if (simulateResult.result?.retval) {
            const findResult = scValToNative(simulateResult.result.retval);
            
            // If found, the key exists (membership, invalid non-membership)
            if (findResult.found) {
                return { 
                    success: false, 
                    error: 'Key exists in tree (membership, invalid non-membership)',
                    keyExists: true,
                };
            }
            
            // Build non-membership proof
            const proof = {
                root: await fetchRoot().then(r => r.root),
                key: keyHex,
                siblings: findResult.siblings || [],
                notFoundKey: findResult.not_found_key || findResult.notFoundKey,
                notFoundValue: findResult.not_found_value || findResult.notFoundValue,
                isOld0: findResult.is_old0 || findResult.isOld0,
            };
            
            return { success: true, proof };
        }
        
        return { success: false, error: 'No result from simulation' };
    } catch (error) {
        console.error('[ASPNonMembershipFetcher] Failed to fetch proof:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Converts hex string to U256 ScVal.
 * @param {string} hex - Hex string
 * @returns {xdr.ScVal}
 */
function hexToU256ScVal(hex) {
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
    const paddedHex = cleanHex.padStart(64, '0');
    
    // U256 is stored as 4 x u64: hi_hi, hi_lo, lo_hi, lo_lo
    const hiHi = BigInt('0x' + paddedHex.slice(0, 16));
    const hiLo = BigInt('0x' + paddedHex.slice(16, 32));
    const loHi = BigInt('0x' + paddedHex.slice(32, 48));
    const loLo = BigInt('0x' + paddedHex.slice(48, 64));
    
    return xdr.ScVal.scvU256(
        new xdr.UInt256Parts({
            hiHi: xdr.Uint64.fromString(hiHi.toString()),
            hiLo: xdr.Uint64.fromString(hiLo.toString()),
            loHi: xdr.Uint64.fromString(loHi.toString()),
            loLo: xdr.Uint64.fromString(loLo.toString()),
        })
    );
}