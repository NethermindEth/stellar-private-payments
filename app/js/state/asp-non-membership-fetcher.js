/**
 * ASP Non-Membership Fetcher - fetches SMT non-membership proofs on-demand from RPC.
 * The ASP Non-Membership contract stores all nodes on-chain, so we can query directly
 * without local state sync.
 * @module state/asp-non-membership-fetcher
 */

import { getSorobanServer, getDeployedContracts, scValToNative, getNetwork } from '../stellar.js';
import { xdr, Address, TransactionBuilder, Account, Operation } from '@stellar/stellar-sdk';
import { bytesToHex, hexToBytes, BN254_MODULUS } from './utils.js';

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
 * Creates an enum-style key for Soroban contract storage.
 * Soroban enum DataKey variants serialize as scvVec([scvSymbol(variant), ...values]).
 * @param {string} variant - Enum variant name (e.g., 'Root', 'Admin')
 * @returns {xdr.ScVal}
 */
function createEnumKey(variant) {
    return xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(variant)]);
}

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
        
        // Build the ledger key for Root using enum-style key format
        // DataKey::Root serializes as scvVec([scvSymbol("Root")])
        const rootKey = createEnumKey('Root');
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
 * @returns {Promise<{success: boolean, proof?: SMTNonMembershipProof, error?: string, keyExists?: boolean}>}
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
        const account = 'GDF4BXPQY5N4BEO24UIHM4NVB62MW7HDWH7SVHKLVZAMLP5IIHCFQORC'; // Dummy
        
        const invokeArgs = new xdr.InvokeContractArgs({
            contractAddress: new Address(contractId).toScAddress(),
            functionName: 'find_key',
            args: [keyU256],
        });

        const op = Operation.invokeHostFunction({
            func: xdr.HostFunction.hostFunctionTypeInvokeContract(invokeArgs),
            auth: [],
        });

        // Build a minimal transaction for simulation
        const txBuilder = new TransactionBuilder(
            new Account(account, '0'),
            {
                fee: '100',
                networkPassphrase: getNetwork().passphrase,
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
            
            // Fetch root
            const rootResult = await fetchRoot();
            if (!rootResult.success) {
                return { success: false, error: `Failed to fetch root: ${rootResult.error}` };
            }
            
            // Build non-membership proof
            const proof = {
                root: toBytes(rootResult.root),
                key: hexToBytes(keyHex),
                siblings: (findResult.siblings || []).map(s => toBytes(s)),
                notFoundKey: toBytes(findResult.not_found_key || findResult.notFoundKey),
                notFoundValue: toBytes(findResult.not_found_value || findResult.notFoundValue),
                isOld0: findResult.is_old0 ?? findResult.isOld0 ?? false,
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
 * Converts various types to Uint8Array (32 bytes, little-endian for circuit use).
 * Handles hex strings, Uint8Array, ArrayBuffer, BigInt, and null/undefined.
 * BigInt values are reduced modulo BN254 to ensure they're valid field elements.
 * @param {string|Uint8Array|ArrayBuffer|BigInt|null|undefined} value
 * @returns {Uint8Array}
 */
function toBytes(value) {
    if (value === null || value === undefined) {
        return new Uint8Array(32); // Return zero bytes
    }
    if (value instanceof Uint8Array) {
        return value;
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }
    // Handle Buffer-like objects (has buffer property pointing to ArrayBuffer)
    if (value && typeof value === 'object' && value.buffer instanceof ArrayBuffer) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (typeof value === 'bigint') {
        // Reduce to BN254 field modulus to ensure valid field element
        const reduced = value % BN254_MODULUS;
        // Convert to 32-byte little-endian representation (for circuit compatibility)
        const bytes = new Uint8Array(32);
        let v = reduced;
        for (let i = 0; i < 32; i++) {
            bytes[i] = Number(v & 0xffn);
            v >>= 8n;
        }
        return bytes;
    }
    if (typeof value === 'string') {
        // Hex strings are big-endian, convert to little-endian for circuit
        const beBytes = hexToBytes(value);
        return beBytes.reverse();
    }
    console.warn('[ASPNonMembershipFetcher] Unknown value type:', typeof value, value);
    return new Uint8Array(32);
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
