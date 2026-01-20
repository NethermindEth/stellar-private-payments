/**
 * Stellar Network Integration for PoolStellar
 * Specialized for Pool, ASP Membership, and ASP Non-Membership contracts
 * @see https://developers.stellar.org/docs/build/guides/dapps/frontend-guide
 */
import { Horizon, rpc, Networks, Address, xdr, scValToNative as sdkScValToNative } from '@stellar/stellar-sdk';

const SUPPORTED_NETWORK = 'testnet';

const NETWORKS = {
    testnet: {
        name: 'Testnet',
        horizonUrl: 'https://horizon-testnet.stellar.org',
        rpcUrl: 'https://soroban-testnet.stellar.org',
        passphrase: Networks.TESTNET,
    },
    futurenet: {
        name: 'Futurenet',
        horizonUrl: 'https://horizon-futurenet.stellar.org',
        rpcUrl: 'https://rpc-futurenet.stellar.org',
        passphrase: Networks.FUTURENET,
    },
    mainnet: {
        name: 'Mainnet',
        horizonUrl: 'https://horizon.stellar.org',
        rpcUrl: 'https://soroban.stellar.org',
        passphrase: Networks.PUBLIC,
    }
};

let deployedContracts = null;

/**
 * Load deployed contract addresses from deployments.json.
 * Must be called before using contract addresses.
 * @returns {Promise<Object>} Deployed contract configuration
 * @throws {Error} If deployments.json cannot be loaded
 */
export async function loadDeployedContracts() {
    if (deployedContracts) {
        return deployedContracts;
    }
    
    const response = await fetch('/deployments.json');
    if (!response.ok) {
        throw new Error(`Failed to load deployments.json: ${response.status}`);
    }
    
    const data = await response.json();
    deployedContracts = {
        network: data.network,
        admin: data.admin,
        pool: data.pool,
        aspMembership: data.asp_membership,
        aspNonMembership: data.asp_non_membership,
        verifier: data.verifier,
    };
    
    if (deployedContracts.network !== SUPPORTED_NETWORK) {
        throw new Error(
            `Deployment network mismatch: expected '${SUPPORTED_NETWORK}', got '${deployedContracts.network}'`
        );
    }
    
    console.log('[Stellar] Loaded contract addresses from deployments.json');
    return deployedContracts;
}

/**
 * Get deployed contract addresses. Returns cached value if already loaded.
 * @returns {Object|null} Deployed contracts or null if not yet loaded
 */
export function getDeployedContracts() {
    return deployedContracts;
}

let currentNetwork = SUPPORTED_NETWORK;
let horizonServer = null;
let sorobanServer = null;

/**
 * Initialize servers for the current network.
 * Network switching is not supported - only testnet is allowed.
 * @returns {Object} Network configuration object
 */
function initializeNetwork() {
    const config = NETWORKS[currentNetwork];
    horizonServer = new Horizon.Server(config.horizonUrl);
    sorobanServer = new rpc.Server(config.rpcUrl);
    console.log(`[Stellar] Connected to ${config.name}`);
    return config;
}

/**
 * Validate that a wallet network matches the supported network.
 * @param {string} walletNetwork - Network name from wallet (e.g., 'TESTNET')
 * @throws {Error} If wallet network doesn't match supported network
 */
export function validateWalletNetwork(walletNetwork) {
    const normalized = walletNetwork?.toLowerCase();
    if (normalized !== SUPPORTED_NETWORK) {
        throw new Error(
            `Network mismatch: app requires '${SUPPORTED_NETWORK}' but wallet is on '${walletNetwork}'. ` +
            `Please switch your wallet to ${SUPPORTED_NETWORK.toUpperCase()}.`
        );
    }
}

/**
 * @returns {Object} Current network configuration with name
 */
export function getNetwork() {
    return { name: currentNetwork, ...NETWORKS[currentNetwork] };
}

/**
 * @returns {Horizon.Server} Horizon server instance
 */
export function getHorizonServer() {
    if (!horizonServer) initializeNetwork();
    return horizonServer;
}

/**
 * @returns {rpc.Server} Soroban RPC server instance
 */
export function getSorobanServer() {
    if (!sorobanServer) initializeNetwork();
    return sorobanServer;
}

/**
 * Test network connectivity by calling Horizon root endpoint.
 * @returns {Promise<{success: boolean, networkPassphrase?: string, error?: string}>}
 */
export async function pingTestnet() {
    try {
        const server = getHorizonServer();
        const response = await server.root();
        console.log('[Stellar] Connected to Horizon:', response.network_passphrase);
        return { success: true, networkPassphrase: response.network_passphrase };
    } catch (error) {
        console.error('[Stellar] Connection failed:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Build a ledger key for reading contract data.
 * @param {string} contractId - Contract address (C...)
 * @param {xdr.ScVal} scValKey - Storage key as ScVal
 * @param {string} durability - 'persistent' or 'temporary'
 * @returns {xdr.LedgerKey}
 */
function buildContractDataKey(contractId, scValKey, durability = 'persistent') {
    const dur = durability === 'temporary'
        ? xdr.ContractDataDurability.temporary()
        : xdr.ContractDataDurability.persistent();
    
    return xdr.LedgerKey.contractData(
        new xdr.LedgerKeyContractData({
            contract: new Address(contractId).toScAddress(),
            key: scValKey,
            durability: dur,
        })
    );
}

/**
 * Create ScVal for enum-style keys matching Soroban contracttype encoding.
 * @param {string} variant - Enum variant name (e.g., 'Admin', 'Root')
 * @param {xdr.ScVal|null} value - Optional tuple value for variants like FilledSubtrees(u32)
 * @returns {xdr.ScVal}
 */
function createEnumKey(variant, value = null) {
    if (value === null) {
        return xdr.ScVal.scvVec([
            xdr.ScVal.scvSymbol(variant)
        ]);
    }
    return xdr.ScVal.scvVec([
        xdr.ScVal.scvSymbol(variant),
        value
    ]);
}

/**
 * @param {number} n
 * @returns {xdr.ScVal}
 */
function u32Val(n) {
    return xdr.ScVal.scvU32(n);
}

/**
 * Read a single ledger entry from a contract.
 * @param {string} contractId - Contract address
 * @param {xdr.ScVal} scValKey - Storage key
 * @param {string} durability - 'persistent' or 'temporary'
 * @returns {Promise<{success: boolean, value?: any, raw?: any, error?: string}>}
 */
async function readLedgerEntry(contractId, scValKey, durability = 'persistent') {
    try {
        const server = getSorobanServer();
        const ledgerKey = buildContractDataKey(contractId, scValKey, durability);
        const result = await server.getLedgerEntries(ledgerKey);
        
        if (result.entries && result.entries.length > 0) {
            const entry = result.entries[0];
            const contractData = entry.val.contractData();
            return {
                success: true,
                value: scValToNative(contractData.val()),
                raw: contractData.val(),
                lastModifiedLedger: entry.lastModifiedLedgerSeq,
                liveUntilLedger: entry.liveUntilLedgerSeq,
            };
        }
        return { success: false, error: 'Entry not found' };
    } catch (error) {
        console.error('[Stellar] readLedgerEntry error:', error);
        return { success: false, error: error.message || String(error) };
    }
}

/**
 * Read ASP Membership contract state.
 * Storage keys: Admin, FilledSubtrees(u32), Zeroes(u32), Levels, NextIndex, Root
 * @param {string} [contractId] - Contract address, defaults to deployed address
 * @returns {Promise<{success: boolean, root?: string, levels?: number, nextIndex?: number, error?: string}>}
 */
export async function readASPMembershipState(contractId) {
    const contracts = getDeployedContracts();
    contractId = contractId ?? contracts?.aspMembership;
    if (!contractId) {
        return { success: false, error: 'Contract address not provided and deployments not loaded' };
    }
    try {
        const results = {
            success: true,
            contractId,
            contractType: 'ASP Membership',
        };

        // Fetch keys in parallel
        const [rootResult, levelsResult, nextIndexResult, adminResult] = await Promise.all([
            readLedgerEntry(contractId, createEnumKey('Root')),
            readLedgerEntry(contractId, createEnumKey('Levels')),
            readLedgerEntry(contractId, createEnumKey('NextIndex')),
            readLedgerEntry(contractId, createEnumKey('Admin')),
        ]);

        if (rootResult.success) {
            results.root = formatU256(rootResult.value);
            results.rootRaw = rootResult.value;
        }
        if (levelsResult.success) results.levels = levelsResult.value;
        if (nextIndexResult.success) results.nextIndex = nextIndexResult.value;
        if (adminResult.success) results.admin = adminResult.value;

        if (results.levels !== undefined) {
            results.capacity = Math.pow(2, results.levels);
            results.usedSlots = results.nextIndex || 0;
        }
        results.success = rootResult.success && levelsResult.success && nextIndexResult.success && adminResult.success;
        return results;
    } catch (error) {
        console.error('[Stellar] Failed to read ASP Membership:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Read ASP Non-Membership contract state (Sparse Merkle Tree).
 * Storage keys: Admin, Root, Node(U256)
 * @param {string} [contractId] - Contract address, defaults to deployed address
 * @returns {Promise<{success: boolean, root?: string, isEmpty?: boolean, error?: string}>}
 */
export async function readASPNonMembershipState(contractId) {
    const contracts = getDeployedContracts();
    contractId = contractId ?? contracts?.aspNonMembership;
    if (!contractId) {
        return { success: false, error: 'Contract address not provided and deployments not loaded' };
    }
    try {
        const results = {
            success: true,
            contractId,
            contractType: 'ASP Non-Membership (Sparse Merkle Tree)',
        };

        const rootResult = await readLedgerEntry(contractId, createEnumKey('Root'));
        if (rootResult.success) {
            results.root = formatU256(rootResult.value);
            results.rootRaw = rootResult.value;
            results.isEmpty = isZeroU256(rootResult.value);
        }

        const adminResult = await readLedgerEntry(contractId, createEnumKey('Admin'));
        if (adminResult.success) {
            results.admin = adminResult.value;
        }
        results.success = rootResult.success && adminResult.success;
        return results;
    } catch (error) {
        console.error('[Stellar] Failed to read ASP Non-Membership:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Read Pool contract state including Merkle tree with history.
 * DataKey: Admin, Token, Verifier, MaximumDepositAmount, Nullifiers, ASPMembership, ASPNonMembership
 * MerkleDataKey: Levels, CurrentRootIndex, NextIndex, FilledSubtree(u32), Zeroes(u32), Root(u32)
 * @param {string} [contractId] - Contract address, defaults to deployed address
 * @returns {Promise<{success: boolean, merkleRoot?: string, merkleLevels?: number, error?: string}>}
 */
export async function readPoolState(contractId) {
    const contracts = getDeployedContracts();
    contractId = contractId ?? contracts?.pool;
    if (!contractId) {
        return { success: false, error: 'Contract address not provided and deployments not loaded' };
    }
    const results = {
        success: true,
        contractId,
        contractType: 'Privacy Pool',
    };
    try {
        // Fetch all independent keys in parallel
        const dataKeys = ['Admin', 'Token', 'Verifier', 'ASPMembership', 'ASPNonMembership'];
        const merkleKeys = ['Levels', 'CurrentRootIndex', 'NextIndex'];

        const [dataResults, merkleResults, maxDepositResult] = await Promise.all([
            // All data keys in parallel
            Promise.all(dataKeys.map(key =>
                readLedgerEntry(contractId, createEnumKey(key))
                    .then(result => ({ key, result }))
            )),
            // All merkle keys in parallel
            Promise.all(merkleKeys.map(key =>
                readLedgerEntry(contractId, createEnumKey(key))
                    .then(result => ({ key, result }))
            )),
            // MaximumDepositAmount
            readLedgerEntry(contractId, createEnumKey('MaximumDepositAmount')),
        ]);

        // Process data keys results
        for (const { key, result } of dataResults) {
            if (result.success) {
                results[key.toLowerCase()] = result.value;
            }
        }

        // Process merkle keys results
        for (const { key, result } of merkleResults) {
            if (result.success) {
                results['merkle' + key] = result.value;
            }
        }

        if (maxDepositResult.success) {
            results.maximumDepositAmount = maxDepositResult.value;
        }

        // Fetch root current root index
        if (results.merkleCurrentRootIndex !== undefined) {
            const rootResult = await readLedgerEntry(
                contractId,
                createEnumKey('Root', u32Val(results.merkleCurrentRootIndex))
            );
            if (rootResult.success) {
                results.merkleRoot = formatU256(rootResult.value);
                results.merkleRootRaw = rootResult.value;
            }
        }

        if (results.merkleLevels !== undefined) {
            results.merkleCapacity = Math.pow(2, results.merkleLevels);
            results.totalCommitments = results.merkleNextIndex || 0;
        }
        
        results.success = dataResults.every(r => r.result.success) && merkleResults.every(r => r.result.success);
        
        return results;
    } catch (error) {
        console.error('[Stellar] Failed to read Pool state:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Read state from all deployed contracts in parallel.
 * Requires loadDeployedContracts() to be called first.
 * @returns {Promise<{success: boolean, pool: Object, aspMembership: Object, aspNonMembership: Object}>}
 */
export async function readAllContractStates() {
    const contracts = getDeployedContracts();
    if (!contracts) {
        return {
            success: false,
            error: 'Deployments not loaded. Call loadDeployedContracts() first.',
            network: currentNetwork,
            timestamp: new Date().toISOString(),
        };
    }
    
    console.log('[Stellar] Reading all contract states...');
    
    const [poolState, membershipState, nonMembershipState] = await Promise.all([
        readPoolState(),
        readASPMembershipState(),
        readASPNonMembershipState(),
    ]);

    return {
        success: poolState.success && membershipState.success && nonMembershipState.success,
        network: currentNetwork,
        timestamp: new Date().toISOString(),
        pool: poolState,
        aspMembership: membershipState,
        aspNonMembership: nonMembershipState,
    };
}

/**
 * Get events from a contract.
 * @param {string} contractId - Contract address
 * @param {Object} options - Query options
 * @param {number} options.startLedger - Starting ledger sequence
 * @param {number} options.limit - Max events to return
 * @param {Array} options.topics - Topic filters
 * @returns {Promise<{success: boolean, events: Array, error?: string}>}
 */
export async function getContractEvents(contractId, options = {}) {
    try {
        const server = getSorobanServer();
        const latestLedger = await server.getLatestLedger();
        
        const result = await server.getEvents({
            startLedger: options.startLedger || Math.max(1, latestLedger.sequence - 2000),
            filters: [{
                type: 'contract',
                contractIds: [contractId],
                topics: options.topics || [],
            }],
            limit: options.limit || 50,
        });

        const events = result.events.map(event => ({
            id: event.id,
            ledger: event.ledger,
            type: event.type,
            contractId: event.contractId,
            topic: event.topic.map(t => scValToNative(t)),
            value: scValToNative(event.value),
        }));

        return { success: true, events, latestLedger: result.latestLedger };
    } catch (error) {
        console.error('[Stellar] Failed to get events:', error);
        return { success: false, error: error.message, events: [] };
    }
}

/**
 * Get Pool contract events (NewCommitment, NewNullifier).
 * @param {number} limit - Max events to return
 * @returns {Promise<{success: boolean, events: Array, error?: string}>}
 */
export async function getPoolEvents(limit = 20) {
    const contracts = getDeployedContracts();
    if (!contracts?.pool) {
        return { success: false, events: [], error: 'Deployments not loaded' };
    }
    return getContractEvents(contracts.pool, { limit });
}

/**
 * Get ASP Membership events (LeafAdded).
 * @param {number} limit - Max events to return
 * @returns {Promise<{success: boolean, events: Array, error?: string}>}
 */
// TODO: Unused for now. Will be used when everything is integrated.
export async function getASPMembershipEvents(limit = 20) {
    const contracts = getDeployedContracts();
    if (!contracts?.aspMembership) {
        return { success: false, events: [], error: 'Deployments not loaded' };
    }
    return getContractEvents(contracts.aspMembership, { limit });
}

/**
 * Get ASP Non-Membership events (LeafInserted, LeafUpdated, LeafDeleted).
 * @param {number} limit - Max events to return
 * @returns {Promise<{success: boolean, events: Array, error?: string}>}
 */
// TODO: Unused for now. Will be used when everything is integrated.
export async function getASPNonMembershipEvents(limit = 20) {
    const contracts = getDeployedContracts();
    if (!contracts?.aspNonMembership) {
        return { success: false, events: [], error: 'Deployments not loaded' };
    }
    return getContractEvents(contracts.aspNonMembership, { limit });
}

/**
 * Get the latest ledger sequence number.
 * @returns {Promise<number>}
 */
export async function getLatestLedger() {
    const server = getSorobanServer();
    const result = await server.getLatestLedger();
    return result.sequence;
}

/**
 * Fetch all events from a contract with pagination.
 * Handles cursor-based pagination to retrieve events beyond a single page.
 * 
 * Memory behavior:
 * - If `onPage` callback is provided, events are NOT accumulated in memory.
 *   Use this for large datasets where memory is a concern.
 * - If `onPage` is NOT provided, all events are returned in the `events` array.
 * 
 * @param {string} contractId - Contract address
 * @param {Object} options - Query options
 * @param {number} options.startLedger - Starting ledger sequence
 * @param {string} [options.cursor] - Pagination cursor (for resuming)
 * @param {number} [options.pageSize=100] - Events per page
 * @param {function} [options.onPage] - Callback for each page: (events, cursor) => void
 * @returns {Promise<{success: boolean, events: Array, cursor?: string, latestLedger: number, count: number, error?: string}>}
 */
export async function fetchAllContractEvents(contractId, options = {}) {
    const { startLedger, cursor: initialCursor, pageSize = 100, onPage } = options;

    if (!startLedger && !initialCursor) {
        return { success: false, events: [], error: 'startLedger or cursor required' };
    }

    try {
        const server = getSorobanServer();
        // Only accumulate events if no callback is provided (for backward compat)
        const allEvents = onPage ? null : [];
        let cursor = initialCursor;
        let latestLedger = 0;
        let totalCount = 0;

        // eslint-disable-next-line no-constant-condition
        while (true) {
            const requestParams = {
                filters: [{
                    type: 'contract',
                    contractIds: [contractId],
                }],
                limit: pageSize,
            };

            if (cursor) {
                requestParams.cursor = cursor;
            } else {
                requestParams.startLedger = startLedger;
            }

            const result = await server.getEvents(requestParams);
            latestLedger = result.latestLedger;

            const pageEvents = result.events.map(event => ({
                id: event.id,
                ledger: event.ledger,
                type: event.type,
                contractId: event.contractId,
                topic: event.topic.map(t => scValToNative(t)),
                value: scValToNative(event.value),
            }));

            if (pageEvents.length > 0) {
                totalCount += pageEvents.length;
                cursor = pageEvents[pageEvents.length - 1].id;
                
                if (onPage) {
                    // Stream mode: process and discard
                    onPage(pageEvents, cursor);
                } else {
                    // Batch mode: accumulate for return
                    allEvents.push(...pageEvents);
                }
            }

            if (result.events.length < pageSize) {
                break;
            }
        }

        return { 
            success: true, 
            events: allEvents || [], 
            cursor, 
            latestLedger,
            count: totalCount,
        };
    } catch (error) {
        console.error('[Stellar] Failed to fetch all events:', error);
        return { success: false, error: error.message, events: [], count: 0 };
    }
}

/**
 * Fetch Pool events with pagination.
 * @param {Object} options - Query options
 * @param {number} options.startLedger - Starting ledger sequence
 * @param {string} [options.cursor] - Pagination cursor
 * @param {function} [options.onPage] - Callback for each page
 * @returns {Promise<{success: boolean, events: Array, cursor?: string, latestLedger: number, error?: string}>}
 */
export async function fetchAllPoolEvents(options = {}) {
    const contracts = getDeployedContracts();
    if (!contracts?.pool) {
        return { success: false, events: [], error: 'Deployments not loaded' };
    }
    return fetchAllContractEvents(contracts.pool, options);
}

/**
 * Fetch ASP Membership events with pagination.
 * @param {Object} options - Query options
 * @param {number} options.startLedger - Starting ledger sequence
 * @param {string} [options.cursor] - Pagination cursor
 * @param {function} [options.onPage] - Callback for each page
 * @returns {Promise<{success: boolean, events: Array, cursor?: string, latestLedger: number, error?: string}>}
 */
export async function fetchAllASPMembershipEvents(options = {}) {
    const contracts = getDeployedContracts();
    if (!contracts?.aspMembership) {
        return { success: false, events: [], error: 'Deployments not loaded' };
    }
    return fetchAllContractEvents(contracts.aspMembership, options);
}

/**
 * Convert ScVal to native JavaScript types.
 * 
 * Return types vary based on the ScVal type and match the SDK for compatibility.
 *
 * 
 * @param {xdr.ScVal} scVal - Stellar ScVal
 * @returns {null|boolean|number|string|Array|Object} Native JS value
 * @throws {Error} If scVal is invalid
 */
export function scValToNative(scVal) {
    if (!scVal || typeof scVal.switch !== 'function') {
        throw new Error('Invalid ScVal');
    }
    try {
        return sdkScValToNative(scVal);
    } catch (sdkError) {
        console.warn('[Stellar] SDK scValToNative failed, using fallback:', sdkError);
        // Fallback for types the SDK cannot handle directly
        const type = scVal.switch().name;
        switch (type) {
            case 'scvVoid': return null;
            case 'scvBool': return scVal.b();
            case 'scvU32': return scVal.u32();
            case 'scvI32': return scVal.i32();
            case 'scvU64': return scVal.u64().toString();
            case 'scvI64': return scVal.i64().toString();
            case 'scvU128': return formatU128(scVal.u128());
            case 'scvI128': return scVal.i128().toString();
            case 'scvU256': return formatU256Raw(scVal.u256());
            case 'scvI256': return scVal.i256().toString();
            case 'scvBytes': return scVal.bytes().toString('hex');
            case 'scvString': return scVal.str().toString();
            case 'scvSymbol': return scVal.sym().toString();
            case 'scvAddress': return Address.fromScAddress(scVal.address()).toString();
            case 'scvVec': return scVal.vec().map(v => scValToNative(v));
            case 'scvMap': {
                const map = {};
                for (const entry of scVal.map()) {
                    map[scValToNative(entry.key())] = scValToNative(entry.val());
                }
                return map;
            }
            default: return `[${type}]`;
        }
    }
}

/**
 * Format U256 value to hex string.
 * @param {any} value - U256 value (bigint, string, or object)
 * @returns {string} Hex string representation
 */
function formatU256(value) {
    if (typeof value === 'string') return value;
    if (typeof value === 'bigint') return '0x' + value.toString(16).padStart(64, '0');
    if (typeof value === 'object' && value !== null) {
        try {
            return JSON.stringify(value);
        } catch (error) {
            console.warn('[Stellar] Failed to stringify U256 object:', error);
            return String(value);
        }
    }
    return String(value);
}

/**
 * Format raw U256 XDR type (4 x u64: hi_hi, hi_lo, lo_hi, lo_lo).
 * @param {Object} u256Xdr - XDR U256 object
 * @returns {string} Hex string
 */
function formatU256Raw(u256Xdr) {
    try {
        const hiHi = BigInt(u256Xdr.hiHi().toString());
        const hiLo = BigInt(u256Xdr.hiLo().toString());
        const loHi = BigInt(u256Xdr.loHi().toString());
        const loLo = BigInt(u256Xdr.loLo().toString());
        
        const value = (hiHi << 192n) | (hiLo << 128n) | (loHi << 64n) | loLo;
        return '0x' + value.toString(16).padStart(64, '0');
    } catch (error) {
        console.warn('[Stellar] Failed to stringify U256 raw object:', error);
        return '[U256]';
    }
}

/**
 * Format U128 XDR type (2 x u64: hi, lo).
 * @param {Object} u128Xdr - XDR U128 object
 * @returns {string} Decimal string
 */
function formatU128(u128Xdr) {
    try {
        const hi = BigInt(u128Xdr.hi().toString());
        const lo = BigInt(u128Xdr.lo().toString());
        return ((hi << 64n) | lo).toString();
    } catch (error) {
        console.warn('[Stellar] Failed to stringify U128 object:', error);
        return '[U128]';
    }
}

/**
 * Check if U256 value is zero.
 * @param {any} value - U256 value
 * @returns {boolean}
 */ 
function isZeroU256(value) {
    if (typeof value === 'string') {
        return value === '0' || value === '0x' + '0'.repeat(64);
    }
    if (typeof value === 'bigint') return value === 0n;
    if (typeof value === 'number') return value === 0;
    return false;
}

/**
 * Truncate address for display.
 * @param {string} address - Full address
 * @param {number} startChars - Chars to show at start
 * @param {number} endChars - Chars to show at end
 * @returns {string} Truncated address
 */
export function formatAddress(address, startChars = 4, endChars = 4) {
    if (!address) return '';
    if (address.length <= startChars + endChars + 3) return address;
    return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
}

initializeNetwork();

export { NETWORKS, SUPPORTED_NETWORK };
