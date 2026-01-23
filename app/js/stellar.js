/**
 * Stellar Network Integration for PoolStellar
 * Specialized for Pool, ASP Membership, and ASP Non-Membership contracts
 * @see https://developers.stellar.org/docs/build/guides/dapps/frontend-guide
 */
import { Horizon, rpc, Networks, Address, xdr, scValToNative as sdkScValToNative, contract, ScInt } from '@stellar/stellar-sdk';

const SUPPORTED_NETWORK = 'testnet';

const NETWORKS = {
    testnet: {
        name: 'Testnet',
        horizonUrl: 'https://horizon-testnet.stellar.org',
        rpcUrl: 'https://stellar.liquify.com/api=41EEWAH79Y5OCGI7/testnet',
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

// Pool contract client cache
let poolClient = null;

/**
 * Creates a signer object compatible with the Stellar SDK contract client.
 * Uses Freighter wallet for signing transactions and auth entries.
 *
 * @param {string} publicKey - User's Stellar public key
 * @param {string} networkPassphrase - Network passphrase for signing
 * @param {function} signTransaction - Function to sign transactions (from wallet.js)
 * @param {function} signAuthEntry - Function to sign auth entries (from wallet.js)
 * @returns {Object} Signer object with signTransaction and signAuthEntry methods
 */
export function createFreighterSigner(publicKey, networkPassphrase, signTransaction, signAuthEntry) {
    return {
        signTransaction: async (transactionXdr, opts = {}) => {
            // SDK expects { signedTxXdr, signerAddress } object, not just the XDR string
            return signTransaction(transactionXdr, {
                networkPassphrase,
                address: publicKey,
                ...opts,
            });
        },
        signAuthEntry: async (entryXdr, opts = {}) => {
            // SDK expects { signedAuthEntry } object
            return signAuthEntry(entryXdr, {
                networkPassphrase,
                address: publicKey,
                ...opts,
            });
        },
    };
}

/**
 * Get or create the Pool contract client.
 * Uses the contract spec from on-chain to build the client dynamically.
 *
 * @param {Object} signerOptions - Options for creating the signer
 * @param {string} signerOptions.publicKey - User's Stellar public key
 * @param {function} signerOptions.signTransaction - Function to sign transactions
 * @param {function} signerOptions.signAuthEntry - Function to sign auth entries
 * @param {boolean} [forceRefresh=false] - Force creation of new client
 * @returns {Promise<contract.Client>} Pool contract client
 */
export async function getPoolClient(signerOptions, forceRefresh = false) {
    const contracts = getDeployedContracts();
    if (!contracts?.pool) {
        throw new Error('Deployments not loaded. Call loadDeployedContracts() first.');
    }

    const network = getNetwork();

    // Return cached client if available and not forcing refresh
    if (poolClient && !forceRefresh) {
        return poolClient;
    }

    const signer = createFreighterSigner(
        signerOptions.publicKey,
        network.passphrase,
        signerOptions.signTransaction,
        signerOptions.signAuthEntry
    );

    console.log('[Stellar] Loading Pool contract client from RPC...');
    poolClient = await contract.Client.from({
        contractId: contracts.pool,
        rpcUrl: network.rpcUrl,
        networkPassphrase: network.passphrase,
        publicKey: signerOptions.publicKey,
        signTransaction: signer.signTransaction,
        signAuthEntry: signer.signAuthEntry,
    });

    console.log('[Stellar] Pool contract client ready');
    return poolClient;
}

/**
 * Converts various types to Uint8Array for Soroban contract calls.
 * Handles Uint8Array, ArrayBuffer, and array-like objects.
 *
 * @param {Uint8Array|ArrayBuffer|Array<number>} value - Value to convert
 * @returns {Uint8Array} Value as Uint8Array
 */
function toBytes(value) {
    if (value instanceof Uint8Array) {
        return value;
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }
    if (Array.isArray(value)) {
        return new Uint8Array(value);
    }
    // Handle objects with buffer-like properties
    if (value && typeof value === 'object' && 'length' in value) {
        return new Uint8Array(Array.from(value));
    }
    throw new Error(`Cannot convert ${typeof value} to Uint8Array`);
}

/**
 * Convert a BigInt to a U256 compatible object for Soroban.
 *
 * @param {bigint} value - BigInt value to convert
 * @returns {bigint} Value as BigInt (SDK handles conversion)
 */
function toU256(value) {
    // The SDK contract client handles BigInt -> U256 conversion
    return value;
}

/**
 * Convert a BigInt to an I256 ScVal for Soroban.
 * Uses ScInt which properly handles negative values via two's complement.
 *
 * @param {bigint} value - BigInt value (can be negative for withdrawals)
 * @returns {xdr.ScVal} I256 ScVal
 */
function toI256(value) {
    return new ScInt(value, { type: 'i256' }).toScVal();
}

/**
 * Submit a transact call to the Pool contract.
 *
 * @param {Object} params
 * @param {Object} params.proof - Proof data from transaction builder
 * @param {Object} params.proof.proof - Groth16 proof { a: Uint8Array(64), b: Uint8Array(128), c: Uint8Array(64) }
 * @param {bigint} params.proof.root - Pool merkle root
 * @param {bigint[]} params.proof.input_nullifiers - Input nullifiers
 * @param {bigint} params.proof.output_commitment0 - First output commitment
 * @param {bigint} params.proof.output_commitment1 - Second output commitment
 * @param {bigint} params.proof.public_amount - Public amount (deposit positive, withdraw negative)
 * @param {Uint8Array} params.proof.ext_data_hash - 32-byte ext data hash
 * @param {bigint} params.proof.asp_membership_root - ASP membership root
 * @param {bigint} params.proof.asp_non_membership_root - ASP non-membership root
 * @param {Object} params.extData - External data
 * @param {string} params.extData.recipient - Recipient address
 * @param {bigint} params.extData.ext_amount - External amount
 * @param {bigint} [params.extData.fee=0n] - Relayer fee
 * @param {Uint8Array} params.extData.encrypted_output0 - Encrypted output 0
 * @param {Uint8Array} params.extData.encrypted_output1 - Encrypted output 1
 * @param {string} params.sender - Sender address (must match signer)
 * @param {Object} params.signerOptions - Signer options for getPoolClient
 * @returns {Promise<{success: boolean, txHash?: string, error?: string}>}
 */
export async function submitPoolTransaction(params) {
    const { proof, extData, sender, signerOptions } = params;

    try {
        console.log('[Stellar] Preparing pool transaction...');

        // Get pool client with signer
        const client = await getPoolClient(signerOptions);

        // Format proof for contract. Ensure Uint8Array for byte fields
        const contractProof = {
            proof: {
                a: toBytes(proof.proof.a),
                b: toBytes(proof.proof.b),
                c: toBytes(proof.proof.c),
            },
            root: toU256(proof.root),
            input_nullifiers: proof.input_nullifiers.map(n => toU256(n)),
            output_commitment0: toU256(proof.output_commitment0),
            output_commitment1: toU256(proof.output_commitment1),
            public_amount: toU256(proof.public_amount),
            ext_data_hash: toBytes(proof.ext_data_hash),
            asp_membership_root: toU256(proof.asp_membership_root),
            asp_non_membership_root: toU256(proof.asp_non_membership_root),
        };

        // Format ext_data for contract (must match ExtData struct in pool.rs)
        // Use ScInt for I256 which handles negative values via two's complement
        const contractExtData = {
            encrypted_output0: toBytes(extData.encrypted_output0),
            encrypted_output1: toBytes(extData.encrypted_output1),
            ext_amount: new ScInt(extData.ext_amount, { type: 'i256' }).toScVal(),
            recipient: extData.recipient,
        };

        console.log('[Stellar] Calling transact...', {
            proof: { root: proof.root.toString(16) },
            ext_amount: extData.ext_amount.toString(),
        });
        
        // Debug: log all fields to find undefined values
        console.log('[Stellar] contractProof fields:', {
            proof_a: contractProof.proof?.a?.length,
            proof_b: contractProof.proof?.b?.length,
            proof_c: contractProof.proof?.c?.length,
            root: typeof contractProof.root,
            input_nullifiers: contractProof.input_nullifiers?.length,
            output_commitment0: typeof contractProof.output_commitment0,
            output_commitment1: typeof contractProof.output_commitment1,
            public_amount: typeof contractProof.public_amount,
            ext_data_hash: contractProof.ext_data_hash?.length,
            asp_membership_root: typeof contractProof.asp_membership_root,
            asp_non_membership_root: typeof contractProof.asp_non_membership_root,
        });
        console.log('[Stellar] contractExtData fields:', {
            encrypted_output0: contractExtData.encrypted_output0?.length,
            encrypted_output1: contractExtData.encrypted_output1?.length,
            ext_amount: contractExtData.ext_amount?.switch?.()?.name,
            recipient: contractExtData.recipient,
        });

        // Build the transaction (this will simulate)
        let tx;
        try {
            tx = await client.transact({
                proof: contractProof,
                ext_data: contractExtData,
                sender,
            });
            console.log('[Stellar] Transaction built successfully');
        } catch (buildError) {
            console.error('[Stellar] Transaction build error:', buildError);
            
            // Check if simulation failed
            const errorMsg = String(buildError?.message || '');
            if (errorMsg.includes('simulation') || errorMsg.includes('Simulation')) {
                throw new Error(`Transaction simulation failed: ${errorMsg}`);
            }
            throw buildError;
        }

        console.log('[Stellar] Signing and sending transaction...');
        
        // Use simple signAndSend like the working code
        const sent = await tx.signAndSend();
        const txHash = sent.sendTransactionResponse?.hash;
        
        console.log('[Stellar] Transaction submitted successfully:', txHash);

        return {
            success: true,
            txHash,
        };
    } catch (error) {
        console.error('[Stellar] Transaction submission failed:', error);
        
        // Check if this is a parsing error that might have happened after submission
        const errorMsg = String(error?.message || '');
        if (errorMsg.includes('switch') || errorMsg.includes('Cannot read properties')) {
            console.warn('[Stellar] SDK parsing error - transaction status uncertain');
            return {
                success: false,
                error: 'SDK parsing error - check Stellar Expert for transaction status',
                warning: errorMsg,
            };
        }
        
        return {
            success: false,
            error: error.message || String(error),
        };
    }
}

/**
 * Submit a deposit transaction to the Pool contract.
 * Convenience wrapper around submitPoolTransaction for deposits.
 *
 * @param {Object} proofResult - Result from generateDepositProof()
 * @param {Object} signerOptions - Signer options (publicKey, signTransaction, signAuthEntry)
 * @returns {Promise<{success: boolean, txHash?: string, error?: string}>}
 */
export async function submitDeposit(proofResult, signerOptions) {
    return submitPoolTransaction({
        proof: proofResult.sorobanProof,
        extData: proofResult.extData,
        sender: signerOptions.publicKey,
        signerOptions,
    });
}

/**
 * Register a public key on the Pool contract for address book discovery.
 * This allows other users to find your public key for sending you transfers.
 *
 * @param {Object} params
 * @param {string} params.owner - Owner's Stellar address
 * @param {Uint8Array} params.publicKey - Public key bytes (32 bytes)
 * @param {Object} params.signerOptions - Signer options for getPoolClient
 * @returns {Promise<{success: boolean, txHash?: string, error?: string}>}
 */
export async function registerPublicKey(params) {
    const { owner, publicKey, signerOptions } = params;

    try {
        console.log('[Stellar] Registering public key...');

        const client = await getPoolClient(signerOptions);

        // Format account data for contract
        const account = {
            owner,
            public_key: toBytes(publicKey),
        };

        console.log('[Stellar] Calling register...', {
            owner: owner.slice(0, 8) + '...',
            publicKeyLength: publicKey.length,
        });

        // Build and send the transaction
        const tx = await client.register({ account });
        const sent = await tx.signAndSend();
        const txHash = sent.sendTransactionResponse?.hash;

        console.log('[Stellar] Registration submitted:', txHash);

        return {
            success: true,
            txHash,
        };
    } catch (error) {
        console.error('[Stellar] Registration failed:', error);
        return {
            success: false,
            error: error.message || String(error),
        };
    }
}

export { NETWORKS, SUPPORTED_NETWORK };