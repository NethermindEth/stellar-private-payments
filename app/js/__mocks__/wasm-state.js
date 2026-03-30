// Mock for ./wasm-state/state.js (Rust WASM StateManager)
// Used by Jest since the real module is a wasm-pack build artifact.

const initStateWasm = async () => {};

class StateManager {
    // Pool
    process_pool_events() { return '{"commitments":0,"nullifiers":0}'; }
    process_new_commitment() {}
    process_new_nullifier() {}
    get_pool_root() { return new Uint8Array(32); }
    get_pool_root_hex() { return '0x' + '00'.repeat(32); }
    get_pool_merkle_proof() { return { path_elements: new Uint8Array(0), path_indices: 0, root: new Uint8Array(32) }; }
    is_nullifier_spent() { return false; }
    get_pool_next_index() { return 0; }
    get_pool_leaf_count() { return 0; }
    rebuild_pool_tree() { return 0; }
    get_encrypted_outputs() { return '[]'; }
    clear_pool() {}

    // ASP Membership
    process_asp_membership_events() { return 0; }
    process_asp_leaf_added() {}
    get_asp_membership_root() { return new Uint8Array(32); }
    get_asp_membership_root_hex() { return '0x' + '00'.repeat(32); }
    get_asp_membership_proof() { return { path_elements: new Uint8Array(0), path_indices: 0, root: new Uint8Array(32) }; }
    find_asp_membership_leaf() { return 'null'; }
    get_asp_membership_leaf_count() { return 0; }
    get_asp_membership_next_index() { return 0; }
    rebuild_asp_membership_tree() { return 0; }
    clear_asp_membership() {}

    // Notes
    save_note(json) { const n = JSON.parse(json); return JSON.stringify({ id: n.commitment, ...n }); }
    mark_note_spent() { return false; }
    get_note_by_commitment() { return 'null'; }
    get_notes_by_owner() { return '[]'; }
    get_unspent_notes() { return '[]'; }
    get_balance() { return '0'; }
    get_all_notes() { return '[]'; }
    delete_note() {}
    clear_notes() {}

    // Public Keys
    store_public_key() {}
    get_public_key_by_address() { return 'null'; }
    get_all_public_keys() { return '[]'; }
    get_public_key_count() { return 0; }
    clear_public_keys() {}

    // Note Scanner
    scan_for_notes() { return '{"scanned":0,"found":0,"alreadyKnown":0}'; }
    check_spent_notes() { return '{"checked":0,"markedSpent":0}'; }
    derive_nullifier() { return '0x' + '00'.repeat(32); }

    // Sync Metadata
    get_sync_metadata() { return 'null'; }
    put_sync_metadata() {}
    delete_sync_metadata() {}

    // Retention Config
    get_retention_config() { return 'null'; }
    put_retention_config() {}

    // Utilities
    hex_to_bytes() { return new Uint8Array(0); }
    bytes_to_hex() { return '0x'; }
    field_to_hex() { return '0x' + '00'.repeat(32); }
    hex_to_bytes_for_tree() { return new Uint8Array(0); }
    ledgers_to_duration() { return '0m'; }

    // Housekeeping
    clear_all() {}
}

module.exports = {
    __esModule: true,
    default: initStateWasm,
    StateManager,
};
