import { Address, rpc, scValToNative, xdr } from '@stellar/stellar-sdk';

/** Read public contract state directly; never opens the local database. */
export async function lookupPublicIdentity({ address, rpcUrl, registry }, server = new rpc.Server(rpcUrl, { timeout: 10_000 })) {
    const key = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
        contract: new Address(registry).toScAddress(),
        key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Registration'), new Address(address).toScVal()]),
        durability: xdr.ContractDataDurability.persistent,
    }));
    const response = await server.getLedgerEntries(key);
    // Missing live state can also mean archived registration. Do not claim the
    // account has never registered based on a missing ledger entry.
    if (!response.entries.length) return { status: 'not-found' };
    const value = scValToNative(response.entries[0].val.value.val);
    const hex = bytes => {
        if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('Invalid public registry key.');
        return '0x' + Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    };
    return { status: 'registered', notePublicKey: hex(value.note_key), encryptionPublicKey: hex(value.encryption_key) };
}
