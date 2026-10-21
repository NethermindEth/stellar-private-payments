# Wallet support

SPP supports the Freighter browser extension because it provides the signing operations the app needs and has been tested through the full payment flow. The app also relies on Freighter for connection permissions, account changes and network information. Supporting another wallet means checking its signing behavior and replacing those app-level calls with the equivalent for that provider.

The contracts don't depend on Freighter. The SDK accepts other signers through its [`WalletSigner` interface](https://github.com/NethermindEth/stellar-private-payments/blob/13f2374f4a7ae5b7871caba248763d92fb7c642a/sdk/web/js/types/signer.d.ts), so a compatible wallet can be added through an adapter. The difficulty is deciding whether it is compatible: support for Stellar transactions alone doesn't cover everything SPP asks a wallet to do.

These findings reflect wallet support as of October 2026. Freighter is the only wallet tested end-to-end with SPP; the other findings come from source code and vendor documentation.

**Signing requirements**

SPP needs a `G…` Ed25519 account and three operations: `signMessage`, `signAuthEntry` and `signTransaction`. Where a transaction requires separate Soroban authorization signatures, SPP collects and inserts them before asking the wallet to sign the transaction envelope. Throughout that process, the adapter must keep the requested account and network and return signatures in the format SPP expects.

Message signing has two further jobs beyond transaction approval: deriving the keys that encrypt and spend shielded notes, and unwrapping the key that encrypts local SQLite storage. Each job uses its own signing domain, and both require the wallet to follow [SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md) by signing `SHA256("Stellar Signed Message:\n" + UTF8(message))` with the owner's key. Another authorized signer on the Stellar account cannot substitute for that key.

Because both paths depend on the signature bytes themselves, signing must be deterministic. When enrolling local storage, SPP checks same-device reproducibility by requesting two signatures over the storage-unlock message and verifying they match before sealing the random database key; later unlocks must produce the same signature to unwrap it. Cross-device recovery is stricter still: if a wallet produces different signature bytes after the user restores their Stellar account on a new machine, key derivation yields different privacy keys and the user loses access to existing notes unless the original privacy keys were backed up. SPP cannot test cross-device reproducibility at runtime, so each wallet needs to be checked for it separately.

[SEP-43](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0043.md) describes a common wallet interface, though implementations still differ in authorization payloads, response formats and network support. Encoding is one practical example: SPP's current decoder can interpret an unprefixed hex signature as base64. An adapter can avoid that ambiguity by explicitly returning base64.

The owner-signature requirement excludes `C…` contract accounts, including passkey smart accounts, from the current flow. A passkey that unlocks a normal `G…` account may work; its signing behavior still needs checking.

**Other wallets**

Several wallets expose the required methods, but a method in an adapter can simply forward a call that the wallet doesn't implement. OneKey is an example: the kit exposes auth signing, while the inspected provider throws `NotImplemented`. The table distinguishes those cases from integrations that still need testing.

| Wallet or route | Findings |
|---|---|
| Ledger through Freighter or directly | Source exposes transaction, message and Soroban authorization signing. Released device/software combinations need testing. Direct integration would also need transport, account selection and device-version handling. |
| Scopuly, Hana, Klever | Scopuly documents the required methods; the kit forwards them for Hana and Klever. Each has an injected provider. Exact signing behavior and recovery have not been tested with SPP. |
| MetaMask | The Stellar adapter exposes all three methods, but the inspected implementation selects mainnet sessions. SPP's default deployment uses testnet. |
| Freighter Mobile | Source documents message and auth signing through WalletConnect. Released-app behavior and the applicable WalletConnect terms need confirmation. |
| HOT Wallet, D’CENT | Adapter methods exist, but signing behavior and recovery need verification. The license grant for HOT's SDK is unresolved. |
| OneKey | Auth signing is unimplemented in the inspected provider. |
| Trezor | Firmware supports Soroban authorization signing, but uses an address-bound preimage that differs from SPP's current format. A complete SEP-53 message-signing route is not established. |
| Albedo, LOBSTR, xBull, Rabet, Bitget, Fordefi | At least one required operation is missing from the inspected API or kit module. Separate vendor APIs may differ. |
| GhostSig, CactusLink | Not assessed sufficiently to establish compatibility. |

These differences are visible in [Freighter's Ledger code](https://github.com/stellar/freighter/blob/master/extension/src/popup/helpers/hardwareConnect.ts), [MetaMask's adapter](https://github.com/MetaMask/connect-stellar/blob/ab53f92e958f89ed690d8cf2f83e3bbfc34f57e0/src/adapter.ts), [OneKey's provider](https://github.com/OneKeyHQ/app-monorepo/blob/8fc0adc44f165e3f0d94e6fd77934f97cfcf6203/packages/kit-bg/src/providers/ProviderApiStellar.ts) and [Trezor's auth implementation](https://github.com/trezor/trezor-firmware/blob/6ab39e95cf45d4b25b3f677806012ac660ae7a51/core/src/apps/stellar/sign_soroban_authorization.py). The reverse situation is possible too: a stub in the kit doesn't establish that the device or another vendor API lacks the operation.

**Stellar Wallets Kit and licensing**

Stellar Wallets Kit supplies a wallet picker and a common API. It can reduce adapter work, but it cannot fill in signing operations missing from a wallet. The earlier integration in [PR #293](https://github.com/NethermindEth/stellar-private-payments/pull/293) was closed because of dependency licensing and integration complexity. Some of the wallets also lacked operations SPP requires.

The kit itself is MIT-licensed. Its assessed dependency list includes xBull's AGPL connector, Reown and WalletConnect components with community-license terms, and the HOT SDK without an established license grant. Those dependencies need attention because SPP's distribution policy requires permissive bundled code. Selective imports can exclude unused code from the browser bundle, but the packages remain in the installed dependency graph. Their presence alone doesn't relicense SPP; what is combined and distributed still needs examination.

SPP could instead use standalone libraries, write adapters for injected providers, or maintain selected MIT-licensed kit code with fewer dependencies. The assessed Freighter and Ledger client libraries are Apache-2.0, and MetaMask's Stellar adapter is ISC. Calling an injected provider does not bundle the wallet, so its own license is separate from that of the adapter SPP uses. Mobile and hosted-wallet connections also have service terms to check.

**Institutional and deployer-provided wallets**

With Fireblocks, a deployer could offer wallets inside its application. The integration depends on who is expected to sign: the deployer, the user, or a backend acting with the user's permission. Fireblocks offers Direct Custody and legacy Embedded Wallets, and now presents [Dynamic as its embedded-wallet offering](https://developers.fireblocks.com/docs/dynamic-embedded-wallets).

| Model | How it would fit SPP |
|---|---|
| Direct Custody | The deployer assigns wallets to users and controls signing through its workspace and approval rules. A backend must authorize each user's access to the assigned wallet. |
| Embedded wallets | Users create wallets inside the app and participate in signing from their device. The app needs login, recovery and an SPP signing adapter. |
| Delegated embedded wallets | Users authorize backend operations. The Stellar interface, delegation permissions and production terms need confirmation. |
| Funding or fee payment only | Fireblocks signs transactions or supplies deposit funds while users retain their SPP privacy keys. The SDK already separates note ownership from the signer/payer. |

Fireblocks documents [RAW Ed25519 signing for vaults and embedded wallets](https://developers.fireblocks.com/reference/structure-the-api-call). An adapter could send the hashes for SPP's message, authorization and transaction signing, leaving SPP to construct, simulate and submit the transactions. Production RAW signing requires paid enablement, use-case eligibility and policy configuration. Dynamic exposes Stellar message and transaction signing, but its inspected connector has no dedicated `signAuthEntry`; the lower-level raw-signing interface would need testing for that operation.

For key derivation, the adapter would request the owner's SEP-53 signature of SPP's key derivation message, and the SDK would derive the note and encryption keys from that signature using SHA-256 with separate domain prefixes.

Recovery and storage unlocking need a separate decision. Fireblocks protects the Stellar signing key, whereas SPP's privacy keys control the shielded notes and wallet-wrapped storage relies on reproducible SEP-53 signatures to unwrap the local database key. Because MPC signing cannot be assumed to return identical signature bytes across calls, an integration with a non-deterministic signer would need another way to supply the storage key alongside a way to preserve the original derivation signature or back up the derived privacy keys. An independent privacy seed is another option; it would require SDK and app changes, though not a new proof system. Fireblocks documents [signature caching](https://developers.fireblocks.com/reference/caching-signatures), but its guarantees across sessions and recovery would need confirmation before SPP relied on it.

Who receives the signature matters as much as who holds the Stellar key. Anyone with the derivation signature can reproduce the privacy keys; a deployer holding those keys can access and spend shielded funds. Freezing the Fireblocks account doesn't necessarily prevent a holder of the note secret from spending through another payer, provided the pool's conditions are met. The SDK's [owner/payer separation](https://github.com/NethermindEth/stellar-private-payments/blob/13f2374f4a7ae5b7871caba248763d92fb7c642a/sdk/native/src/client.rs) allows that. If every private spend must require Fireblocks approval, a signing adapter alone will not enforce it.

The product's exit procedure also needs checking. Legacy embedded wallets list Stellar as [unsupported for key takeover](https://ncw-developers.fireblocks.com/docs/supported-networks), and the documented [migration to Dynamic](https://www.dynamic.xyz/docs/embedded-wallets/mpc/migrate-from-fireblocks) covers EVM and Solana, not Stellar. SDK licensing and service costs depend on the selected product. Using one shared Stellar account would introduce a further requirement: separate privacy identities or an internal ledger, because different user memos do not produce different SPP keys.

**Implementation scope**

If there is interest in proceeding, external-wallet support can be scoped separately from deployer-provided accounts. For an external wallet, the work would cover connection and signing, account/network changes and encoding, followed by tests of deposits, transfers, withdrawals and recovery. Freighter-specific app calls would move behind a provider interface, and each deployment could enable the wallets it needs.

A Fireblocks or Dynamic integration would also need account provisioning and a chosen custody and recovery model. Depending on that model, the work could include a backend, request validation and approval handling, as well as recovery of SPP privacy keys. Approval delays can invalidate prepared authorization or proof data, so retries must handle those cases. Production access, licensing and recurring charges would need confirmation alongside the technical work.

A proof of concept with a selected wallet could establish whether signing and recovery work before estimating the full integration. That estimate would then depend on the platforms and account model being supported, without requiring implementation of every wallet listed here.
