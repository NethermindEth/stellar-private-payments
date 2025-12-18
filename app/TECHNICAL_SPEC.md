# PoolStellar Compliant Private System - Frontend Technical Specification

## Overview

A privacy-preserving transaction interface for the Stellar blockchain, enabling users to deposit, withdraw, and perform private transfers using zero-knowledge proofs.

---

## UI Element Inventory

### 1. Global Header

| Element | Type | Description |
|---------|------|-------------|
| Logo | Image/Icon | Application logo (shield/lock icon) |
| Title | Text | "PoolStellar Compliant Private System" |
| Network Indicator | Badge | Shows current network (e.g., "Testnet") |
| Wallet Button | Button | "Freighter Wallet" - connects/shows wallet status |

### 2. Main Navigation Tabs

| Tab | ID | Description |
|-----|-----|-------------|
| Deposit | `tab-deposit` | Deposit funds into the privacy pool |
| Withdraw | `tab-withdraw` | Withdraw funds using a note |
| Transact (advanced) | `tab-transact` | Advanced split/combine operations |

### 3. Deposit Tab Panel

| Element | Type | ID | Description |
|---------|------|-----|-------------|
| XLM Amount Slider | Range Input | `deposit-slider` | Visual amount selector (0-100) |
| XLM Amount Number | Number Input | `deposit-amount` | Precise amount entry with spinner |
| Deposit Button | Button | `btn-deposit` | Executes deposit transaction |
| Note ID Display | Text Field | `deposit-note-id` | Shows generated hex note ID (readonly) |
| Copy Note ID Button | Button | `btn-copy-note` | Copies note ID to clipboard |
| Download Note Button | Button | `btn-download-note` | Downloads note as file |

### 4. Withdraw Tab Panel

| Element | Type | ID | Description |
|---------|------|-----|-------------|
| Note ID Input | Text Input + File | `withdraw-note-input` | Paste or upload note ID |
| Add Note Button | Button | `btn-add-withdraw-note` | Add additional note input (+ icon) |
| Recipient Address | Text Input | `withdraw-recipient` | Stellar address for withdrawal |
| Withdraw Button | Button | `btn-withdraw` | Executes withdrawal transaction |

### 5. Transact (Advanced) Tab Panel

| Element | Type | ID | Description |
|---------|------|-----|-------------|
| XLM Amount Slider | Range Input | `transact-slider` | Visual amount selector |
| XLM Amount Number | Number Input | `transact-amount` | Precise amount with spinner |

#### Inputs Section
| Element | Type | ID Pattern | Description |
|---------|------|------------|-------------|
| Input Note Field | Text + File | `input-note-{n}` | Note ID input with file upload |
| Dummy Checkbox | Checkbox | `input-dummy-{n}` | Mark input as dummy (zero-value) |
| Input Amount | Number | `input-amount-{n}` | Amount to consume from this note |

#### Outputs Section
| Element | Type | ID Pattern | Description |
|---------|------|------------|-------------|
| Output Note ID | Text (readonly) | `output-note-{n}` | Generated output note hex |
| Output Copy Button | Button | `btn-copy-output-{n}` | Copy output note ID |
| Output Download Button | Button | `btn-download-output-{n}` | Download output note |

| Element | Type | ID | Description |
|---------|------|-----|-------------|
| Recipient Address | Text Input | `transact-recipient` | Address for any withdrawal portion |
| Transact Button | Button | `btn-transact` | Executes complex transaction |

### 6. Stats Panel (Sidebar)

| Element | Type | ID | Description |
|---------|------|-----|-------------|
| Stats Container | Card | `stats-panel` | Container for pool statistics |
| Recent Transactions | List | `stats-recent-tx` | List of recent transaction hashes |
| Total Pool Amount | Text | `stats-pool-total` | Total XLM locked in pool |

### 7. Compliance Contracts Panel (Sidebar)

| Element | Type | ID | Description |
|---------|------|-----|-------------|
| Container | Card | `compliance-panel` | Container for compliance info |
| Contract Entry | List Item | `compliance-{n}` | Address + Merkle root pairs |

### 8. Your Notes Panel (Bottom)

| Element | Type | ID | Description |
|---------|------|-----|-------------|
| Notes Table | Table | `notes-table` | User's notes list |
| Note Row | Table Row | `note-row-{id}` | Individual note entry |
| Note ID Column | Cell | - | Truncated note identifier |
| Status Column | Cell | - | Spent/Unspent badge |

---

## Data Structures

### Note Object
```javascript
{
  id: string,           // Hex note identifier (32 bytes)
  commitment: string,   // Merkle tree commitment
  nullifier: string,    // Nullifier hash
  amount: number,       // XLM amount in stroops
  blinding: string,     // Random blinding factor
  spent: boolean,       // Whether note has been spent
  createdAt: Date       // Creation timestamp
}
```

### Transaction Request
```javascript
{
  type: 'deposit' | 'withdraw' | 'transact',
  inputs: Note[],       // Input notes (for withdraw/transact)
  outputs: {            // Output configuration
    amounts: number[],
    recipients: string[]
  },
  recipient: string,    // Withdrawal recipient address
  fee: number          // Relayer fee in stroops
}
```

---

## State Management

### Application State
```javascript
{
  wallet: {
    connected: boolean,
    address: string | null,
    network: 'testnet' | 'mainnet'
  },
  activeTab: 'deposit' | 'withdraw' | 'transact',
  notes: Note[],
  poolStats: {
    totalLocked: number,
    recentTransactions: string[]
  },
  complianceContracts: {
    membership: { address: string, root: string },
    nonMembership: { address: string, root: string }
  },
  ui: {
    loading: boolean,
    error: string | null,
    notification: string | null
  }
}
```

---

## Event Handlers

| Event | Handler | Action |
|-------|---------|--------|
| Tab Click | `switchTab(tabId)` | Change active panel |
| Slider Change | `updateAmountFromSlider(value)` | Sync number input |
| Number Change | `updateSliderFromNumber(value)` | Sync slider |
| Connect Wallet | `connectWallet()` | Initialize Freighter |
| Deposit | `executeDeposit()` | Create note, submit tx |
| Withdraw | `executeWithdraw()` | Verify note, submit tx |
| Transact | `executeTransact()` | Build complex tx |
| Copy Note | `copyToClipboard(noteId)` | Copy to clipboard |
| Download Note | `downloadNote(note)` | Trigger file download |
| Add Input | `addInputNote()` | Add input row |
| Remove Input | `removeInputNote(index)` | Remove input row |

---

## API Integration Points

### Freighter Wallet
- `isConnected()` - Check wallet connection
- `getPublicKey()` - Get user's Stellar address
- `signTransaction(xdr)` - Sign transaction XDR

### Stellar Horizon (via SDK)
- `loadAccount(address)` - Get account details
- `submitTransaction(tx)` - Submit signed transaction

### Pool Contract (Soroban)
- `transact(proof, extData, sender)` - Execute private transaction
- `get_root()` - Get current Merkle root
- `get_asp_membership_root()` - Get compliance membership root
- `get_asp_non_membership_root()` - Get compliance non-membership root

---

## File Structure

```
frontend/
├── index.html          # Main HTML structure
├── css/
│   └── styles.css      # All styles
├── js/
│   ├── app.js          # Main application logic
│   ├── wallet.js       # Freighter wallet integration
│   ├── crypto.js       # Note generation & proof helpers
│   └── ui.js           # UI manipulation helpers
└── assets/
    └── logo.svg        # Application logo
```

---

## Security Considerations

1. **Note Storage**: Notes stored in localStorage are encrypted
2. **Input Validation**: All user inputs sanitized before processing
3. **XSS Prevention**: HTML escaping on all dynamic content
4. **HTTPS Only**: Enforce secure connections in production
5. **Wallet Auth**: All transactions require wallet signature

---

## Responsive Breakpoints

| Breakpoint | Description |
|------------|-------------|
| < 768px | Mobile: Stack sidebar below main content |
| 768px - 1024px | Tablet: Compressed sidebar |
| > 1024px | Desktop: Full two-column layout |

