/** Admin-recovered note secrets (BN254 field elements as `0x` hex). */
export interface GvkRecoveredNote {
  pk: string;
  amount: string;
  blinding: string;
}

/** Recovered note verified against an on-chain commitment. */
export interface GvkAuditedNote {
  note: GvkRecoveredNote;
  commitment: string;
}

/** Decrypted notes and public nullifiers for one private `transact` call. */
export interface GvkTxAudit {
  ledger: number;
  outputs: GvkAuditedNote[];
  /** Traceable pools only; empty for view-only pools. */
  inputs: GvkAuditedNote[];
  nullifiers: string[];
}
