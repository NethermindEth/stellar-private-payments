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

/** One output slot from a private `transact` call. */
export interface GvkOutputSlot {
  commitment: string;
  note: GvkAuditedNote | null;
}

/** One input slot from a private `transact` call. */
export interface GvkSpentInput {
  nullifier: string;
  note: GvkAuditedNote | null;
}

/** Decrypted notes aligned with on-chain input/output slots for one private `transact` call. */
export interface GvkTxAudit {
  ledger: number;
  outputs: GvkOutputSlot[];
  inputs: GvkSpentInput[];
}

/** Admin audit cursor returned by {@link PrivatePool.audit}. */
export interface GvkAudit {
  nextTx(): Promise<GvkTxAudit | null>;
}

declare module '../../dist/stellar_private_payments_web.js' {
  export class GvkAudit {
    nextTx(): Promise<GvkTxAudit | null>;
  }
}
