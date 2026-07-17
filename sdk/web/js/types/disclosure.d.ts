/** Result of {@link AccountClient.verifySelectiveDisclosure}. */
export interface DisclosureVerificationReport {
  /** Groth16 proof verified against receipt public inputs. */
  proofVerified: boolean;
  /** Receipt context recomputed to the public `extContextHash`. */
  contextVerified: boolean;
  /** Known-root freshness check passed. */
  knownRootStatus: boolean;
  /** Disclosed nullifiers have not been spent on-chain. */
  nullifiersUnspent: boolean;
  /** 0-based indices of disclosed notes whose nullifiers are already spent on-chain. */
  spentNullifierIndices: number[];
}
