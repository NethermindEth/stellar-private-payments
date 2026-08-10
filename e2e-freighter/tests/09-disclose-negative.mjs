// Negative disclosure verification battery — the adversarial complement to
// tests/06-08's positive-path proofs, all as account A against the
// locally-built FIXED app (the deployed app still serves the pre-fix
// wasm). Composes 06/07/08's established machinery (deposit, disclose,
// verify selectors) rather than re-discovering it; see those files' headers
// for the underlying UI facts this one relies on without repeating.
//
// Each tamper case asserts a SPECIFIC named check failure (never a generic
// "something failed"), discovered from app/js/disclosure.js's own check
// labels (mountVerify's makeCheck calls):
//   - proof:   pass "Proof valid",   fail "Proof invalid"
//   - context: pass "Context valid", fail "Context mismatch"
//   - unspent: pass "Nullifiers unspent", fail "Nullifier already spent"
// (unspent is 07/08's territory, not exercised here.)
//
// Garbage-input discovery: `loadReceipt`'s JSON.parse failure path sets
// importErrorEl's text to `Invalid JSON: ${e.message}` and leaves
// summaryWrap/resultsWrap hidden — no exception escapes to the page, no
// stuck spinner, and the SAME textarea + Load Receipt flow cleanly accepts
// a valid receipt afterward with no reload needed. That recovery is the
// case (a) test's actual assertion: not just "shows an error", but "the
// import path is still usable right after".
//
// NO STALE-ROOT CASE (deliberately dropped, not skipped/softened): a
// "verify fresh, deposit once more, re-verify" case for root staleness was
// tried and doesn't work — contracts/pool/src/merkle_with_history.rs
// defines `const ROOT_HISTORY_SIZE: u32 = 90;`, and is_pool_known_root()
// (sdk/stellar/src/contract_state.rs) checks membership across that WHOLE
// 90-root window, not just the current root. One additional deposit only
// advances the tree by one root, leaving a fresh receipt's root nowhere
// close to eviction — confirmed empirically (the U5e deviation this step
// resolves), not just from reading the contract. Genuinely evicting a root
// needs ~91 real deposits, absurd for a test; substituting a fabricated
// never-real root would exercise the same code path but prove a different
// thing (rejecting a bogus root vs. reflecting newer live chain state) and
// is left as a possible future increment, not done here.

import { submitAndConfirm } from '../src/moveFunds.mjs';
import { driveWizard } from '../src/onboarding.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`09-disclose-negative: ${message}`);
}

// Flip the compressed proof's y-SIGN flag on point A, without touching any
// coordinate value — deterministically produces a decodable-but-wrong
// point (a different, valid, on-curve y for the same x), so verification
// reliably reaches the actual pairing check and fails it specifically,
// with zero chance of a decode-time exception.
//
// Two earlier attempts at tampering this proof were flaky (sdk/prover/
// src/prover.rs deserializes it via arkworks' `Proof::<Bn254>::
// deserialize_compressed`, which occasionally rejected the tampered bytes
// outright with "Verification could not be completed: Failed to load
// proof: the input buffer contained invalid data" — a GENERIC decode
// error, not the specific "Proof invalid" cryptographic rejection this
// case needs):
//   1. Flipping a hex digit at a fixed middle offset (up to +15 in value).
//   2. Flipping the lowest bit of a coordinate BYTE (assumed a safe ±1
//      value nudge either way — endianness-order guesses about which byte
//      is "least significant").
// Both miss the actual reason this is inherently flaky: ANY change to a
// compressed point's x-coordinate has roughly a COIN-FLIP chance of
// landing on an x for which no valid y exists at all (elliptic curve
// points only exist for x values where x³+ax+b is a quadratic residue —
// true for only about half of all field elements) — that's a decode
// failure, unrelated to overflow or byte order, and unavoidable whenever
// tampering touches x itself, however carefully.
//
// The fix: don't touch x. ark-ec's short_weierstrass compressed
// serialization (ark-ec-0.6.0/src/models/short_weierstrass/
// serialization_flags.rs — SWFlags) packs a 2-bit flag into the TOP bits
// of the coordinate's LAST byte: bit 7 (0x80) selects which of the two
// valid y-roots to use (YIsPositive/YIsNegative), bit 6 (0x40) marks the
// point at infinity. Those 2 bits are otherwise always zero (BN254's ~254-
// bit Fq modulus never uses the top 2 bits of a 256-bit/32-byte
// representation), so flipping bit 7 alone changes ONLY which y-root gets
// selected — x is untouched, so a valid y ALWAYS exists (the deserializer
// just picks the other one) — and the result is a genuinely different,
// valid, on-curve point that fails the pairing check.
function flipYSignFlag(hexStr) {
  const digits = '0123456789abcdef';
  const chars = hexStr.split('');
  // Point A is the first 32 bytes (64 hex chars) of [A || B || C]; its last
  // byte is at buffer offset 31, i.e. hex chars 2+31*2=64 (high nibble,
  // carrying bit 7) and 65 (low nibble), after the "0x" prefix.
  const targetIndex = 64;
  const current = chars[targetIndex];
  const flipped = digits[digits.indexOf(current) ^ 0x8]; // toggle bit 7 (the y-sign flag) of this nibble
  assert(flipped !== current, 'flipYSignFlag produced no change');
  chars[targetIndex] = flipped;
  return chars.join('');
}

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '09-disclose-negative';

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await page.getByRole('button', { name: 'Move Funds', exact: true }).click();
  await page.waitForTimeout(500);

  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';

  const depositHash = await submitAndConfirm(helpers, {
    logTag,
    flowName: 'deposit-1',
    amountSelector: '#deposit-amount',
    submitSelector: '#btn-deposit',
    confirmDialogTitle: 'Confirm deposit',
    confirmButtonLabel: 'Deposit',
    amount: '0.01',
    rpcUrl,
  });
  console.log(`[${logTag}] deposit confirmed SUCCESS on-chain: ${depositHash}`);

  await page.waitForTimeout(20000);
  await page.getByRole('button', { name: 'Disclosure', exact: true }).click();

  const generatePanel = page.locator('#disclosure-generate');
  const checkboxLocator = generatePanel.locator('label[data-note-id] input[type="checkbox"]');
  const verifyPanel = page.locator('#disclosure-verify');

  const notesAppeared = await checkboxLocator
    .first()
    .waitFor({ state: 'visible', timeout: 30000 })
    .then(() => true)
    .catch(() => false);
  if (!notesAppeared) {
    const panelText = await generatePanel.innerText().catch(() => '(unavailable)');
    assert(false, `no notes appeared in the disclosure generate panel within 30s (panel text: "${panelText}")`);
  }

  await generatePanel.getByRole('button', { name: 'Available', exact: true }).click();
  await page.waitForTimeout(500);
  await checkboxLocator.first().waitFor({ state: 'visible', timeout: 10000 });
  await checkboxLocator.first().check({ force: true });

  await page.fill('#authority-label', 'E2E Test Authority');
  await page.fill('#authority-payload', '0xdeadbeef');
  await page.fill('#purpose', 'e2e-disclosure-negative');

  await generatePanel.getByRole('button', { name: 'Generate Disclosure Receipt', exact: true }).click();
  const receiptPre = generatePanel.locator('pre');
  const receiptAppeared = await receiptPre
    .waitFor({ state: 'visible', timeout: 120000 })
    .then(() => true)
    .catch(() => false);
  if (!receiptAppeared) {
    const errorText = await generatePanel.innerText().catch(() => '(unavailable)');
    assert(false, `disclosure receipt was not generated within 120s (panel text: "${errorText}")`);
  }
  const validReceiptJson = await receiptPre.innerText();
  console.log(`[${logTag}] generated the baseline valid disclosure receipt`);

  const verifyBtn = () => verifyPanel.getByRole('button', { name: 'Verify Receipt', exact: true });

  const loadAndVerify = async (rawText) => {
    await verifyPanel.locator('textarea').fill(rawText);
    await verifyPanel.getByRole('button', { name: 'Load Receipt', exact: true }).click();
    await page.waitForTimeout(500);

    const loadFailed = await verifyPanel.getByText('Invalid JSON', { exact: false }).isVisible().catch(() => false);
    if (loadFailed) return { loaded: false };

    const btnHandle = await verifyBtn().elementHandle();
    await verifyBtn().click();
    await page.waitForTimeout(300);
    const finished = await page
      .waitForFunction((btn) => !btn.disabled, btnHandle, { timeout: 150000 })
      .then(() => true)
      .catch(() => false);
    if (!finished) {
      const resultsText = await verifyPanel.innerText().catch(() => '(unavailable)');
      assert(false, `verify did not finish within 150s (verify panel text: "${resultsText}")`);
    }
    return { loaded: true };
  };

  const isFullyVerified = () =>
    verifyPanel.getByRole('status').filter({ hasText: 'Fully verified' }).isVisible().catch(() => false);

  // --- (a) GARBAGE INPUT: unparsable text must fail cleanly, at the
  // import step (never reaching Verify), with no exception and no stuck
  // state — and the SAME flow must accept a valid receipt right after.
  await verifyPanel.locator('textarea').fill('{ this is not valid json at all {{{');
  await verifyPanel.getByRole('button', { name: 'Load Receipt', exact: true }).click();
  await page.waitForTimeout(500);

  const invalidJsonError = await verifyPanel.getByText('Invalid JSON', { exact: false }).isVisible().catch(() => false);
  assert(invalidJsonError, 'garbage input did not produce an "Invalid JSON" error');

  const verifyButtonVisibleAfterGarbage = await verifyBtn().isVisible().catch(() => false);
  assert(!verifyButtonVisibleAfterGarbage, 'garbage input left the Verify Receipt button visible — the summary panel should stay hidden on a failed import');
  console.log(`[${logTag}] (a) garbage input: clean "Invalid JSON" error, no stuck state`);

  // Clean recovery: the exact same flow accepts a valid receipt right after.
  const recoveredLoad = await loadAndVerify(validReceiptJson);
  assert(recoveredLoad.loaded, 'the import flow did not recover after a prior garbage-input error');
  const recoveredOk = await isFullyVerified();
  assert(recoveredOk, 'the baseline valid receipt did not verify as fully valid after recovering from the garbage-input error');
  console.log(`[${logTag}] (a) clean recovery confirmed: the same flow verified a valid receipt right after`);

  // --- (b) TAMPERED PROOF: flip point A's y-sign flag (keeping it
  // syntactically valid — same length/charset — so it passes shape
  // validation and deterministically reaches the actual cryptographic
  // check, never a decode-time exception; see flipYSignFlag's comment).
  const baseline = JSON.parse(validReceiptJson);
  const tamperedProof = JSON.parse(validReceiptJson);
  tamperedProof.proofCompressedHex = flipYSignFlag(baseline.proofCompressedHex);
  assert(tamperedProof.proofCompressedHex !== baseline.proofCompressedHex, 'proof tampering produced no change');

  const proofLoad = await loadAndVerify(JSON.stringify(tamperedProof));
  assert(proofLoad.loaded, 'tampered-proof receipt failed to load (shape validation should still pass — only the proof bytes changed)');
  const proofInvalidVisible = await verifyPanel.getByText('Proof invalid', { exact: true }).isVisible().catch(() => false);
  if (!proofInvalidVisible) {
    const resultsText = await verifyPanel.innerText().catch(() => '(unavailable)');
    assert(false, `tampered proof did not show "Proof invalid" (verify panel text: "${resultsText}")`);
  }
  const fullyVerifiedAfterProofTamper = await isFullyVerified();
  assert(!fullyVerifiedAfterProofTamper, 'tampered proof still showed "Fully verified"');
  console.log(`[${logTag}] (b) tampered proof: "Proof invalid" shown specifically, not fully verified`);

  // --- (c) WRONG CONTEXT: alter a context field (purpose) so the receipt's
  // committed context hash no longer matches what's declared — the proof
  // itself is untouched, so ONLY the context check should fail.
  const tamperedContext = JSON.parse(validReceiptJson);
  tamperedContext.context.purpose = `${tamperedContext.context.purpose}-TAMPERED`;

  const contextLoad = await loadAndVerify(JSON.stringify(tamperedContext));
  assert(contextLoad.loaded, 'tampered-context receipt failed to load');
  const contextMismatchVisible = await verifyPanel.getByText('Context mismatch', { exact: true }).isVisible().catch(() => false);
  assert(contextMismatchVisible, 'tampered context did not show "Context mismatch"');
  const proofStillOkWithTamperedContext = await verifyPanel.getByText('Proof valid', { exact: true }).isVisible().catch(() => false);
  assert(proofStillOkWithTamperedContext, 'proof check should still pass when only the context is tampered — the proof bytes were untouched');
  const fullyVerifiedAfterContextTamper = await isFullyVerified();
  assert(!fullyVerifiedAfterContextTamper, 'tampered context still showed "Fully verified"');
  console.log(`[${logTag}] (c) wrong context: "Context mismatch" shown specifically, proof still valid, not fully verified`);

  console.log(`[${logTag}] OK: all three negative cases (garbage input, tampered proof, wrong context) behaved correctly`);
}
