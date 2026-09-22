import { waitForCondition } from './waits.mjs';

export function parseDisclosureReceipt(text) {
  try {
    const receipt = JSON.parse(text);
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
      throw new Error('receipt must be a JSON object');
    }
    return receipt;
  } catch (error) {
    throw new Error(`disclosure receipt could not be parsed: ${error.message}`);
  }
}

async function waitForState(locator, operation, expected, { timeoutMs = 30_000, waitOptions = {} } = {}) {
  const result = await waitForCondition({
    operation,
    timeoutMs,
    intervalMs: 200,
    ...waitOptions,
    observe: async () => ({ state: await locator.getAttribute('data-state') }),
    isReady: ({ state }) => expected.includes(state),
  });
  return result.value.state;
}

export async function loadDisclosureText(page, text, options) {
  const serialized = typeof text === 'string' ? text : JSON.stringify(text);
  await page.getByTestId('disclosure-receipt-input').fill(serialized);
  await page.getByTestId('disclosure-load-receipt').click();
  const summary = page.getByTestId('disclosure-receipt-summary');
  const state = await waitForState(summary, 'disclosure:load-receipt', ['ready', 'error'], options);
  return { state, text: serialized };
}

export async function loadDisclosureReceipt(page, receipt, options) {
  const loaded = await loadDisclosureText(page, receipt, options);
  if (loaded.state !== 'ready') throw new Error('[disclosure:load-receipt] receipt was rejected by the UI');
  const serialized = loaded.text;
  return parseDisclosureReceipt(serialized);
}

export async function selectDisclosureNotes(page, {
  status = 'unspent',
  count = 1,
  timeoutMs = 30_000,
  waitOptions = {},
} = {}) {
  if (!['all', 'unspent', 'spent'].includes(status)) throw new TypeError(`unknown disclosure note status '${status}'`);
  if (!Number.isInteger(count) || count < 1 || count > 4) throw new TypeError('disclosure note count must be 1..4');
  await page.getByTestId(`disclosure-filter-${status}`).click();
  const rows = page.locator(`[data-testid="disclosure-note"][data-note-state="${status}"]`);
  await waitForCondition({
    operation: `disclosure:notes:${status}`,
    timeoutMs,
    intervalMs: 100,
    ...waitOptions,
    observe: async () => ({ count: await rows.count() }),
    isReady: ({ count: available }) => available >= count,
  });
  const noteIds = [];
  for (let index = 0; index < count; index += 1) {
    const row = rows.nth(index);
    noteIds.push(await row.getAttribute('data-note-id'));
    await row.getByTestId('disclosure-note-select').check({ force: true });
  }
  return noteIds;
}

export async function clearDisclosureNotes(page, {
  status = 'all',
  timeoutMs = 10_000,
  waitOptions = {},
} = {}) {
  if (!['all', 'unspent', 'spent'].includes(status)) throw new TypeError(`unknown disclosure note status '${status}'`);
  await page.getByTestId(`disclosure-filter-${status}`).click();
  const selected = page.locator('[data-testid="disclosure-note"] input[type="checkbox"]:checked');
  while (await selected.count()) {
    // Toggling a selection synchronously re-renders the picker. click() has
    // no stale-element checked-state postcondition, unlike uncheck(), and
    // the bounded predicate below verifies the newly rendered state.
    await selected.first().click({ force: true });
  }
  await waitForCondition({
    operation: 'disclosure:notes:clear',
    timeoutMs,
    intervalMs: 100,
    ...waitOptions,
    observe: async () => ({ selected: await selected.count() }),
    isReady: ({ selected: count }) => count === 0,
  });
}

export async function generateDisclosure(page, {
  authority,
  payload,
  purpose,
  nonce,
  selectNotes,
  ...options
} = {}) {
  if (typeof selectNotes !== 'function') throw new TypeError('generateDisclosure requires selectNotes');
  const receiptJson = page.getByTestId('disclosure-receipt-json');
  const previousReceipt = await receiptJson.innerText().catch(() => null);
  await selectNotes(page);
  await page.fill('#authority-label', authority);
  await page.fill('#authority-payload', payload);
  await page.fill('#purpose', purpose);
  if (nonce !== undefined) await page.fill('#context-nonce', nonce);
  await page.getByTestId('disclosure-generate-submit').click();
  const result = page.getByTestId('disclosure-generate-result');
  const completion = await waitForCondition({
    operation: 'disclosure:generate',
    timeoutMs: options.timeoutMs || 30_000,
    intervalMs: 200,
    ...options.waitOptions,
    observe: async () => ({
      state: await result.getAttribute('data-state'),
      receipt: await receiptJson.innerText().catch(() => null),
    }),
    isReady: ({ state, receipt }) => state === 'error' || (state === 'ready' && Boolean(receipt) && receipt !== previousReceipt),
  });
  if (completion.value.state !== 'ready') throw new Error('[disclosure:generate] generation ended in an error state');
  return parseDisclosureReceipt(completion.value.receipt);
}

export async function verifyDisclosure(page, options) {
  await page.getByTestId('disclosure-verify-submit').click();
  const results = page.getByTestId('disclosure-verification-results');
  const state = await waitForState(results, 'disclosure:verify', ['complete', 'error'], options);
  if (state !== 'complete') throw new Error('[disclosure:verify] verification ended in an error state');
  const noteStates = await page.getByTestId('disclosure-disclosed-note')
    .evaluateAll((notes) => notes.map((note) => note.getAttribute('data-state')));
  const checks = await results.locator('[data-testid^="disclosure-check-"]')
    .evaluateAll((elements) => Object.fromEntries(elements.map((element) => [
      element.getAttribute('data-testid').replace('disclosure-check-', ''),
      element.getAttribute('data-state'),
    ])));
  return { state, noteStates, checks };
}

/** Re-run verification until external indexers report the expected checks. */
export async function verifyDisclosureUntil(page, {
  checks: expectedChecks,
  predicate,
  timeoutMs = 90_000,
  intervalMs = 1_000,
  waitOptions = {},
} = {}) {
  if ((!expectedChecks || typeof expectedChecks !== 'object') && typeof predicate !== 'function') {
    throw new TypeError('verifyDisclosureUntil requires expected checks or a predicate');
  }
  const result = await waitForCondition({
    operation: 'disclosure:verify-until',
    timeoutMs,
    intervalMs,
    ...waitOptions,
    observe: () => verifyDisclosure(page),
    isReady: (verification) => (
      (!expectedChecks || Object.entries(expectedChecks)
        .every(([check, state]) => verification.checks[check] === state)) &&
      (!predicate || predicate(verification))
    ),
  });
  return result.value;
}
