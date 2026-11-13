// Reads an amount the user typed. `parse` is the SDK's parseTokenAmount.

// What the SDK's decimal parser (sdk/native/src/types/amounts.rs) says, in words
// for the person who typed the amount.
function amountMessage(message, decimals) {
  if (message === 'invalid decimal amount') return 'Enter the amount as a number, for example 1.5.';
  if (message === 'amount must be non-negative') return 'The amount can\'t be negative.';
  if (message === 'amount is too large') return 'That amount is too large.';
  if (/^too many decimal places \(max \d+\)$/.test(message)) {
    return decimals === 0
      ? 'This token has no decimal places. Enter a whole number.'
      : `This token allows at most ${decimals} decimal place${decimals === 1 ? '' : 's'}.`;
  }
  return message;
}

const SEPARATORS = 'Use a dot for decimals, for example 1.5, and leave out thousands separators.';

/**
 * Parses a typed amount into base units. An empty field is zero. A decimal
 * comma is read as a dot ("1,5" is 1.5). A comma that could be a thousands
 * separator ("1,500", "1,000.5") is refused rather than guessed.
 * @returns {{ ok: true, value: bigint } | { ok: false, error: string }}
 */
export function parseAmountInput(value, decimals, parse) {
  let raw = String(value ?? '').trim();
  if (!raw) return { ok: true, value: 0n };
  if (raw.includes(',')) {
    if (!/^[-+]?\d*,\d+$/.test(raw) || /,\d{3}$/.test(raw)) return { ok: false, error: SEPARATORS };
    raw = raw.replace(',', '.');
  }
  try {
    return { ok: true, value: parse(raw, decimals) };
  } catch (error) {
    return { ok: false, error: amountMessage(String(error?.message ?? error), decimals) };
  }
}
