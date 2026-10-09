export function parseAmountRange(min, max, decimals, parse) {
  const errors = ['', ''];
  const amounts = [min, max].map((value, index) => {
    const raw = String(value ?? '').trim();
    if (!raw) return null;
    if (decimals == null) {
      errors[index] = 'Token precision unavailable';
      return null;
    }
    try {
      return parse(raw, decimals);
    } catch (error) {
      errors[index] = error.message;
      return null;
    }
  });
  if (!errors.some(Boolean) && amounts[0] != null && amounts[1] != null && amounts[0] > amounts[1]) {
    errors[1] = 'Maximum amount must be at least the minimum';
  }
  return { amountMin: amounts[0], amountMax: amounts[1], errors, valid: !errors.some(Boolean) };
}
