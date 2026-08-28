// Maps technical errors, meant for developers,
// to user-facing version.

const FRIENDLY_MESSAGES = [
    [/Runtime not initialized/, 'Still connecting. Please wait a moment and try again.'],
    [/Account session not open/, 'Your wallet isn’t connected yet. Connect your wallet and try again.'],
    [/Storage not ready/, 'Still setting up local storage. Please wait a moment and try again.'],
];

export function friendlyErrorMessage(message) {
    if (typeof message !== 'string') return message;
    const match = FRIENDLY_MESSAGES.find(([pattern]) => pattern.test(message));
    return match ? match[1] : message;
}

// Keyed on a structured `.code` rather than message text: an unguarded
// SESSION_SUPERSEDED reads as an internal implementation detail, not
// something a user did wrong.
const FRIENDLY_CODES = {
    SESSION_SUPERSEDED: 'Another connection attempt is already in progress. Please try again.',
};

/**
 * Friendly text for an error, preferring its structured `.code` over
 * `friendlyErrorMessage`'s message-pattern matching.
 *
 * Accepts either a plain message string (the existing calling convention) or
 * an error-like object with `.code`/`.message`, so callers that only have a
 * caught exception in hand can pass it directly.
 * @param {Error|{code?: string, message?: string}|string|unknown} errorOrMessage
 */
export function friendlyErrorForCode(errorOrMessage) {
    if (typeof errorOrMessage === 'string') return friendlyErrorMessage(errorOrMessage);
    const code = errorOrMessage?.code;
    if (typeof code === 'string' && FRIENDLY_CODES[code]) return FRIENDLY_CODES[code];
    return friendlyErrorMessage(errorOrMessage?.message);
}
