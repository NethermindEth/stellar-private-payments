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
