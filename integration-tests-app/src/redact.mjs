// Redact known secrets from any string before it hits a log line.
//
// CodeQL flags clear-text logging of process-environment data
// (js/clear-text-logging): E2E_FREIGHTER_PASSWORD is read from the
// environment and could otherwise surface inside error messages (e.g. a
// thrown Error whose message embeds an env value). scrub() replaces it with
// [REDACTED] so assert/error logging can never echo it. Per-test ephemeral
// account secrets (src/testAccount.mjs) never touch process.env, so they
// need no redaction here.

function secrets() {
  const v = process.env.E2E_FREIGHTER_PASSWORD;
  return v && v.length >= 8 ? [v] : [];
}

// Replace every known secret in `text` with [REDACTED]. Non-strings pass
// through unchanged (callers may log err.message, which is always a string).
export function scrub(text) {
  if (typeof text !== 'string') return text;
  let out = text;
  for (const value of secrets()) {
    out = out.split(value).join('[REDACTED]');
  }
  return out;
}
