// Lightweight, zero-dependency structured logger for the e2e-freighter suite.
//
// Format per line:  YYYY-MM-DDTHH:MM:SS LEVEL [  scope] message
// Level gating:     E2E_LOG_LEVEL env var (default INFO); DEBUG is gated
// Groups:           group(label) / groupEnd() add 2-space indent per depth

// Computed once at module load — env vars are set before Node starts
// (scripts/run-e2e.sh sources .e2e-accounts.env and sets environment
// before invoking node / runner.mjs).
const LOG_LEVEL = (process.env.E2E_LOG_LEVEL || 'INFO').toUpperCase();
const LEVEL_RANK = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

function padLevel(level) {
  return level + (level.length === 5 ? '' : ' ');
}

function padScope(scope) {
  const inner = scope.length > 10 ? scope : scope.padEnd(10);
  return '[' + inner + ']';
}

function timestamp() {
  return new Date().toISOString().slice(0, 19);
}

export function createLogger(scope) {
  let depth = 0;

  function emit(level, args) {
    if (LEVEL_RANK[level] < LEVEL_RANK[LOG_LEVEL]) return;

    const indent = '  '.repeat(depth);
    const ts = timestamp();
    const lvl = padLevel(level);
    const scp = padScope(scope);
    const msg = args.map(String).join(' ');
    const line = `${ts} ${lvl} ${scp} ${indent}${msg}`;

    if (level === 'ERROR') {
      console.error(line);
    } else {
      console.log(line);
    }
  }

  return {
    debug(...args) { emit('DEBUG', args); },
    info(...args)  { emit('INFO', args); },
    warn(...args)  { emit('WARN', args); },
    error(...args) { emit('ERROR', args); },

    group(_label) {
      depth += 1;
    },
    groupEnd() {
      if (depth > 0) depth -= 1;
    },
  };
}