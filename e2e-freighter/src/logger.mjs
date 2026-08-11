// Lightweight, zero-dependency structured logger for the e2e-freighter suite.
//
// Format per line:  YYYY-MM-DDTHH:MM:SS LEVEL [  scope] message
// Color:            only when stdout is a TTY and NO_COLOR is not set
// Level gating:     E2E_LOG_LEVEL env var (default INFO); DEBUG is gated
// Groups:           group(label) / groupEnd() add 2-space indent per depth
// Ring buffer:      getRecentLines(n) for failure-block context

// File sinks (populated by enableFileLogging/enableNdjsonLogging).
import fs from 'node:fs';
import path from 'node:path';

let FILE_SINK = null;
let NDJSON_SINK = null;

// Computed once at module load — env vars are set before Node starts
// (scripts/run-e2e.sh sources .e2e-accounts.env and sets environment
// before invoking node / runner.mjs).
const SHOULD_COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const LOG_LEVEL = (process.env.E2E_LOG_LEVEL || 'INFO').toUpperCase();
const LEVEL_RANK = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

// ANSI escape codes (only applied when SHOULD_COLOR is true).
const C = {
  reset:   '\x1b[0m',
  dim:     '\x1b[2m',
  bold:    '\x1b[1m',
  red:     '\x1b[31m',
  yellow:  '\x1b[33m',
};

const LEVEL_COLORS = {
  DEBUG: C.dim,
  INFO:  '',
  WARN:  C.yellow,
  ERROR: C.red,
};

// Ring buffer for recent-formatted-lines (plain text, no color) so a
// failure block can show context without keeping the whole log in memory.
const RECENT_LINES = [];
const MAX_RECENT = 200;

function padLevel(level) {
  // "DEBUG" (5), "INFO " (5), "WARN " (5), "ERROR" (5)
  return level + (level.length === 5 ? '' : ' ');
}

function padScope(scope) {
  // Fixed 12-character scope slot: "[scope     ]" (brackets included)
  // If scope is longer than 10 chars, use it as-is.
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

    // Plain version for the ring buffer
    const plain = `${ts} ${lvl} ${scp} ${indent}${msg}`;
    RECENT_LINES.push(plain);
    if (RECENT_LINES.length > MAX_RECENT) RECENT_LINES.shift();

    let line;
    if (SHOULD_COLOR) {
      const color = LEVEL_COLORS[level];
      line = `${color}${ts} ${lvl}${C.reset} ${C.bold}${scp}${C.reset} ${indent}${msg}`;
    } else {
      line = plain;
    }

    if (level === 'ERROR') {
      console.error(line);
    } else {
      console.log(line);
    }

    // Write to file sinks (plain text, no color, synchronous for ordering).
    if (FILE_SINK) {
      try { fs.appendFileSync(FILE_SINK, plain + '\n', 'utf-8'); } catch { /* best-effort */ }
    }
    if (NDJSON_SINK) {
      const entry = JSON.stringify({ ts, level, scope, msg }) + '\n';
      try { fs.appendFileSync(NDJSON_SINK, entry, 'utf-8'); } catch { /* best-effort */ }
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

// Expose the ring buffer for failure-block inspection (step 5.1).
export function getRecentLines(n = 15) {
  return RECENT_LINES.slice(-n);
}

// Enable plain-text file logging. Disabled when E2E_LOG_FILE=0.
export function enableFileLogging(filePath) {
  if (process.env.E2E_LOG_FILE === '0') return;
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  FILE_SINK = filePath;
}

// Enable NDJSON file logging. Disabled when E2E_LOG_FILE=0.
export function enableNdjsonLogging(filePath) {
  if (process.env.E2E_LOG_FILE === '0') return;
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  NDJSON_SINK = filePath;
}
