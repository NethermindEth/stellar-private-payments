#!/usr/bin/env node
/**
 * Verify wasm-bindgen exports are covered by the public type surface and that
 * staged declarations match live bindgen output from `dist/`.
 */
import { access, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const distWasmTypesPath = path.join(root, 'dist/stellar_private_payments_web.d.ts');
const stagedWasmTypesPath = path.join(root, 'js/types/crates/stellar_private_payments_web.d.ts');
const publicTypesPath = path.join(root, 'js/types/index.d.ts');
const apiTypesPath = path.join(root, 'js/types/api-types.d.ts');

async function requireReadable(filePath, hint) {
  try {
    await access(filePath, constants.R_OK);
  } catch {
    console.error(`Bindgen type check failed: missing ${path.relative(root, filePath)}`);
    if (hint) {
      console.error(hint);
    }
    process.exit(1);
  }
}

await requireReadable(distWasmTypesPath, 'Run `npm run build` first.');
await requireReadable(stagedWasmTypesPath, 'Run `npm run build` to stage wasm types under js/types/crates/.');
await requireReadable(publicTypesPath);
await requireReadable(apiTypesPath);

const [distTypes, stagedTypes] = await Promise.all([
  readFile(distWasmTypesPath, 'utf8'),
  readFile(stagedWasmTypesPath, 'utf8'),
]);

if (distTypes !== stagedTypes) {
  console.error(
    'Staged wasm types are out of sync with dist/stellar_private_payments_web.d.ts.',
  );
  console.error('Run `npm run build` to refresh js/types/crates/.');
  process.exit(1);
}

async function collectExports(filePath) {
  const sourceText = await readFile(filePath, 'utf8');
  const sourceFile = ts.createSourceFile(
    filePath,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );

  const names = new Set();
  const aliases = new Map();
  const starExportModules = [];

  const visit = (node) => {
    if (ts.isExportDeclaration(node)) {
      if (node.exportClause && ts.isNamedExports(node.exportClause)) {
        for (const element of node.exportClause.elements) {
          const exported = element.name.getText(sourceFile);
          const local = element.propertyName?.getText(sourceFile) ?? exported;
          names.add(exported);
          aliases.set(local, exported);
        }
      } else if (!node.exportClause && node.moduleSpecifier) {
        const modulePath = node.moduleSpecifier.getText(sourceFile).slice(1, -1);
        starExportModules.push({ filePath, modulePath });
      }
    }

    if (
      node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
    ) {
      if ('name' in node && node.name) {
        names.add(node.name.getText(sourceFile));
      } else if (ts.isVariableStatement(node)) {
        for (const declaration of node.declarationList.declarations) {
          names.add(declaration.name.getText(sourceFile));
        }
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return { names, aliases, starExportModules };
}

function isRelativeModule(modulePath) {
  return modulePath.startsWith('./') || modulePath.startsWith('../');
}

/** Map TS declaration imports (`./foo.js`) to on-disk `.d.ts` paths. */
function resolveDeclarationPath(baseDir, modulePath) {
  let resolvedPath = path.resolve(baseDir, modulePath);
  if (resolvedPath.endsWith('.js')) {
    return resolvedPath.slice(0, -3) + '.d.ts';
  }
  if (!resolvedPath.endsWith('.d.ts') && !resolvedPath.endsWith('.ts')) {
    return `${resolvedPath}.d.ts`;
  }
  return resolvedPath;
}

async function resolveStarExports(starExportModules, baseDir) {
  const resolvedNames = new Set();
  const resolvedAliases = new Map();

  for (const { modulePath } of starExportModules) {
    if (!isRelativeModule(modulePath)) {
      continue;
    }

    const resolvedPath = resolveDeclarationPath(baseDir, modulePath);

    try {
      const nested = await collectExports(resolvedPath);
      nested.names.forEach((name) => resolvedNames.add(name));
      nested.aliases.forEach((exported, local) => resolvedAliases.set(local, exported));
      const deeper = await resolveStarExports(nested.starExportModules, path.dirname(resolvedPath));
      deeper.names.forEach((name) => resolvedNames.add(name));
      deeper.aliases.forEach((exported, local) => resolvedAliases.set(local, exported));
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        console.error(
          `Bindgen type check failed: could not resolve star export "${modulePath}" from ${baseDir}`,
        );
        process.exit(1);
      }
      throw error;
    }
  }

  return { names: resolvedNames, aliases: resolvedAliases };
}

const { names: wasmExports } = await collectExports(stagedWasmTypesPath);
const publicEntry = await collectExports(publicTypesPath);
const apiEntry = await collectExports(apiTypesPath);

const publicExports = new Set(publicEntry.names);
const publicAliases = new Map(publicEntry.aliases);

const publicStars = await resolveStarExports(
  publicEntry.starExportModules,
  path.dirname(publicTypesPath),
);
publicStars.names.forEach((name) => publicExports.add(name));
publicStars.aliases.forEach((exported, local) => publicAliases.set(local, exported));

apiEntry.names.forEach((name) => publicExports.add(name));
apiEntry.aliases.forEach((exported, local) => publicAliases.set(local, exported));

const apiStars = await resolveStarExports(
  apiEntry.starExportModules,
  path.dirname(apiTypesPath),
);
apiStars.names.forEach((name) => publicExports.add(name));
apiStars.aliases.forEach((exported, local) => publicAliases.set(local, exported));

/** Wasm exports mapped to facade or re-export names on the package entry. */
const exportAliases = new Map([
  ['Client', ['Client', 'WasmClient']],
  ['Account', ['Account', 'WasmAccount']],
  ['Storage', ['Storage', 'WasmStorage']],
  ['init', ['default', 'init']],
]);

/** wasm-bindgen option parsers — used internally, not part of the public facade. */
const internalWasmExports = new Set([
  'AccountOptions',
  'PoolOptions',
  'RegisterPublicKeysOptions',
  'VerifyDisclosureOptions',
  // Async/sync init plumbing (public entry re-exports only `default` / `init`).
  'InitInput',
  'InitOutput',
  'SyncInitInput',
  'initSync',
  '__wbg_init',
]);

function isInternalWasmExport(name) {
  return internalWasmExports.has(name) || name.startsWith('__wbg_');
}

function isCovered(name) {
  if (publicExports.has(name)) {
    return true;
  }
  const aliases = exportAliases.get(name);
  if (aliases?.some((candidate) => publicExports.has(candidate))) {
    return true;
  }
  if (publicAliases.has(name)) {
    return true;
  }
  for (const [, exported] of publicAliases) {
    if (exported === name) {
      return true;
    }
  }
  return false;
}

const missing = [...wasmExports]
  .filter((name) => !isInternalWasmExport(name) && !isCovered(name))
  .sort();

if (missing.length > 0) {
  console.error('Type declarations are missing the following wasm-bindgen exports:');
  for (const name of missing) {
    console.error(`- ${name}`);
  }
  console.error('Update js/types/index.d.ts or js/types/api-types.d.ts.');
  process.exit(1);
}

console.log(
  'Bindgen type check passed: wasm exports are covered and staged types match dist/.',
);
