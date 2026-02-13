/**
 * Downloads the Freighter extension build ZIP from GitHub Releases
 * and extracts it for use with Playwright.
 *
 * Usage: node download-extension.js [version]
 * Default version: 5.37.1
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const VERSION = process.argv[2] || '5.37.1';
const URL = `https://github.com/stellar/freighter/releases/download/${VERSION}/build-${VERSION}.zip`;
const OUT_DIR = path.join(__dirname, '..', '.freighter-extension');
const ZIP_PATH = path.join(OUT_DIR, `build-${VERSION}.zip`);

// Skip if already extracted
if (fs.existsSync(path.join(OUT_DIR, 'manifest.json'))) {
    console.log(`Freighter ${VERSION} already downloaded at ${OUT_DIR}`);
    process.exit(0);
}

fs.mkdirSync(OUT_DIR, { recursive: true });

console.log(`Downloading Freighter ${VERSION} from ${URL}...`);
execFileSync('curl', ['-fsSL', '-o', ZIP_PATH, URL], { stdio: 'inherit' });

console.log('Extracting...');
execFileSync('unzip', ['-o', ZIP_PATH, '-d', OUT_DIR], { stdio: 'inherit' });

// The ZIP may extract into a subdirectory (e.g. build/). If so, move contents up.
const buildSubdir = path.join(OUT_DIR, 'build');
if (fs.existsSync(path.join(buildSubdir, 'manifest.json'))) {
    const files = fs.readdirSync(buildSubdir);
    for (const file of files) {
        fs.renameSync(path.join(buildSubdir, file), path.join(OUT_DIR, file));
    }
    fs.rmdirSync(buildSubdir);
}

// Clean up ZIP
if (fs.existsSync(ZIP_PATH)) {
    fs.unlinkSync(ZIP_PATH);
}

if (!fs.existsSync(path.join(OUT_DIR, 'manifest.json'))) {
    console.error('ERROR: manifest.json not found after extraction. Check ZIP structure.');
    process.exit(1);
}

console.log(`Freighter ${VERSION} ready at ${OUT_DIR}`);
