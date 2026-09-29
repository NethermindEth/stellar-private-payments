/** Shared Playwright/HTTP harness for isolated storage tests, without Freighter. */
import { appendFileSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, firefox } from 'playwright';

const defaultSdkRoot = fileURLToPath(new URL('../../sdk/web/', import.meta.url));
const contentTypes = new Map([
    ['.html', 'text/html'], ['.js', 'text/javascript'], ['.mjs', 'text/javascript'],
    ['.wasm', 'application/wasm'], ['.css', 'text/css'], ['.json', 'application/json'],
]);

export async function createStorageHarness({
    sdkRoot = defaultSdkRoot, routes = {}, transformResponse,
    artifacts, binary = process.env.CHROMIUM, browser = 'chromium',
} = {}) {
    const browserType = { chromium, firefox }[browser];
    if (!browserType) throw Error(`unsupported browser: ${browser}`);
    sdkRoot = resolve(sdkRoot);
    if (artifacts) await mkdir(artifacts, { recursive: true });
    const profile = await mkdtemp(join(artifacts || tmpdir(), 'storage-profile-'));
    const server = createServer(async (request, response) => {
        try {
            const path = new URL(request.url, 'http://localhost').pathname;
            let body = routes[path];
            if (body === undefined && path === '/') body = '<!doctype html><title>Storage integration test</title>';
            if (body === undefined) {
                const file = resolve(sdkRoot, '.' + path.slice('/sdk'.length));
                if (!path.startsWith('/sdk/') || !file.startsWith(sdkRoot + sep)) throw Error('invalid path');
                body = await readFile(file);
                if (transformResponse) body = await transformResponse(path, body);
            }
            response.writeHead(200, {
                'Content-Type': path === '/' ? 'text/html' : contentTypes.get(extname(path)) || 'application/octet-stream',
                'Cross-Origin-Opener-Policy': 'same-origin',
                'Cross-Origin-Embedder-Policy': 'require-corp',
            });
            response.end(body);
        } catch (error) {
            if (artifacts) appendFileSync(join(artifacts, 'browser.log'), `HTTP ${request.url}: ${error}\n`);
            response.writeHead(404);
            response.end('Not found');
        }
    });
    let context;
    async function launch() {
        // Closing this persistent context terminates the browser process;
        // relaunching it reuses the same profile and origin for restart tests.
        context = await browserType.launchPersistentContext(profile, {
            executablePath: binary, headless: true,
        });
        context.setDefaultTimeout(120_000);
        context.setDefaultNavigationTimeout(120_000);
        if (artifacts) {
            const logPage = page => {
                page.on('console', message => appendFileSync(join(artifacts, 'browser.log'), `${message.type()}: ${message.text()}\n`));
                page.on('pageerror', error => appendFileSync(join(artifacts, 'browser.log'), `${error.stack}\n`));
            };
            context.pages().forEach(logPage);
            context.on('page', logPage);
        }
    }
    async function close() {
        try { await context?.close(); }
        finally {
            await new Promise(resolve => server.close(resolve));
            await rm(profile, { recursive: true, force: true });
        }
    }
    try {
        await new Promise((resolve, reject) => {
            server.once('error', reject);
            server.listen(0, '127.0.0.1', resolve);
        });
        await launch();
    } catch (error) {
        await close();
        throw error;
    }
    return {
        origin: `http://127.0.0.1:${server.address().port}`,
        get context() { return context; },
        get page() { return context.pages()[0]; },
        get version() { return context.browser().version(); },
        async restart() { await context.close(); await launch(); },
        close,
    };
}

/** Hash the actual OPFS bytes; optionally inspect synthetic test secrets. */
export function snapshotOPFS(page, { secrets = [], includeText = false } = {}) {
    return page.evaluate(async ({ secrets, includeText }) => {
        const result = [];
        async function walk(directory, path) {
            for await (const [name, handle] of directory.entries()) {
                if (handle.kind === 'directory') {
                    result.push({ path: path + name + '/', kind: 'directory' });
                    await walk(handle, path + name + '/');
                } else {
                    const bytes = new Uint8Array(await (await handle.getFile()).arrayBuffer());
                    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
                    const text = includeText || secrets.length ? new TextDecoder().decode(bytes) : '';
                    result.push({
                        path: path + name,
                        logical: new TextDecoder().decode(bytes.subarray(0, 512)).split('\0')[0],
                        bytes: bytes.length,
                        sha256: Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join(''),
                        protected: secrets.some(secret => text.includes(secret)),
                        ...(includeText ? { text } : {}),
                    });
                }
            }
        }
        await walk(await navigator.storage.getDirectory(), '');
        return result.sort((a, b) => a.path.localeCompare(b.path));
    }, { secrets, includeText });
}
