/**
 * Custom Playwright fixtures that:
 * 1. Launch Chromium with Freighter extension loaded via persistent context
 * 2. Inject the Freighter message mock via addInitScript
 * 3. Provide a pre-configured page pointed at the local dev server
 */

const { test: base, chromium } = require("@playwright/test");
const path = require("path");
const fs = require("fs");

const FREIGHTER_MOCK_PATH = path.join(
  __dirname,
  "helpers",
  "freighter-mock.js",
);
const EXTENSION_DIR = path.join(__dirname, ".freighter-extension");

// Read the mock script source
const freighterMockSource = fs.readFileSync(FREIGHTER_MOCK_PATH, "utf8");

const test = base.extend({
  testPublicKey: [
    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    { option: true },
  ],

  // Override context to use persistent context with extension
  context: async ({ testPublicKey }, use) => {
    if (!fs.existsSync(path.join(EXTENSION_DIR, "manifest.json"))) {
      throw new Error(
        "Freighter extension not found. Run: npm run test:e2e:download-extension",
      );
    }

    const context = await chromium.launchPersistentContext("", {
      channel: "chromium",
      args: [
        "--headless=new",
        `--disable-extensions-except=${EXTENSION_DIR}`,
        `--load-extension=${EXTENSION_DIR}`,
      ],
    });

    // Inject Freighter mock at context level so it runs on every page
    // (including the initial blank page) before any scripts execute.
    await context.addInitScript(`
      ${freighterMockSource}
      installFreighterMock({
        publicKey: '${testPublicKey}',
      });
    `);

    await use(context);
    await context.close();
  },

  // Override page: reuse the first page from the persistent context
  // (persistent contexts always open with one blank page).
  page: async ({ context }, use) => {
    const pages = context.pages();
    const page = pages.length > 0 ? pages[0] : await context.newPage();
    await use(page);
  },
});

const expect = test.expect;

module.exports = { test, expect };
