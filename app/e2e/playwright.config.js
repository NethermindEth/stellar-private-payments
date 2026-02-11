const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
    testDir: './tests',
    timeout: 30_000,
    expect: { timeout: 10_000 },
    fullyParallel: false,
    retries: process.env.CI ? 2 : 0,
    workers: 1,
    reporter: process.env.CI ? 'github' : 'list',

    outputDir: './test-results',

    use: {
        baseURL: 'http://localhost:8000',
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
    },

    webServer: {
        command: 'npx serve ../dist -l 8000 --no-clipboard',
        port: 8000,
        reuseExistingServer: !process.env.CI,
        timeout: 10_000,
    },
});
