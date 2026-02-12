const { test, expect } = require("../fixtures");

/**
 * Helper: click the wallet button and wait for connection to complete.
 * Retries the click if the first attempt doesn't trigger a state change
 * (can happen if the page scripts haven't fully initialized yet).
 */
async function connectWallet(page) {
  const walletText = page.locator("#wallet-text");

  for (let attempt = 0; attempt < 3; attempt++) {
    await page.locator("#wallet-btn").click();
    try {
      await expect(walletText).not.toHaveText("Connect Freighter", {
        timeout: 5000,
      });
      return; // success
    } catch {
      // Retry: the page may not have been fully initialized
      await page.waitForTimeout(500);
    }
  }
  // Final attempt — let it throw on failure
  await expect(walletText).not.toHaveText("Connect Freighter", {
    timeout: 5000,
  });
}

test.describe("Wallet Connection", () => {
  test("page loads with Connect Freighter button", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const walletBtn = page.locator("#wallet-btn");
    await expect(walletBtn).toBeVisible();

    const walletText = page.locator("#wallet-text");
    await expect(walletText).toHaveText("Connect Freighter");
  });

  test("clicking Connect Freighter connects the wallet", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await connectWallet(page);

    // Verify truncated address is displayed
    const walletText = page.locator("#wallet-text");
    const text = await walletText.textContent();
    expect(text.length).toBeGreaterThan(5);
    expect(text).toContain("...");

    // Verify the button has the connected styling
    await expect(page.locator("#wallet-btn")).toHaveClass(/border-emerald-500/);

    // Verify the dropdown icon is now visible
    await expect(page.locator("#wallet-dropdown-icon")).toBeVisible();
  });

  test("deposit button becomes enabled after wallet connection", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Initially disabled
    const depositBtn = page.locator("#btn-deposit");
    await expect(depositBtn).toBeDisabled();

    // Connect wallet
    await connectWallet(page);

    // Now enabled
    await expect(depositBtn).toBeEnabled();
  });

  test("wallet disclaimer hides after connection", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const disclaimer = page.locator("#wallet-disclaimer-deposit");
    await expect(disclaimer).toBeVisible();

    // Connect
    await connectWallet(page);

    await expect(disclaimer).toBeHidden();
  });

  test("network name updates after connection", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Connect
    await connectWallet(page);

    // Network should show TESTNET (from mock)
    const network = page.locator("#network-name");
    await expect(network).toHaveText("TESTNET", { timeout: 5000 });
  });
});
