const { test, expect } = require("../fixtures");

/**
 * Helper: click the wallet button and wait for connection to complete.
 * Retries the click if the first attempt doesn't trigger a state change.
 */
async function connectWallet(page) {
  const walletText = page.locator("#wallet-text");

  for (let attempt = 0; attempt < 3; attempt++) {
    await page.locator("#wallet-btn").click();
    try {
      await expect(walletText).not.toHaveText("Connect Freighter", {
        timeout: 5000,
      });
      return;
    } catch {
      await page.waitForTimeout(500);
    }
  }
  await expect(walletText).not.toHaveText("Connect Freighter", {
    timeout: 5000,
  });
}

/**
 * Helper: navigate to the app and wait for full JS initialization.
 * The app logs "PoolStellar initialized" when DOMContentLoaded completes.
 * We also need to handle the case where WASM init fails and the message
 * never appears — fall back to waiting for the tab handlers to be attached.
 */
async function navigateAndWaitForInit(page) {
  await page.goto("/");
  // Wait for the app JS to initialize by checking that tab click handlers
  // are attached. We poll by clicking the deposit tab (already active)
  // and checking if it responds.
  await page.waitForFunction(
    () => {
      // Test if tabs are interactive: click withdraw, check if it switches
      const btn = document.querySelector("#tab-withdraw");
      if (!btn) return false;
      btn.click();
      const switched =
        document
          .querySelector("#tab-withdraw")
          ?.getAttribute("aria-selected") === "true";
      if (switched) {
        // Switch back to deposit
        document.querySelector("#tab-deposit")?.click();
      }
      return switched;
    },
    { timeout: 15000, polling: 500 },
  );
  // Ensure we're back on deposit tab
  await page.evaluate(() => document.querySelector("#tab-deposit")?.click());
}

test.describe("Deposit Tab", () => {
  test("deposit tab is active by default", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await expect(page.locator("#tab-deposit")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(page.locator("#panel-deposit")).toBeVisible();
  });

  test("clicking withdraw tab switches panel", async ({ page }) => {
    await navigateAndWaitForInit(page);

    await page.locator("#tab-withdraw").click();

    await expect(page.locator("#panel-withdraw")).toBeVisible();
    await expect(page.locator("#panel-deposit")).toBeHidden();
    await expect(page.locator("#tab-withdraw")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(page.locator("#tab-deposit")).toHaveAttribute(
      "aria-selected",
      "false",
    );
  });

  test("all four tabs are present and clickable", async ({ page }) => {
    await navigateAndWaitForInit(page);

    const tabs = ["deposit", "withdraw", "transfer", "transact"];
    for (const tab of tabs) {
      const tabBtn = page.locator(`#tab-${tab}`);
      await expect(tabBtn).toBeVisible();
      await tabBtn.click();
      await expect(page.locator(`#panel-${tab}`)).toBeVisible();
      await expect(tabBtn).toHaveAttribute("aria-selected", "true");
    }
  });

  test("deposit amount input has default value", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const amountInput = page.locator("#deposit-amount");
    await expect(amountInput).toHaveValue("10");
  });

  test("deposit button click with connected wallet", async ({ page }) => {
    await navigateAndWaitForInit(page);

    // Connect wallet first
    await connectWallet(page);

    // Deposit button should be enabled
    const depositBtn = page.locator("#btn-deposit");
    await expect(depositBtn).toBeEnabled();

    // Click deposit — this will attempt a transaction flow which will
    // likely error due to missing contract state, but validates the
    // click handler fires
    await depositBtn.click();

    // Verify the click handler fired by checking for loading state
    // or an error toast (either means the handler executed)
    const indicator = page.locator(
      '.btn-loading:not(.hidden), [class*="toast"], .toast',
    );
    await expect(indicator.first()).toBeVisible({ timeout: 5000 });
  });
});
