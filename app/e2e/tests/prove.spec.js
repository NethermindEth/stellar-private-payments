const { test, expect } = require("../fixtures");

/**
 * Helper: click the wallet button and wait for connection to complete.
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

test.describe("Prove (Deposit Flow)", () => {
  // The deposit flow downloads large ZK artifacts (~13 MB total)
  test.setTimeout(120_000);

  test("connect wallet and click deposit — capture logs", async ({ page }) => {
    const logs = [];

    page.on("console", (msg) => {
      const type = msg.type();
      const text = msg.text();
      logs.push({ type, text });
      console.log(`[browser:${type}] ${text}`);
    });

    page.on("pageerror", (err) => {
      logs.push({ type: "pageerror", text: err.message });
      console.log(`[browser:pageerror] ${err.message}`);
    });

    await page.goto("/");

    // Wait for the wallet click handler to be attached by polling
    // until clicking #wallet-btn triggers the Wallet.connect() flow
    await page.waitForFunction(
      () => {
        const btn = document.querySelector("#wallet-btn");
        if (!btn) return false;
        // Check if the click handler is attached by looking for
        // Wallet.init() side-effects: it calls updateSubmitButtons(false)
        // which disables #btn-deposit
        const depositBtn = document.querySelector("#btn-deposit");
        return depositBtn && depositBtn.disabled;
      },
      { timeout: 15000, polling: 500 },
    );

    await connectWallet(page);

    // Click the Deposit button
    const depositBtn = page.locator("#btn-deposit");
    await expect(depositBtn).toBeEnabled();
    await depositBtn.click();

    // Wait for the deposit flow to produce log output.
    // The flow downloads ZK artifacts and attempts proof generation,
    // eventually hitting an error due to missing contract state.
    await page.waitForTimeout(15000);

    // Print summary
    console.log("\n--- Console Log Summary ---");
    console.log(`Total messages: ${logs.length}`);
    for (const entry of logs) {
      console.log(`  [${entry.type}] ${entry.text}`);
    }
    console.log("--- End Summary ---\n");

    expect(logs.length).toBeGreaterThan(0);
  });
});
