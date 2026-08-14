// Top-level view navigation helpers.
//
// The nav buttons in app/index.html have stable data-testid attributes so
// tests don't depend on button text or aria labels. Each helper clicks the
// nav button and waits a short beat for the view panel to mount/update.

const VIEW_TRANSITION_MS = 500;

export async function gotoDashboard(page) {
  await page.getByTestId('nav-dashboard').click();
  await page.waitForTimeout(VIEW_TRANSITION_MS);
}

export async function gotoMoveFunds(page) {
  await page.getByTestId('nav-move-funds').click();
  await page.waitForTimeout(VIEW_TRANSITION_MS);
}

export async function gotoAdvanced(page) {
  await page.getByTestId('nav-advanced').click();
  await page.waitForTimeout(VIEW_TRANSITION_MS);
}

export async function gotoDisclosure(page) {
  await page.getByTestId('nav-disclosure').click();
  await page.waitForTimeout(VIEW_TRANSITION_MS);
}
