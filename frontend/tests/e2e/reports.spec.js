const { test, expect } = require('@playwright/test');

test.describe('Reports E2E Flows', () => {
  test('should display reports container', async ({ page }) => {
    await page.goto('/');
    const main = page.locator('main');
    await expect(main).toBeVisible();
  });
});
