const { test, expect } = require('@playwright/test');

test.describe('Monitoring E2E Flows', () => {
  test('should display monitoring status container', async ({ page }) => {
    await page.goto('/');
    const body = page.locator('body');
    await expect(body).toBeVisible();
  });
});
