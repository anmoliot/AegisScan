const { test, expect } = require('@playwright/test');

test.describe('Findings E2E Flows', () => {
  test('should display finding list placeholder', async ({ page }) => {
    await page.goto('/');
    const content = page.locator('body');
    await expect(content).toBeVisible();
  });
});
