const { test, expect } = require('@playwright/test');

test.describe('Authentication Flows', () => {
  test('should show registration and login layout elements', async ({ page }) => {
    await page.goto('/');
    
    // Check brand/logo is visible
    await expect(page.locator('.brand')).toBeVisible();

    // Check we see sign in titles
    await expect(page.locator('h2')).toContainText('Sign in to your workspace');
    
    // Toggle registration view
    await page.click('text=Need an account? Register');
    await expect(page.locator('h2')).toContainText('Start scanning safely');
  });
});
