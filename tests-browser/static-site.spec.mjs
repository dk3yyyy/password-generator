import { expect, test } from '@playwright/test';

const localOrigin = 'http://127.0.0.1:8766';

async function instrumentPage(page) {
  const requests = [];
  const consoleErrors = [];
  page.on('request', (request) => requests.push({ method: request.method(), url: request.url() }));
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  await page.addInitScript(() => {
    window.__cspViolations = [];
    document.addEventListener('securitypolicyviolation', (event) => {
      window.__cspViolations.push(`${event.violatedDirective}:${event.blockedURI}`);
    });
  });
  return { requests, consoleErrors };
}

test('generates a password without storage, outbound requests, CSP errors, or secret announcements', async ({ page }, testInfo) => {
  const observed = await instrumentPage(page);
  await page.goto('/');
  await page.locator('#count').fill('2');
  await page.locator('#generate-button').click();

  await expect(page.locator('.result-item')).toHaveCount(2);
  await expect(page.locator('.password-value').first()).toHaveText(/\S{20}/);
  await expect(page.locator('#generation-status')).toHaveText('2 credentials generated.');
  await expect(page.locator('#results')).not.toHaveAttribute('aria-live', /.+/);

  const runtimeState = await page.evaluate(() => ({
    localStorage: localStorage.length,
    sessionStorage: sessionStorage.length,
    cspViolations: window.__cspViolations,
  }));
  expect(runtimeState).toEqual({ localStorage: 0, sessionStorage: 0, cspViolations: [] });
  expect(observed.requests.every(({ method, url }) => method === 'GET' && url.startsWith(localOrigin))).toBe(true);
  expect(observed.consoleErrors).toEqual([]);

  if (testInfo.project.name === 'desktop') {
    await page.screenshot({ path: testInfo.outputPath('static-desktop.png'), fullPage: true });
  }
});

test('loads the same-origin EFF wordlist and renders a passphrase', async ({ page }) => {
  const observed = await instrumentPage(page);
  await page.goto('/');
  await page.locator('#passphrase-tab').click();
  await page.locator('input[name="add_number"]').check();
  await page.locator('#generate-button').click();

  const result = page.locator('.password-value');
  await expect(result).toHaveCount(1);
  await expect(result).toHaveText(/[0-9]{2}$/);
  await expect(page.locator('#wordlist-status')).toHaveText('EFF long wordlist · 7,776 validated unique words');
  expect(observed.requests.some(({ method, url }) => method === 'GET' && url === `${localOrigin}/eff_large_wordlist.txt`)).toBe(true);
  expect(observed.requests.every(({ method, url }) => method === 'GET' && url.startsWith(localOrigin))).toBe(true);
  expect(observed.consoleErrors).toEqual([]);
});

test('supports keyboard tab navigation and a manual clipboard fallback', async ({ page }) => {
  await page.goto('/');
  await page.locator('#random-tab').focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('#passphrase-tab')).toBeFocused();
  await expect(page.locator('#passphrase-tab')).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('ArrowLeft');
  await expect(page.locator('#random-tab')).toBeFocused();

  await page.locator('#generate-button').click();
  await page.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: () => Promise.reject(new Error('blocked in test')) },
    });
  });
  const credential = await page.locator('.password-value').textContent();
  await page.locator('.copy-button').click();
  await expect(page.locator('#error-message')).toContainText('copy it manually');
  expect(await page.evaluate(() => window.getSelection().toString())).toBe(credential);
});

test('fits a narrow viewport without horizontal overflow', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile', 'mobile-only layout assertion');
  await page.goto('/');
  await page.locator('#generate-button').click();
  const dimensions = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
});
