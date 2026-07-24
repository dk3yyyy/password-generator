import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests-browser',
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:8766',
    browserName: 'chromium',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: 'python -m http.server 8766 --bind 127.0.0.1 --directory docs',
    url: 'http://127.0.0.1:8766',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
