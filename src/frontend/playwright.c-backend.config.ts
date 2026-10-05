import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: "list",
  outputDir: "node_modules/.playwright-results-c-backend",
  use: {
    baseURL: process.env.FIRC_E2E_BASE_URL || "http://localhost:5173",
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: { executablePath: "/opt/pw-browsers/chromium-1194/chrome-linux/chrome" },
      },
    },
  ],
});
