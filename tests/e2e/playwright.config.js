// Playwright settings. BASE_URL = the website to test (CodeBuild reads it from the stack outputs).
const { defineConfig, devices } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./specs",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  retries: process.env.CI ? 1 : 0,          // one retry in CodeBuild to absorb a network blip
  reporter: [
    ["list"],
    ["junit", { outputFile: "results/junit.xml" }],              // CodeBuild test report
    ["html", { outputFolder: "playwright-report", open: "never" }], // full report with traces
  ],
  use: {
    baseURL: process.env.BASE_URL || "http://localhost:8080",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
