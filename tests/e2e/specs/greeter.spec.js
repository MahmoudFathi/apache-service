// End-to-end browser tests for the Greeter app. Tests tagged @smoke also run against production.
const { test, expect } = require("@playwright/test");

const EXPECTED_VERSION = process.env.EXPECTED_VERSION; // set by the pipeline, e.g. v7

test.describe("Greeter", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
  });

  test("page loads and shows the deployed version @smoke", async ({ page }) => {
    await expect(page).toHaveTitle("Greeter");
    await expect(page.getByRole("heading", { name: "Greeter" })).toBeVisible();
    const version = page.getByTestId("version");
    await expect(version).not.toHaveText(/loading|unavailable/);   // front end reached the API
    if (EXPECTED_VERSION) await expect(version).toHaveText(EXPECTED_VERSION);
  });

  test("greets the user by name @smoke", async ({ page }) => {
    await page.getByTestId("name-input").fill("Sam");
    await page.getByTestId("greet-button").click();
    await expect(page.getByTestId("result")).toHaveText("Hello, Sam!");
    await expect(page.getByTestId("error")).toBeEmpty();
  });

  test("Enter key submits the form", async ({ page }) => {
    await page.getByTestId("name-input").fill("Lina");
    await page.getByTestId("name-input").press("Enter");
    await expect(page.getByTestId("result")).toHaveText("Hello, Lina!");
  });

  test("trims spaces around the name", async ({ page }) => {
    await page.getByTestId("name-input").fill("   Ann   ");
    await page.getByTestId("greet-button").click();
    await expect(page.getByTestId("result")).toHaveText("Hello, Ann!");
  });

  test("empty name shows an error", async ({ page }) => {
    await page.getByTestId("greet-button").click();
    await expect(page.getByTestId("error")).toHaveText("Please enter your name.");
    await expect(page.getByTestId("result")).toBeEmpty();
  });

  test("name longer than 50 characters is rejected", async ({ page }) => {
    await page.getByTestId("name-input").fill("x".repeat(51));
    await page.getByTestId("greet-button").click();
    await expect(page.getByTestId("error")).toHaveText("Name must be 50 characters or fewer.");
  });

  test("HTML in the name is shown as text, not rendered", async ({ page }) => {
    await page.getByTestId("name-input").fill("<b>bold</b>");
    await page.getByTestId("greet-button").click();
    await expect(page.getByTestId("result")).toHaveText("Hello, <b>bold</b>!");
    await expect(page.getByTestId("result").locator("b")).toHaveCount(0);
  });

  test("no browser console errors while using the app", async ({ page }) => {
    const errors = [];
    page.on("console", (msg) => { if (msg.type() === "error") errors.push(msg.text()); });
    page.on("pageerror", (err) => errors.push(err.message));
    await page.reload();
    await page.getByTestId("name-input").fill("Console");
    await page.getByTestId("greet-button").click();
    await expect(page.getByTestId("result")).toHaveText("Hello, Console!");
    expect(errors).toEqual([]);
  });
});
