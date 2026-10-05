import { expect, test } from "@playwright/test";

import { AuthPage } from "./pages/AuthPage";
import { signedIn } from "./pages/session";

test.describe("Authentication", () => {
  let authPage: AuthPage;

  test.beforeEach(async ({ page }) => {
    authPage = new AuthPage(page);
    await page.route("**/interfaces", async (route) => {
      await route.fulfill({ json: { interfaces: [] } });
    });
  });

  test("should display login form", async ({ page }) => {
    await authPage.goto();
    await expect(authPage.loginInput).toBeVisible();
    await expect(authPage.passwordInput).toBeVisible();
  });

  test("should login successfully", async ({ page }) => {
    await page.route("**/auth", async (route) => {
      await route.fulfill({ json: { token: "fake-token" } });
    });
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({ json: { groups: [] } });
    });

    await authPage.goto();
    await authPage.login("admin", "admin");

    await expect(page.locator(".group-controls")).toBeVisible();
  });

  // A 403 with a reason is what a wrong password gets; the login form must show it itself.
  test("should show error on failure", async ({ page }) => {
    await page.route("**/auth", async (route) => {
      await route.fulfill({ status: 403, json: { error: "Invalid credentials" } });
    });

    await authPage.goto();
    await authPage.login("admin", "wrong");

    await expect(authPage.signInButton).toHaveClass(/fail/);
  });

  // A 403 is a refused request, not a lost session; resetting on it logged the operator out.
  test("a 403 on an API route does not throw the session away", async ({ page }) => {
    await signedIn(page);
    await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: [] } }));
    await page.route("**/groups?with_rules=true", (route) =>
      route.fulfill({ status: 403, json: { error: "Forbidden" } }),
    );
    await page.goto("/");

    await expect(page.locator(".group-controls")).toBeVisible();
    const kept = await page.evaluate(() => localStorage.getItem("auth"));
    expect(kept).toContain("e2e-session-token");
  });

  test("should render the logo as inline svg", async ({ page }) => {
    await authPage.goto();
    const logo = page.locator(".logo-wrapper svg[aria-label='firc']");
    await expect(logo).toBeVisible();
    await expect(logo.locator("path.fill")).toHaveAttribute("fill", /url\(#/);
  });

  test("should show a static logo under reduced motion", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await authPage.goto();
    const fill = page.locator(".logo-wrapper svg path.fill");
    await expect(fill).toBeVisible();
    const state = await fill.evaluate((el) => ({
      opacity: getComputedStyle(el).opacity,
      name: getComputedStyle(el).animationName,
      running: el.getAnimations().length,
    }));
    expect(state).toEqual({ opacity: "1", name: "none", running: 0 });
    await expect(authPage.loginInput).toBeEnabled();
  });
});
