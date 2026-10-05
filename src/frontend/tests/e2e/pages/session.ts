import type { Page } from "@playwright/test";

// The token is not verified; it only puts the page in a signed-in state.
export async function signedIn(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("auth", JSON.stringify({ value: "e2e-session-token" }));
  });
}
