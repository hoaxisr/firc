import { expect, test, type Page } from "@playwright/test";

import { answer, oldDaemon, openSettings } from "./pages/settings";

type Mode = "old" | "502" | "new" | "stuck";

async function startRestart(page: Page, mode: { value: Mode }) {
  let restarted = false;
  await openSettings(
    page,
    async (route) => {
      if (!restarted) {
        await route.fulfill({ json: answer({}, ["app.link"]) });
        return;
      }
      if (mode.value === "old") await route.fulfill({ json: oldDaemon(["app.link"]) });
      else if (mode.value === "502") await route.fulfill({ status: 502, body: "" });
      else if (mode.value === "stuck")
        await route.fulfill({ json: answer({}, ["app.link"], undefined, "boot-1", false) });
      else await route.fulfill({ json: answer({}, [], undefined, "boot-2") });
    },
    {
      onRestart: async (route) => {
        restarted = true;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }).click();
}

const segment = (page: Page, n: number) => page.locator(`[data-seg="${n}"]`);

test("the overlay walks the three segments and closes on a new boot", async ({ page }) => {
  const mode = { value: "old" as Mode };
  await startRestart(page, mode);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay).toBeVisible();
  await expect(overlay.getByRole("status")).toContainText("Stopping the daemon…");
  await expect(segment(page, 1)).toHaveAttribute("data-state", "current");
  await expect(segment(page, 2)).toHaveAttribute("data-state", "idle");

  mode.value = "502";
  await expect(overlay.getByRole("status")).toContainText("Waiting for it to start…", {
    timeout: 5000,
  });
  await expect(segment(page, 1)).toHaveAttribute("data-state", "done");
  await expect(segment(page, 2)).toHaveAttribute("data-state", "current");

  mode.value = "new";
  await expect(overlay.getByRole("status")).toContainText("Done", { timeout: 5000 });
  for (const n of [1, 2, 3]) {
    await expect(segment(page, n)).toHaveAttribute("data-state", "done");
    await expect(segment(page, n)).toHaveCSS("opacity", "1");
  }
  await expect(overlay).toHaveCount(0, { timeout: 5000 });
  await expect(page.getByText("The daemon is back")).toHaveCount(0);
  await expect(page.getByText("Restarting the daemon…")).toHaveCount(0);
});

test("a restart that did not start turns the ring red and Close dismisses it", async ({ page }) => {
  const mode = { value: "stuck" as Mode };
  await startRestart(page, mode);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay.getByRole("status")).toContainText("The restart did not start", {
    timeout: 5000,
  });
  await expect(overlay).toHaveAttribute("data-failed", "true");
  const close = overlay.getByRole("button", { name: "Close" });
  expect(await close.evaluate((el) => getComputedStyle(el).borderTopWidth)).toBe("1px");
  expect(await close.evaluate((el) => getComputedStyle(el).backgroundColor)).not.toBe(
    "rgba(0, 0, 0, 0)",
  );
  await expect(close).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(overlay).toBeVisible();
  await close.click();
  await expect(overlay).toHaveCount(0);
});

test("the daemon not coming back before the limit shows the failure", async ({ page }) => {
  const mode = { value: "502" as Mode };
  await startRestart(page, mode);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay).toBeVisible();
  await page.evaluate(async () => {
    const path = "/src/modules/settings/settings.svelte.ts";
    const store = await import(path);
    store.restartLimit.ms = 1500;
  });
  await expect(overlay.getByRole("status")).toContainText("The daemon did not come back", {
    timeout: 10_000,
  });
  await expect(overlay).toHaveAttribute("data-failed", "true");
  await overlay.getByRole("button", { name: "Close" }).click();
  await expect(overlay).toHaveCount(0);
});

test("the overlay blocks the page underneath", async ({ page }) => {
  const mode = { value: "502" as Mode };
  await startRestart(page, mode);
  await expect(page.getByTestId("restart-overlay")).toBeVisible();
  const box = await page.getByRole("button", { name: "Save", exact: true }).boundingBox();
  expect(box).not.toBeNull();
  const covered = await page.evaluate(
    ([x, y]) =>
      document.elementFromPoint(x, y)?.closest('[data-testid="restart-overlay"]') !== null,
    [box!.x + box!.width / 2, box!.y + box!.height / 2],
  );
  expect(covered).toBe(true);
});

test("reduced motion runs no animation on the overlay", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  const mode = { value: "502" as Mode };
  await startRestart(page, mode);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay).toBeVisible();
  const running = await overlay.evaluate(
    (el) =>
      el
        .getAnimations({ subtree: true })
        .filter((a) => a.playState === "running" && a.effect?.getTiming().iterations === Infinity)
        .length,
  );
  expect(running).toBe(0);
});

test("the current segment pulses without reduced motion", async ({ page }) => {
  const mode = { value: "502" as Mode };
  await startRestart(page, mode);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay).toBeVisible();
  const running = await overlay.evaluate(
    (el) =>
      el
        .getAnimations({ subtree: true })
        .filter((a) => a.playState === "running" && a.effect?.getTiming().iterations === Infinity)
        .length,
  );
  expect(running).toBeGreaterThan(0);
});

test("a moved web port shows the overlay with its own text", async ({ page }) => {
  await page.route("http://localhost:8081/**", async (route) => {
    await new Promise((r) => setTimeout(r, 4000));
    await route.fulfill({ contentType: "text/html", body: "<html><title>moved</title></html>" });
  });
  await openSettings(
    page,
    async (route) => {
      if (route.request().method() === "PUT") {
        await route.fulfill({ json: { applied: [], pendingRestart: ["app.httpWeb.host.port"] } });
        return;
      }
      await route.fulfill({ json: answer() });
    },
    { onRestart: (route) => route.fulfill({ status: 202, json: { restarting: true } }) },
  );
  await page.getByRole("spinbutton", { name: "WebUI port" }).fill("8081");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Save and restart" }).click();
  await expect(page.getByTestId("restart-overlay").getByRole("status")).toContainText(
    "Moving to the new port…",
  );
});

test("the overlay is a labelled modal dialog that holds the keyboard", async ({ page }) => {
  const mode = { value: "502" as Mode };
  await startRestart(page, mode);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay).toHaveAttribute("role", "dialog");
  await expect(overlay).toHaveAttribute("aria-modal", "true");
  await expect(overlay).toHaveAttribute("aria-label", /.+/);
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press("Tab");
    const inside = await page.evaluate(
      () => document.activeElement?.closest('[data-testid="restart-overlay"]') !== null,
    );
    expect(inside).toBe(true);
  }
});

test("an expired login during the wait clears the overlay", async ({ page }) => {
  let restarted = false;
  await openSettings(
    page,
    async (route) => {
      if (!restarted) return route.fulfill({ json: answer({}, ["app.link"]) });
      return route.fulfill({ status: 401, body: "" });
    },
    {
      onRestart: async (route) => {
        restarted = true;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }).click();
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0, { timeout: 5000 });
});

test("a restart that was under way and then stopped says the daemon did not restart", async ({
  page,
}) => {
  const mode = { value: "old" as Mode };
  await startRestart(page, mode);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay.getByRole("status")).toContainText("Stopping the daemon…");
  await page.waitForTimeout(1500);
  mode.value = "stuck";
  await expect(overlay.getByRole("status")).toContainText("The daemon did not restart", {
    timeout: 5000,
  });
});

test("a second restart within the linger keeps its overlay", async ({ page }) => {
  let restarts = 0;
  let boot = "boot-1";
  await openSettings(
    page,
    async (route) => {
      if (restarts === 0) return route.fulfill({ json: answer({}, ["app.link"]) });
      if (restarts === 1)
        return route.fulfill({ json: answer({}, ["app.link"], undefined, "boot-2") });
      return route.fulfill({ json: answer({}, ["app.link"], undefined, boot, true) });
    },
    {
      onRestart: async (route) => {
        restarts += 1;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }).click();
  await expect(page.getByText("Done")).toBeVisible({ timeout: 5000 });
  boot = "boot-2";
  await page
    .getByTestId("settings-banner")
    .getByRole("button", { name: "Restart" })
    .dispatchEvent("click");
  await page.waitForTimeout(1500);
  await expect(page.getByTestId("restart-overlay")).toBeVisible();
});
