import { expect, test } from "@playwright/test";

import { answer, oldDaemon, openSettings } from "./pages/settings";

// Catches restart buttons offered for a live-only change, or a PUT carrying unchanged keys.
test("a live-only change is saved with one button", async ({ page }) => {
  const puts: unknown[] = [];
  await openSettings(page, async (route) => {
    if (route.request().method() === "PUT") {
      puts.push(route.request().postDataJSON());
      await route.fulfill({
        json: {
          applied: ["app.dnsProxy.upstream.address", "app.dnsProxy.disableDropAAAA"],
          pendingRestart: [],
        },
      });
      return;
    }
    await route.fulfill({ json: answer() });
  });
  await page.getByRole("textbox", { name: "Upstream DNS", exact: true }).fill("1.1.1.1");
  await page.getByRole("switch", { name: "Drop AAAA" }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();

  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Save settings")).toBeVisible();
  await expect(dialog.getByText("Applies at once")).toBeVisible();
  await expect(dialog.getByText("Needs a daemon restart")).toHaveCount(0);
  const row = dialog.locator('[data-key="app.dnsProxy.upstream.address"]');
  await expect(row).toContainText("127.0.0.1");
  await expect(row).toContainText("1.1.1.1");
  const aaaa = dialog.locator('[data-key="app.dnsProxy.disableDropAAAA"]');
  await expect(aaaa.locator(".was")).toHaveText("on");
  await expect(aaaa.locator(".now")).toHaveText("off");
  await expect(dialog.getByRole("button", { name: "Save and restart" })).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Apply without restart" })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Save", exact: true }).click();

  await expect(page.getByRole("dialog")).toBeHidden();
  expect(puts).toEqual([
    {
      settings: {
        "app.dnsProxy.upstream.address": "1.1.1.1",
        "app.dnsProxy.disableDropAAAA": true,
      },
    },
  ]);
  await expect(page.getByTestId("settings-counter")).toHaveText("0 settings changed");
});

// Catches unmatchedTtl missing from the catalogue, filed in the wrong class, or sent as a string.
test("unmatchedTtl renders its default and saves as a live change", async ({ page }) => {
  const puts: unknown[] = [];
  await openSettings(page, async (route) => {
    if (route.request().method() === "PUT") {
      puts.push(route.request().postDataJSON());
      await route.fulfill({ json: { applied: ["app.dnsProxy.unmatchedTtl"], pendingRestart: [] } });
      return;
    }
    await route.fulfill({ json: answer() });
  });
  const field = page.getByRole("spinbutton", { name: "TTL of answers outside the rules" });
  await expect(field).toHaveValue("60");
  await field.fill("90");
  await page.getByRole("button", { name: "Save", exact: true }).click();

  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Applies at once")).toBeVisible();
  await expect(dialog.getByText("Needs a daemon restart")).toHaveCount(0);
  const row = dialog.locator('[data-key="app.dnsProxy.unmatchedTtl"]');
  await expect(row.locator(".was")).toHaveText("60 s");
  await expect(row.locator(".now")).toHaveText("90 s");
  await dialog.getByRole("button", { name: "Save", exact: true }).click();

  await expect(page.getByRole("dialog")).toBeHidden();
  expect(puts).toEqual([{ settings: { "app.dnsProxy.unmatchedTtl": 90 } }]);
  await expect(page.getByTestId("settings-counter")).toHaveText("0 settings changed");
});

// Catches a 500 after the write being taken at its word instead of re-reading what is saved.
test("a save that fails after the write re-reads what the daemon holds", async ({ page }) => {
  let gets = 0;
  let written = false;
  await openSettings(page, async (route) => {
    if (route.request().method() === "PUT") {
      written = true;
      await route.fulfill({
        status: 500,
        json: {
          error:
            "saved to firc.conf, but a live setting could not be applied (out of memory); it applies at the next restart",
        },
      });
      return;
    }
    gets++;
    await route.fulfill({
      json: answer(written ? { "app.dnsProxy.upstream.address": "1.1.1.1" } : {}),
    });
  });
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  await upstream.fill("1.1.1.1");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByTestId("settings-counter")).toHaveText("0 settings changed");
  expect(gets).toBe(2);
  await expect(upstream).toHaveValue("1.1.1.1");
});

test("a refusal keeps the dialog open and marks the field", async ({ page }) => {
  await openSettings(page, async (route) => {
    if (route.request().method() === "PUT") {
      await route.fulfill({
        status: 400,
        json: { error: "not an IPv4 or IPv6 address", field: "app.dnsProxy.upstream.address" },
      });
      return;
    }
    await route.fulfill({ json: answer() });
  });
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  await upstream.fill("dns.example");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(dialog.getByText("not an IPv4 or IPv6 address")).toBeVisible();
  await expect(dialog.locator('[data-key="app.dnsProxy.upstream.address"]')).toHaveClass(/invalid/);
  await expect(upstream).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
});

// The daemon owns the range; its refusal must keep the dialog open and mark the field.
test("unmatchedTtl's refusal keeps the dialog open and marks the field", async ({ page }) => {
  await openSettings(page, async (route) => {
    if (route.request().method() === "PUT") {
      await route.fulfill({
        status: 400,
        json: {
          error: "0 (off), or 1 second to 86400 seconds",
          field: "app.dnsProxy.unmatchedTtl",
        },
      });
      return;
    }
    await route.fulfill({ json: answer() });
  });
  const field = page.getByRole("spinbutton", { name: "TTL of answers outside the rules" });
  await field.fill("999999");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(dialog.getByText("0 (off), or 1 second to 86400 seconds")).toBeVisible();
  await expect(dialog.locator('[data-key="app.dnsProxy.unmatchedTtl"]')).toHaveClass(/invalid/);
  await expect(field).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
});

// Catches "apply without restart" restarting, no warning before a restart change, or no banner after.
test("apply without restart saves, and the banner appears", async ({ page }) => {
  const puts: unknown[] = [];
  let restarts = 0;
  await openSettings(
    page,
    async (route) => {
      if (route.request().method() === "PUT") {
        puts.push(route.request().postDataJSON());
        await route.fulfill({
          json: {
            applied: ["app.dnsProxy.upstream.address"],
            pendingRestart: ["app.addressPool.maxNames"],
          },
        });
        return;
      }
      await route.fulfill({ json: answer() });
    },
    {
      onRestart: async (route) => {
        restarts++;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByRole("textbox", { name: "Upstream DNS", exact: true }).fill("1.1.1.1");
  await page.getByRole("spinbutton", { name: "Domains in the pool, at most" }).fill("4096");
  await page.getByRole("button", { name: "Save", exact: true }).click();

  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Applies at once")).toBeVisible();
  await expect(dialog.getByText("Needs a daemon restart")).toBeVisible();
  const names = dialog.locator('[data-key="app.addressPool.maxNames"]');
  await expect(names).toContainText("65536");
  await expect(names).toContainText("4096");
  await expect(dialog.getByText("DNS will stop answering for a few seconds.")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Cancel" })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Save and restart" })).toBeVisible();
  await dialog.getByRole("button", { name: "Apply without restart" }).click();

  await expect(page.getByRole("dialog")).toBeHidden();
  expect(puts).toEqual([
    { settings: { "app.dnsProxy.upstream.address": "1.1.1.1", "app.addressPool.maxNames": 4096 } },
  ]);
  expect(restarts).toBe(0);
  await expect(page.getByTestId("settings-banner")).toContainText("1 setting waits for a restart");
  await expect(page.locator('[data-row="app.addressPool.maxNames"]')).toContainText(
    "waits for a restart",
  );
});

// Catches a restart sent before the PUT lands, polling that stops at the old daemon's answer, or a stale banner.
test("save and restart follows the restart until the daemon is back", async ({ page }) => {
  const order: string[] = [];
  let restarted = false;
  let wentDown = false;
  await openSettings(
    page,
    async (route) => {
      if (route.request().method() === "PUT") {
        order.push("PUT");
        await route.fulfill({
          json: { applied: [], pendingRestart: ["app.addressPool.maxNames"] },
        });
        return;
      }
      if (!restarted) {
        await route.fulfill({ json: answer() });
      } else if (!wentDown) {
        wentDown = true;
        await route.abort("connectionrefused");
      } else {
        await route.fulfill({
          json: answer({ "app.addressPool.maxNames": 4096 }, [], undefined, "boot-2"),
        });
      }
    },
    {
      onRestart: async (route) => {
        order.push("RESTART");
        restarted = true;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByRole("spinbutton", { name: "Domains in the pool, at most" }).fill("4096");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Save and restart" }).click();

  await expect.poll(() => wentDown, { timeout: 10_000 }).toBe(true);
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0, { timeout: 10_000 });
  await expect(page.getByTestId("settings-banner")).toHaveCount(0);
  expect(order).toEqual(["PUT", "RESTART"]);
  await expect(page.getByRole("spinbutton", { name: "Domains in the pool, at most" })).toHaveValue(
    "4096",
  );
});

test("a restart settles only on an answer with another boot", async ({ page }) => {
  let restarted = false;
  let polls = 0;
  await openSettings(
    page,
    async (route) => {
      if (!restarted) {
        await route.fulfill({ json: answer({}, ["app.link"]) });
        return;
      }
      polls += 1;
      if (polls === 1) {
        await route.fulfill({ status: 503, json: { error: "busy" } });
      } else if (polls === 2) {
        await route.fulfill({ json: oldDaemon() });
      } else if (polls === 3) {
        await route.abort("connectionrefused");
      } else if (polls === 4) {
        await route.fulfill({ json: oldDaemon(["app.link"]) });
      } else {
        await route.fulfill({ json: answer({}, [], undefined, "boot-2") });
      }
    },
    {
      onRestart: async (route) => {
        restarted = true;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }).click();
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0, { timeout: 15_000 });
  await expect(page.getByText("The daemon is back")).toHaveCount(0);
  expect(polls).toBe(5);
});

test("a restart behind a proxy settles after 502 and 504 and a new boot", async ({ page }) => {
  let restarted = false;
  let polls = 0;
  await openSettings(
    page,
    async (route) => {
      if (!restarted) {
        await route.fulfill({ json: answer({}, ["app.link"]) });
        return;
      }
      polls += 1;
      if (polls === 1) {
        await route.fulfill({ status: 502, json: { error: "bad gateway" } });
      } else if (polls === 2) {
        await route.fulfill({ status: 504, json: { error: "gateway timeout" } });
      } else {
        await route.fulfill({ json: answer({}, [], undefined, "boot-2") });
      }
    },
    {
      onRestart: async (route) => {
        restarted = true;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }).click();
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0, { timeout: 10_000 });
  await expect(page.getByText("The daemon is back")).toHaveCount(0);
  await expect(page.getByTestId("settings-banner")).toHaveCount(0);
  expect(polls).toBe(3);
});

test("a restart that did not start stops the wait with an error", async ({ page }) => {
  let restarted = false;
  let polls = 0;
  await openSettings(
    page,
    async (route) => {
      if (!restarted) {
        await route.fulfill({ json: answer({}, ["app.link"]) });
        return;
      }
      polls += 1;
      await route.fulfill({ json: answer({}, ["app.link"]) });
    },
    {
      onRestart: async (route) => {
        restarted = true;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }).click();
  await expect(page.getByTestId("restart-overlay").getByRole("status")).toContainText(
    "The restart did not start",
    { timeout: 5000 },
  );
  await expect(page.getByText("The restart did not start")).toHaveCount(1);
  await expect(page.getByText("The daemon is back")).toHaveCount(0);
  expect(polls).toBeLessThanOrEqual(3);
});

// Catches a poll with no deadline hanging the restart loop on a connection the router drops.
test("a poll that never answers counts as the daemon gone", async ({ page }) => {
  let restarted = false;
  let polls = 0;
  await openSettings(
    page,
    async (route) => {
      if (!restarted) {
        await route.fulfill({ json: answer({}, ["app.link"]) });
        return;
      }
      polls += 1;
      if (polls === 1) return;
      await route.fulfill({ json: answer({}, [], undefined, "boot-2") });
    },
    {
      onRestart: async (route) => {
        restarted = true;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }).click();
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0, { timeout: 10_000 });
  await expect(page.getByText("The daemon is back")).toHaveCount(0);
  expect(polls).toBe(2);
});

// Catches the banner's button doing nothing.
test("the banner restarts what waits", async ({ page }) => {
  let restarted = false;
  let wentDown = false;
  await openSettings(
    page,
    async (route) => {
      if (!restarted) {
        await route.fulfill({ json: answer({}, ["app.link"]) });
      } else if (!wentDown) {
        wentDown = true;
        await route.abort("connectionrefused");
      } else {
        await route.fulfill({ json: answer({}, [], undefined, "boot-2") });
      }
    },
    {
      onRestart: async (route) => {
        restarted = true;
        await route.fulfill({ status: 202, json: { restarting: true } });
      },
    },
  );
  await page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }).click();
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0, { timeout: 10_000 });
  await expect(page.getByTestId("settings-banner")).toHaveCount(0);
  expect(restarted).toBe(true);
});

// Catches a banner restart over unsaved edits, which the reload then silently discards.
test("the banner will not restart over unsaved edits", async ({ page }) => {
  let restarted = false;
  await openSettings(page, (route) => route.fulfill({ json: answer({}, ["app.link"]) }), {
    onRestart: async (route) => {
      restarted = true;
      await route.fulfill({ status: 202, json: { restarting: true } });
    },
  });
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  await upstream.fill("1.1.1.1");
  const restart = page.getByTestId("settings-banner").getByRole("button", { name: "Restart" });
  await expect(restart).toHaveClass(/inactive/);
  await restart.hover();
  await expect(page.getByText("Save or reset your changes first")).toBeVisible();
  await restart.click();
  await page.waitForTimeout(500);
  expect(restarted).toBe(false);
  await expect(upstream).toHaveValue("1.1.1.1");
});

// Catches the page waiting on the old port for a daemon that will never answer there.
test("a moved web port sends the page to the new port", async ({ page }) => {
  await page.route("http://localhost:8081/**", (route) =>
    route.fulfill({ contentType: "text/html", body: "<html><title>moved</title></html>" }),
  );
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
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByText("After the restart the page will open on port 8081."),
  ).toBeVisible();
  await dialog.getByRole("button", { name: "Save and restart" }).click();
  await page.waitForURL("http://localhost:8081/", { timeout: 10_000 });
});
