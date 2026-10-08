import { expect, test } from "@playwright/test";

import { answer, CLASSES, openSettings } from "./pages/settings";

// Catches rows under the wrong heading, an uncounted change, or a restart setting not marked waiting.
test("the saved values show, with nothing counted as changed", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await expect(page.getByRole("textbox", { name: "Upstream DNS", exact: true })).toHaveValue(
    "127.0.0.1",
  );
  await expect(page.getByRole("spinbutton", { name: "Query timeout" })).toHaveValue("5000");
  await expect(page.getByRole("switch", { name: "Drop AAAA" })).toHaveAttribute(
    "aria-checked",
    "true",
  );
  await expect(page.getByTestId("settings-counter")).toHaveText("0 settings changed");
});

test("there is no fake PTR switch", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await expect(page.getByRole("switch", { name: "Drop AAAA" })).toBeVisible();
  await expect(page.getByText("PTR")).toHaveCount(0);
  await expect(page.locator('[data-row="app.dnsProxy.disableFakePTR"]')).toHaveCount(0);
});

// Catches rows filed by the WebUI's own list instead of the classes the daemon sends.
test("rows are filed under the class the daemon gives them", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const dns = page.locator('[data-section="dns"]');
  await expect(dns.locator('[data-group="live"]').getByText("Upstream DNS").first()).toBeVisible();
  await expect(dns.locator('[data-group="restart"]').getByText("Query timeout")).toBeVisible();
  await expect(dns.getByText("After a daemon restart")).toBeVisible();
  await expect(page.locator('[data-section="netfilter"] header')).toContainText(
    "The whole section applies after a restart",
  );
  await expect(page.locator('[data-section="dns"] header')).not.toContainText(
    "The whole section applies after a restart",
  );
});

test("a class the daemon changes moves the row", async ({ page }) => {
  const classes = { ...CLASSES, "app.dnsProxy.timeout": "live" };
  await openSettings(page, (r) => r.fulfill({ json: answer({}, [], classes) }));
  await expect(
    page.locator('[data-section="dns"] [data-group="live"]').getByText("Query timeout"),
  ).toBeVisible();
});

// Catches a missed edit in the counter, a border before any change, or a Reset leaving a field edited.
test("edits are counted and bordered, and Reset puts every one back", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  const names = page.getByRole("spinbutton", { name: "Domains in the pool, at most" });
  await expect(upstream).not.toHaveClass(/changed/);
  await upstream.fill("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
  await expect(upstream).toHaveClass(/changed-live/);
  await names.fill("4096");
  await expect(page.getByTestId("settings-counter")).toHaveText("2 settings changed");
  await expect(names).toHaveClass(/changed-restart/);
  await page.getByRole("button", { name: "Reset" }).click();
  await expect(page.getByTestId("settings-counter")).toHaveText("0 settings changed");
  await expect(upstream).toHaveValue("127.0.0.1");
  await expect(names).toHaveValue("65536");
  await expect(upstream).not.toHaveClass(/changed/);
});

// Catches a pending restart setting not marked, a live one marked, or a miscounting banner.
test("settings waiting for a restart are marked and counted", async ({ page }) => {
  await openSettings(page, (r) =>
    r.fulfill({
      json: answer({ "app.addressPool.maxNames": 4096 }, ["app.addressPool.maxNames", "app.link"]),
    }),
  );
  await expect(page.getByTestId("settings-banner")).toContainText("2 settings wait for a restart");
  await expect(page.locator('[data-row="app.addressPool.maxNames"]')).toContainText(
    "waits for a restart",
  );
  await expect(page.locator('[data-row="app.dnsProxy.upstream.address"]')).not.toContainText(
    "waits for a restart",
  );
});

test("there is no banner when nothing waits", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await expect(page.getByTestId("settings-banner")).toHaveCount(0);
});

// Catches loading only on mount, so a change made on the daemon is never seen (bits-ui mounts all tabs at start).
test("switching back to Settings reloads, so a change made while away is seen", async ({
  page,
}) => {
  let served = answer();
  await openSettings(page, (r) => r.fulfill({ json: served }));
  await page.getByRole("tab", { name: "Groups" }).click();
  served = answer({ "app.addressPool.maxNames": 4096 }, ["app.addressPool.maxNames"]);
  await page.getByRole("tab", { name: "Settings" }).click();
  await expect(page.getByRole("spinbutton", { name: "Domains in the pool, at most" })).toHaveValue(
    "4096",
  );
  await expect(page.getByTestId("settings-banner")).toContainText("1 setting waits for a restart");
});

// Catches a reload on tab activation overwriting an unsaved draft.
test("an unsaved edit survives switching tabs away and back", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  await upstream.fill("1.1.1.1");
  await page.getByRole("tab", { name: "Groups" }).click();
  await page.getByRole("tab", { name: "Settings" }).click();
  await expect(upstream).toHaveValue("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
});

// Catches an edit typed during a slow reload being discarded when the answer lands.
test("an edit made while a reload is in flight survives the answer landing", async ({ page }) => {
  let releaseSecond: () => void = () => {};
  const secondDelay = new Promise<void>((resolve) => {
    releaseSecond = resolve;
  });
  let requests = 0;
  await openSettings(page, async (r) => {
    requests += 1;
    if (requests === 1) {
      await r.fulfill({ json: answer() });
      return;
    }
    await secondDelay;
    await r.fulfill({ json: answer({}, ["app.addressPool.maxNames"]) });
  });
  await page.getByRole("tab", { name: "Groups" }).click();
  await page.getByRole("tab", { name: "Settings" }).click();
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  await upstream.fill("1.1.1.1");
  releaseSecond();
  await expect(page.getByTestId("settings-banner")).toContainText("1 setting waits for a restart");
  await expect(page.locator('[data-row="app.addressPool.maxNames"]')).toContainText(
    "waits for a restart",
  );
  await expect(upstream).toHaveValue("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
});

// Catches a reload keeping the whole draft, so a key saved elsewhere shows stale and is written back.
test("a key saved elsewhere arrives under an edit, and only the edit counts", async ({ page }) => {
  let releaseSecond: () => void = () => {};
  const secondDelay = new Promise<void>((resolve) => {
    releaseSecond = resolve;
  });
  let requests = 0;
  await openSettings(page, async (r) => {
    requests += 1;
    if (requests === 1) {
      await r.fulfill({ json: answer() });
      return;
    }
    await secondDelay;
    await r.fulfill({
      json: answer({ "app.addressPool.maxNames": 4096 }, ["app.addressPool.maxNames"]),
    });
  });
  await page.getByRole("tab", { name: "Groups" }).click();
  await page.getByRole("tab", { name: "Settings" }).click();
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  const names = page.getByRole("spinbutton", { name: "Domains in the pool, at most" });
  await upstream.fill("1.1.1.1");
  releaseSecond();
  await expect(page.getByTestId("settings-banner")).toContainText("1 setting waits for a restart");
  await expect(names).toHaveValue("4096");
  await expect(names).not.toHaveClass(/changed/);
  await expect(upstream).toHaveValue("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
});

// Catches one Russian form for every number (1, 2 and 5 take different forms).
test("Russian counts agree with the number", async ({ page }) => {
  const five = [
    "app.addressPool.maxNames",
    "app.link",
    "app.dnsProxy.timeout",
    "app.addressPool.ttlClamp",
    "app.addressPool.idleWindow",
  ];
  await openSettings(page, (r) => r.fulfill({ json: answer({}, five) }), { locale: "ru" });
  await expect(page.getByTestId("settings-banner")).toContainText("5 настроек ждут перезапуска");
  await page.getByRole("textbox", { name: "Вышестоящий DNS", exact: true }).fill("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("Изменена 1 настройка");
  await page.getByRole("spinbutton", { name: "Таймаут запроса" }).fill("2500");
  await expect(page.getByTestId("settings-counter")).toHaveText("Изменены 2 настройки");
});

// Catches an interface listed only as a tunnel uplink suggested as a LAN interface.
test("the LAN interface suggestions leave out uplink-only interfaces", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const offered = page.locator('[data-row="app.link"] datalist option');
  await expect(offered).toHaveCount(1);
  await expect(offered).toHaveAttribute("value", "br1");
});
