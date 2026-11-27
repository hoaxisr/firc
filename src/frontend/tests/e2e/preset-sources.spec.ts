import { expect, test, type Page } from "@playwright/test";

import { answer, openSettings } from "./pages/settings";

const RAW = "https://raw.githubusercontent.com";
const INDEX = {
  generated: "2026-11-27T00:00:00Z",
  fetchedAt: 1795780000,
  stale: false,
  sources: [
    {
      id: "sagernet",
      url: `${RAW}/SagerNet/sing-geosite/rule-set/geosite-{}.srs`,
      names: ["google", "youtube"],
    },
    { id: "hoaxisr", url: `${RAW}/hoaxisr/rulesets/master/srs/{}.srs`, names: ["youtube"] },
  ],
  providers: [
    { id: "sagernet", name: "SagerNet" },
    { id: "hoaxisr", name: "hoaxisr" },
    { id: "loyalsoldier", name: "Loyalsoldier" },
    { id: "itdog", name: "ITDog" },
  ],
};
const FILES: Record<string, unknown> = {
  loyalsoldier: {
    ...INDEX,
    providers: undefined,
    sources: [
      {
        id: "loyalsoldier-geoip",
        url: `${RAW}/Loyalsoldier/geoip/release/text/{}.txt`,
        names: ["google", "ru"],
      },
      {
        id: "loyalsoldier-geosite",
        url: `${RAW}/hoaxisr/rulesets/geo/loyalsoldier/geosite/{}.srs`,
        names: ["google"],
      },
    ],
  },
  itdog: {
    ...INDEX,
    providers: undefined,
    sources: [
      {
        id: "itdog-services",
        url: `${RAW}/itdoginfo/allow-domains/main/Services/{}.lst`,
        names: ["youtube"],
      },
    ],
  },
};

type Answer = { status: number; json: unknown };

/** Serves the catalog: the index, or a provider's file for ?provider=; records which files were asked for. */
async function serveCatalog(
  page: Page,
  opts: { index?: Answer; files?: Record<string, Answer> } = {},
) {
  const asked: string[] = [];
  const writes: string[] = [];
  page.on("request", (r) => {
    if (r.method() !== "GET" && r.url().includes("/api/v1/"))
      writes.push(`${r.method()} ${r.url()}`);
  });
  await page.route(
    (url) => url.pathname.endsWith("/groups/list/catalog"),
    async (route) => {
      const provider = new URL(route.request().url()).searchParams.get("provider");
      asked.push(provider ?? "index");
      if (provider === null) return route.fulfill(opts.index ?? { status: 200, json: INDEX });
      const file = opts.files?.[provider] ?? { status: 200, json: FILES[provider] };
      return route.fulfill(
        file.json === undefined
          ? { status: 502, json: { error: "the server answered 404" } }
          : file,
      );
    },
  );
  return { asked, writes };
}

const panel = (page: Page) => page.locator('[data-section="preset-sources"]');
const toggle = (page: Page, name: string) => panel(page).getByRole("switch", { name });

async function searchInDialog(page: Page, word: string) {
  await page.getByRole("tab", { name: "Groups" }).click();
  await page.locator('[data-value="Add Group"] button').click();
  const dialog = page.getByRole("dialog");
  await dialog.locator("#gd-name").fill("Test");
  await dialog.locator("#gd-url").fill(word);
  return dialog;
}

const badges = (dialog: ReturnType<Page["getByRole"]>) =>
  dialog.locator(".catalog-panel .catalog-badge");

// Catches: optional providers on by default, or their catalogs downloaded although nobody turned them on.
test("only SagerNet and hoaxisr are on by default, and no optional catalog is fetched", async ({
  page,
}) => {
  const seen = await serveCatalog(page);
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  for (const [name, on] of [
    ["SagerNet", true],
    ["hoaxisr", true],
    ["Loyalsoldier", false],
    ["ITDog", false],
  ] as const) {
    await expect(toggle(page, name)).toHaveAttribute("aria-checked", String(on));
  }
  await expect(panel(page).locator('[data-provider="loyalsoldier"]')).toContainText(
    "Downloaded to the router once turned on",
  );
  const dialog = await searchInDialog(page, "google");
  await expect(badges(dialog)).toHaveText(["sagernet"]);
  expect(seen.asked.filter((a) => a !== "index")).toEqual([]);
});

// Catches: a switch hiding only one of a provider's catalogs, or the choice forgotten on reload.
test("turning a provider on shows all its catalogs, survives a reload, and turning it off hides them", async ({
  page,
}) => {
  const seen = await serveCatalog(page);
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await toggle(page, "Loyalsoldier").click();
  await expect(toggle(page, "Loyalsoldier")).toHaveAttribute("aria-checked", "true");
  expect(seen.asked).toEqual(["index"]);
  let dialog = await searchInDialog(page, "google");
  await expect(badges(dialog)).toHaveText([
    "sagernet",
    "loyalsoldier-geoip",
    "loyalsoldier-geosite",
  ]);
  expect(seen.asked).toContain("loyalsoldier");
  expect(seen.asked).not.toContain("itdog");

  // A fresh load of the app (the tab's path, /groups, is mocked as an API route here, so no reload()).
  await page.goto("/");
  await page.getByRole("tab", { name: "Settings" }).click();
  await expect(toggle(page, "Loyalsoldier")).toHaveAttribute("aria-checked", "true");
  await toggle(page, "Loyalsoldier").click();
  await toggle(page, "SagerNet").click();
  dialog = await searchInDialog(page, "google");
  await expect(dialog.locator(".catalog-panel")).toContainText("nothing found");
  expect(seen.writes).toEqual([]);
});

// Catches: no way to search nothing, or a typed URL refused once every provider is off.
test("every provider can be off and a URL still adds a list", async ({ page }) => {
  await serveCatalog(page);
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await toggle(page, "SagerNet").click();
  await toggle(page, "hoaxisr").click();
  const dialog = await searchInDialog(page, "youtube");
  await expect(dialog.locator(".catalog-panel")).toContainText("nothing found");
  await dialog.locator("#gd-url").fill(`${RAW}/SagerNet/sing-geosite/rule-set/geosite-youtube.srs`);
  await expect(dialog.locator(".catalog-panel")).toHaveCount(0);
  await dialog.getByRole("button", { name: "Add list" }).click();
  await expect(dialog.locator(".gd-list-line").first()).toBeVisible();
});

// Catches: an unreachable catalog wiping the saved choices, or the settings page failing with it.
test("an unavailable catalog says so and keeps the saved choices", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      "preset_sources",
      JSON.stringify({ value: { loyalsoldier: true, sagernet: false } }),
    );
  });
  await serveCatalog(page, { index: { status: 502, json: { error: "the server answered 404" } } });
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await expect(panel(page)).toContainText("the server answered 404");
  await expect(page.getByRole("switch", { name: "Drop AAAA" })).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("preset_sources"))).toBe(
    JSON.stringify({ value: { loyalsoldier: true, sagernet: false } }),
  );
});

// Catches: one provider's failure hiding the others' results, or failing without naming it.
test("a provider whose catalog fails is named while the others still answer", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      "preset_sources",
      JSON.stringify({ value: { itdog: true, loyalsoldier: true } }),
    );
  });
  await serveCatalog(page, {
    files: { loyalsoldier: { status: 502, json: { error: "the server answered 404" } } },
  });
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const dialog = await searchInDialog(page, "youtube");
  await expect(badges(dialog)).toHaveText(["sagernet", "hoaxisr", "itdog-services"]);
  await expect(dialog.locator(".catalog-panel")).toContainText("Catalog unavailable: Loyalsoldier");
});

// Catches: a provider added to the catalog later arriving switched on.
test("a new provider in the catalog starts off", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("preset_sources", JSON.stringify({ value: { loyalsoldier: true } }));
  });
  const later = {
    ...INDEX,
    providers: [...INDEX.providers, { id: "runetfreedom", name: "RunetFreedom" }],
  };
  await serveCatalog(page, { index: { status: 200, json: later } });
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await expect(toggle(page, "RunetFreedom")).toHaveAttribute("aria-checked", "false");
  await expect(toggle(page, "Loyalsoldier")).toHaveAttribute("aria-checked", "true");
});

// Catches: the section missing its Russian strings.
test("the section is translated", async ({ page }) => {
  await serveCatalog(page);
  await openSettings(page, (r) => r.fulfill({ json: answer() }), { locale: "ru" });
  await expect(panel(page)).toContainText("Источники пресетов");
  await expect(panel(page).locator('[data-provider="sagernet"]')).toContainText("Входит в каталог");
});
