import { expect, test, type Page } from "@playwright/test";

import { AuthPage } from "./pages/AuthPage";
import { signedIn } from "./pages/session";

const LAST = new Date(2026, 9, 20, 14, 32).getTime() / 1000;
const SINCE = new Date(2026, 9, 20, 9, 5).getTime() / 1000;

const CALM = { window: 600, total: 0, fallbacks: 0, last: 0, reason: "", resting: false, since: 0 };

const group = (id: string, name: string, health: Record<string, unknown>) => ({
  id,
  name,
  enable: true,
  interface: "wg0",
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [],
  live: true,
  resolver: { source: "firmware", servers: ["9.9.9.9"], health: { ...CALM, ...health } },
});

async function setup(
  page: Page,
  groups: Record<string, unknown>[],
  locale = "en",
  polled: Record<string, unknown>[] = groups,
) {
  await signedIn(page);
  await page.addInitScript(
    (l) => localStorage.setItem("locale", JSON.stringify({ value: l })),
    locale,
  );
  await page.route("**/interfaces", (route) =>
    route.fulfill({ json: { interfaces: [{ id: "wg0", role: "tunnel" }] } }),
  );
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  const seen = { polls: 0 };
  await page.route(/\/groups(\?.*)?$/, (route) => {
    const load = route.request().url().includes("with_rules");
    if (!load) seen.polls++;
    return route.fulfill({ json: { groups: load ? groups : polled } });
  });
  await page.goto("/");
  await expect(page.locator(".group")).toHaveCount(groups.length);
  return seen;
}

test.describe("The DNS health tag on a card", () => {
  // Catches a tag missing, wrong in colour, or shown on a calm card.
  test("amber for failures, red for a resting group, none for a calm one", async ({ page }) => {
    await setup(
      page,
      [
        group("0a000021", "Flaky", {
          total: 37,
          fallbacks: 4,
          last: LAST,
          reason: "fallback_timeout",
        }),
        group("0a000022", "Resting", { total: 12, fallbacks: 12, resting: true, since: SINCE }),
        group("0a000023", "Calm", { total: 50 }),
      ],
      "ru",
    );
    const cards = page.locator(".group");
    await expect(cards.nth(0).locator(".health-badge.amber")).toHaveText(
      "DNS группы сбоит: 4 из 37 за 10 мин",
    );
    await expect(cards.nth(1).locator(".health-badge.red")).toHaveText("DNS группы не отвечает");
    await expect(cards.nth(2).locator(".health-badge")).toHaveCount(0);
    await expect(page.locator(".health-badge")).toHaveCount(2);
  });

  // Catches the tooltip missing, or showing the wrong time or note.
  test("hovering the tag explains the last failure", async ({ page }) => {
    await setup(page, [
      group("0a000021", "Flaky", {
        total: 37,
        fallbacks: 4,
        last: LAST,
        reason: "fallback_timeout",
      }),
    ]);
    await page.locator(".health-badge").hover();
    await expect(page.getByRole("tooltip")).toHaveText(
      "Last failure at 14:32: the group's DNS did not answer in time; the common upstream answered. Click to open the group's journal.",
    );
  });

  // Catches the red tooltip naming the last failure instead of the time the group went quiet.
  test("hovering the red tag names when the group stopped answering", async ({ page }) => {
    await setup(page, [
      group("0a000022", "Resting", { total: 3, fallbacks: 3, resting: true, since: SINCE }),
    ]);
    await page.locator(".health-badge").hover();
    await expect(page.getByRole("tooltip")).toHaveText(
      "Since 09:05 the group's DNS is not answering, the common upstream answers. firc checks it every 30 s. Click to open the group's journal.",
    );
  });
});

test.describe("The DNS health tag follows the poll", () => {
  // Catches the tag read only from the loaded groups, so a clean window keeps it amber, or a poll dropping an unsaved name.
  test("an amber tag goes once a poll reports a clean window, keeping an unsaved edit", async ({
    page,
  }) => {
    await page.clock.install();
    const seen = await setup(
      page,
      [
        group("0a000021", "Flaky", {
          total: 37,
          fallbacks: 4,
          last: LAST,
          reason: "fallback_timeout",
        }),
      ],
      "en",
      [group("0a000021", "Flaky", { total: 40 })],
    );
    await expect(page.locator(".health-badge.amber")).toHaveCount(1);
    await page.locator("input.group-name").fill("Flaky2");

    await page.clock.runFor(5_000);
    await expect.poll(() => seen.polls).toBeGreaterThan(0);
    await expect(page.locator(".health-badge")).toHaveCount(0);
    await expect(page.locator("input.group-name")).toHaveValue("Flaky2");
  });

  // Catches a resolver that stops answering after load never lighting the card.
  test("a calm card turns red once a poll reports the group resting", async ({ page }) => {
    await page.clock.install();
    const seen = await setup(page, [group("0a000023", "Calm", { total: 50 })], "en", [
      group("0a000023", "Calm", { total: 12, fallbacks: 12, resting: true, since: SINCE }),
    ]);
    await expect(page.locator(".health-badge")).toHaveCount(0);

    await page.clock.runFor(5_000);
    await expect.poll(() => seen.polls).toBeGreaterThan(0);
    await expect(page.locator(".health-badge.red")).toHaveText("The group's DNS is not answering");
  });
});

test.describe("The DNS health tag opens the journal", () => {
  // Catches a tag that does not switch tabs or open Events, or an effect that undoes the user's own filter picks.
  test("focuses the group with DNS on, and leaves later picks alone", async ({ page }) => {
    await setup(page, [
      group("0a000021", "Flaky", {
        total: 37,
        fallbacks: 4,
        last: LAST,
        reason: "fallback_timeout",
      }),
      group("0a000024", "Other", {}),
    ]);
    const panel = page.locator(".jh-panel");
    const filter = page.getByRole("button", { name: /^Filter/ });
    const dns = panel.getByRole("group", { name: "Sources" }).getByRole("button", { name: /DNS/ });
    const groupFilter = panel.getByRole("button", { name: "Group" });
    const capture = page.getByRole("tab", { name: "Capture", exact: true });

    await page.getByRole("tab", { name: "Journal" }).click();
    await filter.click();
    await dns.click();
    await expect(dns).toHaveAttribute("aria-pressed", "false");
    await page.keyboard.press("Escape");
    await capture.click();
    await page.getByRole("tab", { name: "Groups" }).click();

    await page.locator(".health-badge").click();
    await expect(page.getByRole("tab", { name: "Journal" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(page.getByRole("tab", { name: "Events", exact: true })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await filter.click();
    await expect(dns).toHaveAttribute("aria-pressed", "true");
    await expect(groupFilter).toHaveText("Flaky");

    await dns.click();
    await expect(dns).toHaveAttribute("aria-pressed", "false");
    await groupFilter.click();
    await page.getByRole("option", { name: "Other" }).click();
    await expect(groupFilter).toHaveText("Other");
    await expect(dns).toHaveAttribute("aria-pressed", "false");
    await page.keyboard.press("Escape");

    await page.getByRole("tab", { name: "Groups" }).click();
    await page.locator(".health-badge").click();
    await expect(page.getByRole("tab", { name: "Journal" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await filter.click();
    await expect(dns).toHaveAttribute("aria-pressed", "true");
    await expect(groupFilter).toHaveText("Flaky");
  });

  // Catches a spent focus request replaying after logout and login, past the user's own tab.
  test("a click before logout does not steer the next login", async ({ page }) => {
    await setup(page, [
      group("0a000021", "Flaky", {
        total: 37,
        fallbacks: 4,
        last: LAST,
        reason: "fallback_timeout",
      }),
    ]);
    await page.route("**/auth", (route) => route.fulfill({ json: { token: "fake-token" } }));
    await page.locator(".health-badge").click();
    await page.getByRole("tab", { name: "Groups" }).click();

    await page.locator(".logout button").click();
    await new AuthPage(page).login("admin", "admin");

    await expect(page.getByRole("tab", { name: "Groups" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await page.getByRole("tab", { name: "Journal" }).click();
    await page.getByRole("button", { name: /^Filter/ }).click();
    await expect(page.locator(".jh-panel").getByRole("button", { name: "Group" })).toHaveText(
      "any group",
    );
  });
});
