import { expect, test, type Page, type Route } from "@playwright/test";

import { signedIn } from "./pages/session";

async function shellWith(page: Page, onEvents: (route: Route) => unknown) {
  await signedIn(page);
  await page.route("**/groups?with_rules=true", (route) => route.fulfill({ json: { groups: [] } }));
  await page.route(/\/subscriptions(\?.*)?$/, (route) =>
    route.fulfill({ json: { subscriptions: [] } }),
  );
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route(/\/system\/capture(\?.*)?$/, (route) =>
    route.fulfill({ json: { running: false } }),
  );
  await page.route(/\/system\/events(\?.*)?$/, onEvents);
}

async function openFilter(page: Page, name = "Filter") {
  await page.getByRole("button", { name: new RegExp(`^${name}(,|$)`) }).click();
  return page.locator(".jh-panel");
}

async function closeFilter(page: Page) {
  await page.keyboard.press("Escape");
  await expect(page.locator(".jh-panel")).toHaveCount(0);
}

async function shell(page: Page, events: unknown[]) {
  await shellWith(page, (route) => {
    const since = Number(new URL(route.request().url()).searchParams.get("since") ?? 0);
    const fresh = since === 0 ? events : [];
    const next = since === 0 && events.length ? events.length : since;
    return route.fulfill({ json: { events: fresh, next, dropped: 0 } });
  });
}

// Catches a dead daemon being toasted on every poll over any tab instead of once on Journal.
test("a log that does not answer is shown on its tab, not toasted per poll", async ({ page }) => {
  let polls = 0;
  await shellWith(page, (route) => {
    polls += 1;
    return route.fulfill({ status: 500, json: { error: "down" } });
  });

  await page.goto("/");
  await expect.poll(() => polls, { timeout: 10_000 }).toBeGreaterThanOrEqual(3);
  await expect(page.getByText("Request failed")).toHaveCount(0);

  await page.getByRole("tab", { name: "Journal" }).click();
  await expect(page.getByText("The daemon did not answer for the log.")).toBeVisible();
});

test("the journal shows what the daemon said", async ({ page }) => {
  await shell(page, [
    { seq: 1, at: 1790000000, kind: "log", level: "warn", source: "fircd", message: "pool is low" },
  ]);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  await expect(page.locator(".row.l-warn").getByText("pool is low")).toBeVisible();
  await page.waitForTimeout(2500);
  await expect(page.locator(".pane .row")).toHaveCount(1);
});

const MIXED = [
  { seq: 1, at: 1790000000, kind: "log", level: "info", source: "fircd", message: "group up" },
  { seq: 2, at: 1790000001, kind: "log", level: "debug", source: "fircd", message: "a detail" },
  {
    seq: 3,
    at: 1790000002,
    kind: "log",
    level: "warn",
    source: "tunvless0",
    message: "B does not answer",
  },
  {
    seq: 4,
    at: 1790000003,
    kind: "log",
    level: "error",
    source: "tunvless1",
    message: "no usable VLESS node",
  },
  {
    seq: 5,
    at: 1790000004,
    kind: "dns",
    client: "192.168.1.42",
    name: "youtube.com",
    qtype: "A",
    rcode: "NOERROR",
    decision: "no-match",
    reals: [],
  },
  {
    seq: 6,
    at: 1790000005,
    kind: "bypass",
    client: "192.168.1.42",
    dst: "142.250.1.1",
    port: 443,
    proto: "tcp",
    how: "sni",
    name: "cdn.example.net",
    repeats: 0,
  },
];

// Catches a count over the shown rows, a level read as a minimum, or DNS rows hidden by a level.
test("the source and level buttons filter the rows, each on its own", async ({ page }) => {
  await shell(page, MIXED);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  const panel = await openFilter(page);
  const sources = panel.getByRole("group", { name: "Sources" });
  const levels = panel.getByRole("group", { name: "Log levels" });
  await expect(rows).toHaveCount(4);
  await expect(page.getByText("a detail")).toHaveCount(0);
  await expect(sources.getByRole("button")).toHaveText(["firc core2", "Tunnels2", "DNS1"]);
  await expect(levels.getByRole("button", { name: "debug" })).toHaveAttribute(
    "aria-pressed",
    "false",
  );

  await levels.getByRole("button", { name: "debug" }).click();
  await expect(rows).toHaveCount(5);
  for (const name of ["debug", "info", "warn"]) await levels.getByRole("button", { name }).click();
  await expect(rows).toHaveCount(2);
  await expect(page.locator(".pane .row.l-error")).toHaveText(/no usable VLESS node/);
  await expect(sources.getByRole("button", { name: /firc core/ })).toHaveText("firc core2");

  await levels.getByRole("button", { name: "error" }).click();
  await expect(rows).toHaveCount(1);
  await sources.getByRole("button", { name: /DNS/ }).click();
  await expect(rows).toHaveCount(0);
  await levels.getByRole("button", { name: "info" }).click();
  await sources.getByRole("button", { name: /Tunnels/ }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("group up");
});

// Catches a tunnel badge that does not search for its device, or a search that ignores the source.
test("clicking a tunnel's badge shows that tunnel's lines", async ({ page }) => {
  await shell(page, MIXED);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  await expect(rows).toHaveCount(4);
  await expect(rows.nth(0).locator(".chip")).toHaveText("firc core");
  await rows.nth(1).getByRole("button", { name: "tunvless0" }).click();
  await expect(page.getByPlaceholder("client, name or tunnel")).toHaveValue("tunvless0");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("B does not answer");
  await expect(rows.nth(0)).not.toContainText("tunnel tunvless0");
});

// Catches a toolbar or row wider than a phone, a toolbar that wraps, or popover segments not in one row of equal buttons.
test("a phone-wide journal scrolls only down", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await shell(page, MIXED);
  await page.goto("/journal");
  await expect(page.locator(".pane .row")).toHaveCount(4);
  const wide = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(wide).toBeLessThanOrEqual(0);
  const search = (await page.getByPlaceholder("client, name or tunnel").boundingBox())!;
  const clear = (await page.getByRole("button", { name: "Clear view" }).boundingBox())!;
  expect(Math.abs(search.y + search.height / 2 - (clear.y + clear.height / 2))).toBeLessThan(2);
  expect(clear.x + clear.width).toBeLessThanOrEqual(390);
  expect(search.width).toBeGreaterThan(120);
  const panel = await openFilter(page);
  for (const [name, n] of [
    ["Sources", 3],
    ["Log levels", 4],
  ] as const) {
    const boxes = await panel
      .getByRole("group", { name })
      .getByRole("button")
      .evaluateAll((els) => els.map((el) => el.getBoundingClientRect()));
    expect(boxes).toHaveLength(n);
    for (const b of boxes) {
      expect(Math.abs(b.top - boxes[0].top)).toBeLessThan(1);
      expect(Math.abs(b.width - boxes[0].width)).toBeLessThan(1);
      expect(b.right).toBeLessThanOrEqual(390);
    }
  }
  await expect(
    panel.getByRole("group", { name: "Sources" }).getByRole("button").first().locator(".dot"),
  ).toHaveCSS("background-color", "rgb(143, 179, 204)");
  await closeFilter(page);
  const row = page.locator(".pane .row").first();
  const at = await row.locator(".at").boundingBox();
  const msg = await row.locator(".msg").boundingBox();
  expect(msg!.y).toBeGreaterThanOrEqual(at!.y + at!.height - 1);
});

test("a DNS event is shown, and clicking its client filters to that client", async ({ page }) => {
  await shell(page, [
    {
      seq: 1,
      at: 1790000000,
      kind: "dns",
      client: "192.168.1.42",
      name: "youtube.com",
      qtype: "A",
      rcode: "NOERROR",
      decision: "issued",
      group: { id: "g1", name: "media" },
      fake: "198.18.0.5",
      reals: ["142.250.1.1"],
    },
    {
      seq: 2,
      at: 1790000001,
      kind: "dns",
      client: "192.168.1.51",
      name: "ya.ru",
      qtype: "A",
      rcode: "NOERROR",
      decision: "no-match",
      reals: [],
    },
    {
      seq: 3,
      at: 1790000002,
      kind: "log",
      level: "info",
      source: "fircd",
      message: "netfilter rebuilt",
    },
  ]);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0)).toContainText("issued 198.18.0.5 (142.250.1.1)");
  await rows.nth(0).getByRole("button", { name: "192.168.1.42" }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("youtube.com");
});

// Catches a blocked answer read as passed, its code missing, the decision not set apart in red, the row not ending at it, or a group name painted as the decision.
test("a blocked row ends with a red 'blocked: 0.0.0.0'", async ({ page }) => {
  await shell(page, [
    {
      seq: 1,
      at: 1790000000,
      kind: "dns",
      client: "192.168.1.7",
      name: "ads.doubleclick.net",
      qtype: "A",
      rcode: "NOERROR",
      decision: "blocked",
      resolver: "local",
      group: { id: "a0a0a0a0", name: "Ads" },
      reals: [],
    },
    {
      seq: 2,
      at: 1790000001,
      kind: "dns",
      client: "192.168.1.7",
      name: "x.example.com",
      qtype: "A",
      rcode: "REFUSED",
      decision: "blocked",
      resolver: "local",
      group: { id: "a0a0a0a1", name: "blocked: REFUSED" },
      reals: [],
    },
    {
      seq: 3,
      at: 1790000002,
      kind: "dns",
      client: "fd00::5",
      name: "tracker.example.com",
      qtype: "AAAA",
      rcode: "NXDOMAIN",
      decision: "blocked",
      resolver: "local",
      group: { id: "a0a0a0a0", name: "Ads" },
      reals: [],
    },
  ]);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0).locator(".tail")).toHaveText("A → Ads · blocked: 0.0.0.0");
  const red = rows.nth(0).locator(".tail .blocked");
  const endsAtRed = await rows
    .nth(0)
    .locator(".tail")
    .evaluate(
      (el) =>
        el.lastElementChild === el.querySelector(".blocked") &&
        el.textContent!.trimEnd().endsWith(el.lastElementChild!.textContent!),
    );
  expect(endsAtRed).toBe(true);
  await expect(red).toHaveText("blocked: 0.0.0.0");
  await expect(red).toHaveCSS("color", "rgb(248, 81, 73)");
  await expect(rows.nth(0).locator(".tail")).not.toHaveCSS("color", "rgb(248, 81, 73)");
  await expect(rows.nth(2).locator(".tail .blocked")).toHaveText("blocked: NXDOMAIN");
  const named = rows.nth(1).locator(".tail");
  await expect(named).toHaveText("A → blocked: REFUSED · blocked: REFUSED");
  await expect(named.locator(".blocked")).toHaveCount(1);
  expect(
    await named.evaluate(
      (el) =>
        el.lastElementChild === el.querySelector(".blocked") &&
        el.textContent!.trimEnd().endsWith(el.lastElementChild!.textContent!),
    ),
  ).toBe(true);
});

// Catches a known device shown by its address alone, or its name not found by the search.
test("a DNS row names the device that asked, beside its address", async ({ page }) => {
  await shell(page, [
    {
      seq: 1,
      at: 1790000000,
      kind: "dns",
      client: "192.168.1.42",
      name: "youtube.com",
      qtype: "A",
      rcode: "NOERROR",
      decision: "issued",
      group: { id: "g1", name: "media" },
      fake: "198.18.0.5",
      reals: ["142.250.1.1"],
    },
    {
      seq: 2,
      at: 1790000001,
      kind: "dns",
      client: "192.168.1.51",
      name: "ya.ru",
      qtype: "A",
      rcode: "NOERROR",
      decision: "no-match",
      reals: [],
    },
  ]);
  await page.route("**/system/hosts", (route) =>
    route.fulfill({
      json: {
        hosts: [
          {
            mac: "aa:00:00:00:00:01",
            name: "Phone",
            ip: "192.168.1.42",
            ip6: [],
            active: true,
            registered: true,
            policy: "",
          },
        ],
      },
    }),
  );
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0).locator(".who")).toHaveText(/Phone\s*192\.168\.1\.42/);
  await expect(rows.nth(1).locator(".who")).toHaveText("192.168.1.51");
  await page.getByPlaceholder("client, name or tunnel").fill("phone");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("youtube.com");
});

// Catches the search missing the client, the name, or the log line's own message.
test("typing in the search field filters by client, name or message", async ({ page }) => {
  await shell(page, [
    {
      seq: 1,
      at: 1790000000,
      kind: "dns",
      client: "192.168.1.42",
      name: "youtube.com",
      qtype: "A",
      rcode: "NOERROR",
      decision: "issued",
      group: { id: "g1", name: "media" },
      fake: "198.18.0.5",
      reals: ["142.250.1.1"],
    },
    {
      seq: 2,
      at: 1790000001,
      kind: "dns",
      client: "192.168.1.51",
      name: "ya.ru",
      qtype: "A",
      rcode: "NOERROR",
      decision: "no-match",
      reals: [],
    },
    {
      seq: 3,
      at: 1790000002,
      kind: "log",
      level: "info",
      source: "fircd",
      message: "netfilter rebuilt",
    },
  ]);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  await expect(rows).toHaveCount(3);

  const search = page.getByPlaceholder("client, name or tunnel");
  await search.fill("tube");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("youtube.com");

  await search.fill("rebuilt");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("netfilter rebuilt");
});

test("clicking a row's name fills the search field", async ({ page }) => {
  await shell(page, [
    {
      seq: 1,
      at: 1790000000,
      kind: "dns",
      client: "192.168.1.42",
      name: "youtube.com",
      qtype: "A",
      rcode: "NOERROR",
      decision: "issued",
      group: { id: "g1", name: "media" },
      fake: "198.18.0.5",
      reals: ["142.250.1.1"],
    },
    {
      seq: 2,
      at: 1790000001,
      kind: "dns",
      client: "192.168.1.51",
      name: "ya.ru",
      qtype: "A",
      rcode: "NOERROR",
      decision: "no-match",
      reals: [],
    },
  ]);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  await expect(rows).toHaveCount(2);

  await rows.nth(0).getByRole("button", { name: "youtube.com" }).click();
  await expect(page.getByPlaceholder("client, name or tunnel")).toHaveValue("youtube.com");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("youtube.com");
});

// Catches a bypass event showing the flow's own data instead of what firc last answered, shown among the Events, carrying the Leaks chip, or a click on it filtering the Events unseen.
test("a bypass event is shown on Capture with what firc answered", async ({ page }) => {
  await shell(page, [
    {
      seq: 1,
      at: 1790000000,
      kind: "bypass",
      client: "192.168.1.42",
      dst: "142.250.1.1",
      port: 443,
      proto: "udp",
      how: "addr",
      name: "cdn.example.net",
      group: { id: "g1", name: "media" },
      last: { decision: "issued", at: 1789999970, fake: "198.18.0.5" },
      repeats: 0,
    },
  ]);
  await page.route(/\/system\/capture(\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        running: false,
        last: {
          startedAt: 1789999900,
          endedAt: 1790000200,
          ended: "reached-end",
          leaks: 1,
          summary: [],
        },
      },
    }),
  );
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  await expect(page.getByText("Nothing matches the filters.")).toBeVisible();
  await expect(page.locator(".pane .row")).toHaveCount(0);
  await page.getByRole("tab", { name: "Capture", exact: true }).click();
  const rows = page.locator(".cap-pane .row");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("by address");
  await expect(rows.nth(0)).toContainText("firc issued 198.18.0.5");
  await expect(rows.nth(0).getByRole("button")).toHaveCount(0);
  await expect(rows.nth(0)).not.toContainText("Leaks");
  await rows.nth(0).getByText("cdn.example.net").click();
  await rows.nth(0).getByText("192.168.1.42").click();
  await page.getByRole("tab", { name: "Events", exact: true }).click();
  await expect(page.getByPlaceholder("client, name or tunnel")).toHaveValue("");
});

// The Bypass tab was folded into the journal; nothing may be left at it.
test("the Bypass tab is gone", async ({ page }) => {
  await shell(page, []);
  await page.goto("/");
  await expect(page.getByRole("tab", { name: "Bypass", exact: true })).toHaveCount(0);
});

// Catches a tab not opened by its address, a click not changing the address, or Back not returning.
test("each tab has an address of its own", async ({ page }) => {
  await shell(page, []);
  const active = page.locator('[data-tabs-trigger][data-state="active"]');
  await page.goto("/journal");
  await expect(active).toContainText("Journal");
  await page.getByRole("tab", { name: "Settings", exact: true }).click();
  await expect(page).toHaveURL(/\/settings$/);
  await page.goBack();
  await expect(page).toHaveURL(/\/journal$/);
  await expect(active).toContainText("Journal");
  await page.goto("/");
  await expect(active).toContainText("Groups");
  await expect(page).toHaveURL(/\/$/);
});

// Catches a sub-tab not opened by its address, a click not changing it, Back not returning, or the sub-tab lost on a trip through another tab.
test("each Journal sub-tab has an address of its own", async ({ page }) => {
  await shell(page, []);
  const sub = (name: string) => page.getByRole("tab", { name, exact: true });
  await page.goto("/journal/stats");
  await expect(sub("DNS stats")).toHaveAttribute("aria-selected", "true");
  await expect(sub("Events")).toHaveAttribute("aria-selected", "false");
  await sub("Capture").click();
  await expect(page).toHaveURL(/\/journal\/capture$/);
  await expect(sub("Capture")).toHaveAttribute("aria-selected", "true");
  await page.goBack();
  await expect(page).toHaveURL(/\/journal\/stats$/);
  await expect(sub("DNS stats")).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Settings", exact: true }).click();
  await expect(page).toHaveURL(/\/settings$/);
  await page.getByRole("tab", { name: "Journal", exact: true }).click();
  await expect(page).toHaveURL(/\/journal\/stats$/);
  await sub("Events").click();
  await expect(page).toHaveURL(/\/journal$/);
  await expect(page.getByPlaceholder("client, name or tunnel")).toBeVisible();
});

// Catches the next page waiting a full poll interval after a full page; both requests are timed.
test("a full page is followed at once by the next one", async ({ page }) => {
  const at: number[] = [];
  await shellWith(page, (route) => {
    at.push(Date.now());
    const since = Number(new URL(route.request().url()).searchParams.get("since") ?? 0);
    const size = since === 0 ? 1024 : since === 1024 ? 3 : 0;
    const events = Array.from({ length: size }, (_, i) => ({
      seq: since + i + 1,
      at: 1790000000,
      kind: "log",
      level: "info",
      source: "fircd",
      message: `m${since + i + 1}`,
    }));
    return route.fulfill({ json: { events, next: since + size, dropped: 0 } });
  });
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  await expect(page.getByText("m1027")).toBeVisible();
  expect(at.length).toBeGreaterThanOrEqual(2);
  expect(at[1] - at[0]).toBeLessThan(1000);
});

// Catches a stripe in the wrong colour, a DNS row given one, or warn and error rows not set apart.
test("each level has its own stripe, and warn and error their own colour", async ({ page }) => {
  await shell(
    page,
    MIXED.concat([
      { seq: 7, at: 1790000006, kind: "log", level: "warn", source: "fircd", message: "w" },
      { seq: 8, at: 1790000007, kind: "log", level: "error", source: "fircd", message: "e" },
    ]),
  );
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const panel = await openFilter(page);
  await panel
    .getByRole("group", { name: "Log levels" })
    .getByRole("button", { name: "debug" })
    .click();
  await closeFilter(page);
  const stripe = (sel: string) =>
    page
      .locator(sel)
      .first()
      .evaluate((el) => getComputedStyle(el, "::before").backgroundColor);
  expect(await stripe(".row.l-debug")).toBe("rgb(93, 96, 114)");
  expect(await stripe(".row.l-info")).toBe("rgb(47, 127, 168)");
  expect(await stripe(".row.l-warn")).toBe("rgb(217, 138, 43)");
  expect(await stripe(".row.l-error")).toBe("rgb(217, 83, 76)");
  expect(await stripe(".row.dns")).toBe("rgba(0, 0, 0, 0)");
  await expect(page.locator(".row.l-warn .msg").first()).toHaveCSS("color", "rgb(217, 138, 43)");
  await expect(page.locator(".row.l-error .msg").first()).toHaveCSS("color", "rgb(217, 83, 76)");
  await expect(page.locator(".row.l-info .msg").first()).toHaveCSS("color", "rgb(255, 255, 255)");
  const bg = (sel: string) =>
    page
      .locator(sel)
      .first()
      .evaluate((el) => getComputedStyle(el).backgroundColor);
  expect(await bg(".row.l-info")).toBe("rgba(0, 0, 0, 0)");
  expect(await bg(".row.l-error")).not.toBe("rgba(0, 0, 0, 0)");
});

// Catches a toggle whose aria-pressed does not follow its state, or a pressed toggle that looks like the rest.
test("every toggle says and shows whether it is pressed", async ({ page }) => {
  await shell(page, MIXED);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const panel = await openFilter(page);
  const sources = panel.getByRole("group", { name: "Sources" }).getByRole("button");
  const levels = panel.getByRole("group", { name: "Log levels" }).getByRole("button");
  await expect(sources).toHaveCount(3);
  for (let i = 0; i < 3; i++) await expect(sources.nth(i)).toHaveAttribute("aria-pressed", "true");
  const want = ["false", "true", "true", "true"];
  for (let i = 0; i < 4; i++) await expect(levels.nth(i)).toHaveAttribute("aria-pressed", want[i]);
  await sources.nth(0).click();
  await expect(sources.nth(0)).toHaveAttribute("aria-pressed", "false");
  await levels.nth(2).click();
  await expect(levels.nth(2)).toHaveAttribute("aria-pressed", "false");
  await levels.nth(0).click();
  await expect(levels.nth(0)).toHaveAttribute("aria-pressed", "true");
  const look = (i: number) =>
    levels.nth(i).evaluate((el) => {
      const c = getComputedStyle(el);
      return { bg: c.backgroundColor, ring: c.boxShadow };
    });
  const on = await look(1);
  const off = await look(2);
  expect(on.ring).not.toBe("none");
  expect(off.ring).toBe("none");
  expect(on.bg).not.toBe(off.bg);
});

// Catches seqs the daemon evicted before a fresh page ever asked counted as lost, or a later loss not counted.
test("the first catch-up reports nothing lost, a later gap does", async ({ page }) => {
  let later = false;
  let told = false;
  await shellWith(page, (route) => {
    const since = Number(new URL(route.request().url()).searchParams.get("since") ?? 0);
    const size = since === 0 ? 1024 : since === 1024 ? 3 : 0;
    const gap = since === 1027 && later && !told;
    if (gap) told = true;
    const dropped = since === 1024 ? 40 : gap ? 5 : 0;
    const events = Array.from({ length: size }, (_, i) => ({
      seq: since + i + 1,
      at: 1790000000,
      kind: "log",
      level: "info",
      source: "fircd",
      message: `m${since + i + 1}`,
    }));
    return route.fulfill({ json: { events, next: since + size, dropped } });
  });
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  await expect(page.getByText("m1027")).toBeVisible();
  await page.waitForTimeout(2500);
  await expect(page.getByText("Events were lost before this page asked for them:")).toHaveCount(0);
  later = true;
  await expect(page.locator(".status")).toContainText(
    "Events were lost before this page asked for them: 5",
    { timeout: 6000 },
  );
});

// Catches rows arriving under display:none (scrollHeight 0) leaving the tab open on its top row.
test("the pane follows to the bottom the first time its tab is opened", async ({ page }) => {
  const events = Array.from({ length: 80 }, (_, i) => ({
    seq: i + 1,
    at: 1790000000 + i,
    kind: "log",
    level: "info",
    source: "fircd",
    message: `line ${i + 1}`,
  }));
  await shell(page, events);
  await page.goto("/");
  await expect(page.locator(".pane .row")).toHaveCount(80);
  await page.getByRole("tab", { name: "Journal" }).click();
  await expect(page.getByText("line 80")).toBeVisible();
  const atBottom = await page
    .locator(".pane")
    .evaluate((el) => Math.abs(el.scrollHeight - el.clientHeight - el.scrollTop) <= 1);
  expect(atBottom).toBe(true);
});

// Catches a restarted daemon's seqs restarting at 1 while the tab keeps the old cursor and freezes.
test("a restarted daemon replaces the old run's events", async ({ page }) => {
  let restarted = false;
  await shellWith(page, (route) => {
    const since = Number(new URL(route.request().url()).searchParams.get("since") ?? 0);
    const run = restarted
      ? {
          boot: "b",
          events: [
            {
              seq: 1,
              at: 1790000100,
              kind: "log",
              level: "info",
              source: "fircd",
              message: "second run",
            },
          ],
        }
      : {
          boot: "a",
          events: [
            {
              seq: 1,
              at: 1790000000,
              kind: "log",
              level: "info",
              source: "fircd",
              message: "first run",
            },
            {
              seq: 2,
              at: 1790000001,
              kind: "log",
              level: "info",
              source: "fircd",
              message: "first run, later",
            },
          ],
        };
    const fresh = run.events.filter((e) => e.seq > since);
    const next = fresh.length ? fresh[fresh.length - 1].seq : since;
    return route.fulfill({
      json: { events: fresh, next, dropped: 0, boot: run.boot },
    });
  });
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  await expect(page.getByText("first run, later")).toBeVisible();

  restarted = true;
  await expect(page.getByText("second run")).toBeVisible({ timeout: 6000 });
  await expect(page.getByText("first run", { exact: true })).toHaveCount(0);
  await expect(page.getByText("first run, later")).toHaveCount(0);
  await expect(page.locator(".pane .row")).toHaveCount(1);
});

test.describe("the journal's group filter", () => {
  const GROUPS = [
    { id: "a1a1a1a1", name: "media", interface: "nwg0", enable: true, rules: [] },
    { id: "b2b2b2b2", name: "work", interface: "eth1", enable: true, rules: [] },
  ];

  async function withGroups(page: Page, events: unknown[]) {
    await shell(page, events);
    await page.route("**/groups?with_rules=true", (route) =>
      route.fulfill({ json: { groups: GROUPS } }),
    );
  }

  async function openGroups(page: Page) {
    const panel = await openFilter(page);
    await panel.getByRole("button", { name: "Group" }).click();
    return page.getByRole("option");
  }

  // Catches the group options coming from the buffer alone.
  test("lists the groups with nothing in the buffer", async ({ page }) => {
    await withGroups(page, []);
    await page.goto("/");
    await page.getByRole("tab", { name: "Journal" }).click();
    await expect(page.locator(".pane .row")).toHaveCount(0);
    await expect(await openGroups(page)).toHaveText(["any group", "media", "work"]);
  });

  // Catches a group only the events know being dropped or not marked deleted.
  test("marks a group only the events know as deleted", async ({ page }) => {
    await withGroups(page, [
      {
        seq: 1,
        at: 1790000000,
        kind: "dns",
        client: "192.168.1.42",
        name: "old.example.com",
        qtype: "A",
        rcode: "NOERROR",
        decision: "issued",
        group: { id: "c3c3c3c3", name: "gone" },
        fake: "198.18.0.5",
        reals: ["142.250.1.1"],
      },
    ]);
    await page.goto("/");
    await page.getByRole("tab", { name: "Journal" }).click();
    await expect(page.locator(".pane .row")).toHaveCount(1);
    await expect(await openGroups(page)).toHaveText([
      "any group",
      "media",
      "work",
      "gone (deleted)",
    ]);
  });

  // Catches Clear view dropping a chosen group that still exists.
  test("keeps the chosen group across Clear view", async ({ page }) => {
    await withGroups(page, []);
    await page.goto("/");
    await page.getByRole("tab", { name: "Journal" }).click();
    await (await openGroups(page)).filter({ hasText: "work" }).click();
    const trigger = page.locator(".jh-panel").getByRole("button", { name: "Group" });
    await expect(trigger).toHaveText("work");
    await closeFilter(page);
    await page.getByRole("button", { name: "Clear view" }).click();
    await openFilter(page);
    await expect(trigger).toHaveText("work");
  });
});

test.describe("pausing the journal", () => {
  const line = (seq: number) => ({
    seq,
    at: 1790000000 + seq,
    kind: "log",
    level: "info",
    source: "fircd",
    message: `line ${seq}`,
  });

  async function live(page: Page, all: unknown[]) {
    await shellWith(page, (route) => {
      const since = Number(new URL(route.request().url()).searchParams.get("since") ?? 0);
      const fresh = (all as { seq: number }[]).filter((e) => e.seq > since);
      const next = fresh.length ? fresh[fresh.length - 1].seq : since;
      return route.fulfill({ json: { events: fresh, next, dropped: 0 } });
    });
  }

  // Catches the source counts following the live buffer while the rows stay frozen.
  test("counts stay with the frozen rows while paused", async ({ page }) => {
    const all = [line(1), line(2)];
    await live(page, all);
    await page.goto("/");
    await page.getByRole("tab", { name: "Journal" }).click();
    const events = page.getByRole("tab", { name: /^Events/ });
    await expect(events).toHaveText("Events2");
    await page.getByRole("button", { name: "Pause", exact: true }).click();
    all.push(line(3), line(4), line(5));
    await expect(page.getByRole("button", { name: "+3 new events" })).toBeVisible({
      timeout: 6000,
    });
    await expect(events).toHaveText("Events2");
    const fircd = (await openFilter(page))
      .getByRole("group", { name: "Sources" })
      .getByRole("button")
      .first();
    await expect(fircd).toHaveText("firc core2");
    await closeFilter(page);
    await page.getByRole("button", { name: "+3 new events" }).click();
    await expect(events).toHaveText("Events5");
    await openFilter(page);
    await expect(fircd).toHaveText("firc core5");
  });

  // Catches a poll appending rows while paused, a wrong new-row count, or Resume not catching up.
  test("freezes the rows, counts the new ones, and resumes on a click", async ({ page }) => {
    const all = [line(1), line(2)];
    await live(page, all);
    await page.goto("/");
    await page.getByRole("tab", { name: "Journal" }).click();
    const rows = page.locator(".pane .row");
    await expect(rows).toHaveCount(2);

    await page.getByRole("button", { name: "Pause", exact: true }).click();
    await expect(page.getByRole("button", { name: "Resume", exact: true })).toBeVisible();

    all.push(line(3), line(4), line(5));
    await expect(page.getByRole("button", { name: "+3 new events" })).toBeVisible({
      timeout: 6000,
    });
    await expect(rows).toHaveCount(2);
    await expect(page.locator(".pane")).not.toContainText("line 3");
    await expect(
      page.locator(".status").getByRole("button", { name: "+3 new events" }),
    ).toBeVisible();
    await expect(page.locator(".card").getByRole("button")).toHaveCount(0);

    await page.getByRole("button", { name: "+3 new events" }).click();
    await expect(rows).toHaveCount(5);
    await expect(page.getByRole("button", { name: "+3 new events" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Pause", exact: true })).toBeVisible();
    const atBottom = await page
      .locator(".pane")
      .evaluate((el) => Math.abs(el.scrollHeight - el.clientHeight - el.scrollTop) <= 1);
    expect(atBottom).toBe(true);
  });
});

// Catches the fircd source shown under its old name, or a Russian form other than «Ядро firc».
for (const [locale, core] of [
  ["en", "firc core"],
  ["ru", "Ядро firc"],
]) {
  test(`the fircd source is named ${core}`, async ({ page }) => {
    await page.addInitScript((l) => {
      localStorage.setItem("locale", JSON.stringify({ value: l }));
    }, locale);
    await shell(page, MIXED);
    await page.goto("/journal");
    const panel = await openFilter(page, locale === "ru" ? "Фильтр" : "Filter");
    const sources = panel.getByRole("group", { name: locale === "ru" ? "Источники" : "Sources" });
    await expect(sources.getByRole("button").nth(0)).toHaveText(`${core}2`);
    await closeFilter(page);
    await expect(page.locator(".pane .row .chip").first()).toHaveText(core);
    const fits = await page
      .locator(".pane .row")
      .first()
      .evaluate((row) => {
        const chip = row.querySelector(".chip")!.getBoundingClientRect();
        const msg = row.querySelector(".msg")!.getBoundingClientRect();
        return chip.right <= msg.left && chip.height < 24;
      });
    expect(fits).toBe(true);
  });
}

// Catches a source label that wraps or spills out of its equal-width button at phone width, the fircd label cut short, or a 4-digit count shown in full there.
test("the source labels fit their buttons at 360 px", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
  });
  const many = Array.from({ length: 4000 }, (_, i) => ({ ...MIXED[4], seq: 100 + i }));
  const tun = Array.from({ length: 240 }, (_, i) => ({ ...MIXED[3], seq: 20000 + i }));
  const core = Array.from({ length: 1500 }, (_, i) => ({
    ...MIXED[0],
    seq: 9000 + i,
    level: ["debug", "info", "warn"][i % 3],
  }));
  await shell(page, [...MIXED, ...many, ...core, ...tun]);
  await page.goto("/");
  await page.getByRole("tab", { name: "Журнал" }).click();
  await page.setViewportSize({ width: 360, height: 740 });
  const buttons = (await openFilter(page, "Фильтр"))
    .getByRole("group", { name: "Источники" })
    .getByRole("button");
  await expect(buttons.nth(2)).toHaveText("DNS4k");
  await expect(buttons.nth(1)).toHaveText("Туннели240");
  await expect(buttons.nth(0)).toHaveText("Ядро firc1k");
  const boxes = await buttons.evaluateAll((els) =>
    els.map((el) => ({
      fits: el.scrollWidth <= el.clientWidth,
      width: Math.round(el.getBoundingClientRect().width),
      height: Math.round(el.getBoundingClientRect().height),
    })),
  );
  for (const b of boxes) expect(b.fits).toBe(true);
  expect(new Set(boxes.map((b) => b.width)).size).toBe(1);
  expect(new Set(boxes.map((b) => b.height)).size).toBe(1);
});

// Catches a second toolbar row, a control left out of it or out of order, or a source, level, group or capture control left in the header.
test("the header has one toolbar row: search, Фильтр, pause, clear", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
  });
  await page.setViewportSize({ width: 1280, height: 800 });
  await shell(page, MIXED);
  await page.goto("/journal");
  await expect(page.locator(".pane .row")).toHaveCount(4);
  const controls = [
    page.getByPlaceholder("клиент, имя или туннель"),
    page.getByRole("button", { name: /^Фильтр/ }),
    page.getByRole("button", { name: "Пауза", exact: true }),
    page.getByRole("button", { name: "Очистить вид", exact: true }),
  ];
  const boxes = [];
  for (const c of controls) boxes.push((await c.boundingBox())!);
  for (const b of boxes) {
    expect(Math.abs(b.y + b.height / 2 - (boxes[0].y + boxes[0].height / 2))).toBeLessThan(2);
  }
  for (let i = 1; i < boxes.length; i++) {
    expect(boxes[i].x).toBeGreaterThanOrEqual(boxes[i - 1].x + boxes[i - 1].width);
  }
  await expect(page.getByRole("group", { name: "Источники" })).toHaveCount(0);
  await expect(page.getByRole("group", { name: "Уровни журнала" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Захват 5 мин" })).toHaveCount(0);
  await expect(page.locator(".tb").getByText("любая группа")).toHaveCount(0);
  await expect(page.getByRole("tab", { name: /^События/ })).toHaveText("События4");
});

// Catches a badge that counts filters showing everything or misses the hidden debug level, or a popover without sources, levels or group.
test("Фильтр shows how many filters hide something and holds sources, levels and group", async ({
  page,
}) => {
  await page.addInitScript(() => {
    localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
  });
  await shell(page, MIXED);
  await page.route("**/groups?with_rules=true", (route) =>
    route.fulfill({
      json: {
        groups: [{ id: "a1a1a1a1", name: "media", interface: "nwg0", enable: true, rules: [] }],
      },
    }),
  );
  await page.goto("/journal");
  const trigger = page.getByRole("button", { name: /^Фильтр/ });
  const badge = trigger.locator(".jh-badge");
  await expect(badge).toHaveText("1");
  await expect(trigger).toHaveAttribute("aria-label", "Фильтр, активно: 1");
  const panel = await openFilter(page, "Фильтр");
  await expect(panel.getByRole("group", { name: "Источники" }).getByRole("button")).toHaveCount(3);
  const levels = panel.getByRole("group", { name: "Уровни журнала" }).getByRole("button");
  await expect(levels).toHaveCount(4);
  await expect(panel.getByRole("button", { name: "Группа" })).toHaveText("любая группа");

  await panel.getByRole("button", { name: "Показать всё" }).click();
  await expect(badge).toHaveCount(0);
  await expect(trigger).toHaveAttribute("aria-label", "Фильтр");
  await expect(levels.nth(0)).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".pane .row")).toHaveCount(5);
  await expect(panel.getByRole("button", { name: "Показать всё" })).toBeDisabled();

  await panel
    .getByRole("group", { name: "Источники" })
    .getByRole("button", { name: /DNS/ })
    .click();
  await expect(badge).toHaveText("1");
  await panel.getByRole("button", { name: "Группа" }).click();
  await page.getByRole("option", { name: "media" }).click();
  await expect(badge).toHaveText("2");
  await levels.nth(3).click();
  await expect(badge).toHaveText("3");
  await expect(trigger).toHaveAttribute("aria-label", "Фильтр, активно: 3");
});

// Catches «Утечки» left among the Events' sources or its rows left in the Events pane.
test("Events has no Утечки source", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
  });
  await shell(page, MIXED);
  await page.goto("/journal");
  await expect(page.locator(".pane .row")).toHaveCount(4);
  await expect(page.locator(".pane .row.bypass")).toHaveCount(0);
  await expect(page.locator(".pane")).not.toContainText("cdn.example.net");
  const panel = await openFilter(page, "Фильтр");
  await expect(panel.getByRole("group", { name: "Источники" }).getByRole("button")).toHaveText([
    "Ядро firc2",
    "Туннели2",
    "DNS1",
  ]);
  await expect(panel.getByText("Утечки")).toHaveCount(0);
});

// Catches a sub-tab label that wraps or spills past a phone's width, the long Russian label kept there, or the English names wrong.
test("at 360 px the three tabs fit and the second reads Статистика", async ({ page }) => {
  await page.addInitScript(() => {
    if (!localStorage.getItem("locale")) {
      localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
    }
  });
  await shell(page, MIXED);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/journal");
  const tabs = page.locator(".subtabs").getByRole("tab");
  await expect(tabs).toHaveCount(3);
  await expect(tabs.nth(1)).toHaveText("Статистика запросов");
  await expect(tabs.nth(2)).toHaveText("Захват");
  await page.setViewportSize({ width: 360, height: 740 });
  await expect(tabs.nth(1)).toHaveText("Статистика");
  await expect(tabs.nth(0)).toHaveText("События");
  const boxes = await tabs.evaluateAll((els) =>
    els.map((el) => ({ r: el.getBoundingClientRect(), fits: el.scrollWidth <= el.clientWidth })),
  );
  for (const b of boxes) {
    expect(b.fits).toBe(true);
    expect(b.r.right).toBeLessThanOrEqual(360);
    expect(Math.abs(b.r.top - boxes[0].r.top)).toBeLessThan(1);
  }
  const wide = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(wide).toBeLessThanOrEqual(0);
  await page.evaluate(() => localStorage.setItem("locale", JSON.stringify({ value: "en" })));
  await page.reload();
  await expect(tabs).toHaveText(["Events", "Stats", "Capture"]);
  await page.setViewportSize({ width: 1280, height: 800 });
  await expect(tabs).toHaveText(["Events4", "DNS stats", "Capture"]);
});

// Catches Clear view leaving the rows it was asked to drop.
test("Clear view empties the pane", async ({ page }) => {
  await shell(page, MIXED);
  await page.goto("/journal");
  await expect(page.locator(".pane .row")).toHaveCount(4);
  await page.getByRole("button", { name: "Clear view" }).click();
  await expect(page.locator(".pane .row")).toHaveCount(0);
  await expect(page.getByText("Nothing matches the filters.")).toBeVisible();
});

// Catches Clear view hiding the events that come after it, or leaving the lost-events notice up.
test("after Clear view new events show and the lost notice is gone", async ({ page }) => {
  let after = false;
  await shellWith(page, (route) => {
    const since = Number(new URL(route.request().url()).searchParams.get("since") ?? 0);
    const line = (seq: number, message: string) => ({
      seq,
      at: 1790000000 + seq,
      kind: "log",
      level: "info",
      source: "fircd",
      message,
    });
    if (since === 0) {
      return route.fulfill({
        json: { events: [line(1, "old one")], next: 1, dropped: 0, boot: "b" },
      });
    }
    if (since === 1) {
      return route.fulfill({
        json: { events: [line(7, "old two")], next: 7, dropped: 5, boot: "b" },
      });
    }
    if (since === 7 && after) {
      return route.fulfill({
        json: { events: [line(8, "fresh one")], next: 8, dropped: 0, boot: "b" },
      });
    }
    return route.fulfill({ json: { events: [], next: since, dropped: 0, boot: "b" } });
  });
  await page.goto("/journal");
  const rows = page.locator(".pane .row");
  const lost = page.getByText("Events were lost before this page asked for them: 5");
  await expect(rows).toHaveCount(2, { timeout: 5000 });
  await expect(lost).toBeVisible();

  await page.getByRole("button", { name: "Clear view" }).click();
  await expect(rows).toHaveCount(0);
  await expect(page.getByText("Events were lost before this page asked for them")).toHaveCount(0);

  after = true;
  await expect(rows).toHaveCount(1, { timeout: 5000 });
  await expect(rows.nth(0)).toContainText("fresh one");
  await expect(page.getByText("Events were lost before this page asked for them")).toHaveCount(0);
});
