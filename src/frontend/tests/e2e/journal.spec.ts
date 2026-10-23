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
  const sources = page.getByRole("group", { name: "Sources" });
  const levels = page.getByRole("group", { name: "Levels" });
  await expect(rows).toHaveCount(5);
  await expect(page.getByText("a detail")).toHaveCount(0);
  await expect(sources.getByRole("button")).toHaveText([
    "firc core2",
    "Tunnels2",
    "DNS1",
    "Leaks1",
  ]);
  await expect(levels.getByRole("button", { name: "debug" })).toHaveAttribute(
    "aria-pressed",
    "false",
  );

  await levels.getByRole("button", { name: "debug" }).click();
  await expect(rows).toHaveCount(6);
  for (const name of ["debug", "info", "warn"]) await levels.getByRole("button", { name }).click();
  await expect(rows).toHaveCount(3);
  await expect(page.locator(".pane .row.l-error")).toHaveText(/no usable VLESS node/);
  await expect(sources.getByRole("button", { name: /firc core/ })).toHaveText("firc core2");

  await levels.getByRole("button", { name: "error" }).click();
  await expect(rows).toHaveCount(2);
  await sources.getByRole("button", { name: /DNS/ }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("cdn.example.net");
});

// Catches a tunnel badge that does not search for its device, or a search that ignores the source.
test("clicking a tunnel's badge shows that tunnel's lines", async ({ page }) => {
  await shell(page, MIXED);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  await expect(rows).toHaveCount(5);
  await expect(rows.nth(0).locator(".chip")).toHaveText("firc core");
  await rows.nth(1).getByRole("button", { name: "tunvless0" }).click();
  await expect(page.getByPlaceholder("client, name or tunnel")).toHaveValue("tunvless0");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("B does not answer");
  await expect(rows.nth(0)).not.toContainText("tunnel tunvless0");
});

// Catches a toolbar or row wider than a phone, or segments that do not split into rows of four.
test("a phone-wide journal scrolls only down", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await shell(page, MIXED);
  await page.goto("/journal");
  await expect(page.locator(".pane .row")).toHaveCount(5);
  const wide = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(wide).toBeLessThanOrEqual(0);
  for (const name of ["Sources", "Levels"]) {
    const boxes = await page
      .getByRole("group", { name })
      .getByRole("button")
      .evaluateAll((els) => els.map((el) => el.getBoundingClientRect()));
    expect(boxes).toHaveLength(4);
    for (const b of boxes) {
      expect(Math.abs(b.top - boxes[0].top)).toBeLessThan(1);
      expect(Math.abs(b.width - boxes[0].width)).toBeLessThan(1);
    }
  }
  const search = await page.getByPlaceholder("client, name or tunnel").boundingBox();
  const levels = await page.getByRole("group", { name: "Levels" }).boundingBox();
  expect(search && levels && search.width).toBeGreaterThan((levels?.width ?? 0) * 0.8);
  const row = page.locator(".pane .row").first();
  const at = await row.locator(".at").boundingBox();
  const msg = await row.locator(".msg").boundingBox();
  expect(msg!.y).toBeGreaterThanOrEqual(at!.y + at!.height - 1);
  await expect(page.getByRole("group", { name: "Sources" }).getByRole("button").first()).toHaveCSS(
    "color",
    "rgb(143, 179, 204)",
  );
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

// Catches a bypass event showing the flow's own data instead of what firc last answered.
test("a bypass event is shown with what firc answered", async ({ page }) => {
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
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("by address");
  await expect(rows.nth(0)).toContainText("firc issued 198.18.0.5");
  await rows.nth(0).getByRole("button", { name: "cdn.example.net" }).click();
  await expect(rows).toHaveCount(1);
  await rows.nth(0).getByRole("button", { name: "192.168.1.42" }).click();
  await expect(rows).toHaveCount(1);
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
  await page.getByRole("group", { name: "Levels" }).getByRole("button", { name: "debug" }).click();
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
  const sources = page.getByRole("group", { name: "Sources" }).getByRole("button");
  const levels = page.getByRole("group", { name: "Levels" }).getByRole("button");
  for (let i = 0; i < 4; i++) await expect(sources.nth(i)).toHaveAttribute("aria-pressed", "true");
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

  async function openFilter(page: Page) {
    await page.getByRole("button", { name: "Group" }).click();
    return page.getByRole("option");
  }

  // Catches the group options coming from the buffer alone.
  test("lists the groups with nothing in the buffer", async ({ page }) => {
    await withGroups(page, []);
    await page.goto("/");
    await page.getByRole("tab", { name: "Journal" }).click();
    await expect(page.locator(".pane .row")).toHaveCount(0);
    await expect(await openFilter(page)).toHaveText(["any group", "media", "work"]);
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
    await expect(await openFilter(page)).toHaveText([
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
    await (await openFilter(page)).filter({ hasText: "work" }).click();
    const trigger = page.getByRole("button", { name: "Group" });
    await expect(trigger).toHaveText("work");
    await page.getByRole("button", { name: "Clear view" }).click();
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
    const fircd = page.getByRole("group", { name: "Sources" }).getByRole("button").first();
    await expect(fircd).toHaveText("firc core2");
    await page.getByRole("button", { name: "Pause", exact: true }).click();
    all.push(line(3), line(4), line(5));
    await expect(page.getByRole("button", { name: "+3 new events" })).toBeVisible({
      timeout: 6000,
    });
    await expect(fircd).toHaveText("firc core2");
    await page.getByRole("button", { name: "+3 new events" }).click();
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

// Catches the bypass or fircd source shown under its old name, or a Russian form other than «Утечки» and «Ядро firc».
for (const [locale, label, core] of [
  ["en", "Leaks", "firc core"],
  ["ru", "Утечки", "Ядро firc"],
]) {
  test(`the bypass source is named ${label}`, async ({ page }) => {
    await page.addInitScript((l) => {
      localStorage.setItem("locale", JSON.stringify({ value: l }));
    }, locale);
    await shell(page, MIXED);
    await page.goto("/");
    await page.getByRole("tab", { name: locale === "ru" ? "Журнал" : "Journal" }).click();
    const sources = page.getByRole("group", { name: locale === "ru" ? "Источники" : "Sources" });
    await expect(sources.getByRole("button").nth(3)).toHaveText(`${label}1`);
    await expect(page.locator(".pane .row.bypass .chip")).toHaveText(label);
    await expect(sources.getByRole("button").nth(0)).toHaveText(`${core}2`);
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

// Catches a source label that wraps or spills out of its equal-width button at phone width, or the fircd tab not shortened there.
test("the source labels fit their buttons at 360 px", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
  });
  const many = Array.from({ length: 4000 }, (_, i) => ({ ...MIXED.at(-1), seq: 100 + i }));
  const core = Array.from({ length: 1500 }, (_, i) => ({
    ...MIXED[0],
    seq: 9000 + i,
    level: ["debug", "info", "warn"][i % 3],
  }));
  await shell(page, [...MIXED, ...many, ...core]);
  await page.goto("/");
  await page.getByRole("tab", { name: "Журнал" }).click();
  await page.setViewportSize({ width: 360, height: 740 });
  const buttons = page.getByRole("group", { name: "Источники" }).getByRole("button");
  await expect(buttons.nth(3)).toHaveText("Утечки4001");
  await expect(buttons.nth(0)).toHaveText(/^Ядро\d{4}$/);
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
