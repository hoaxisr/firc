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
    return route.fulfill({ json: { events: fresh, next, dropped: 0, level: "info" } });
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
    { seq: 1, at: 1790000000, kind: "log", level: "warn", message: "pool is low" },
  ]);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  await expect(page.locator(".row.warn").getByText("pool is low")).toBeVisible();
  await page.waitForTimeout(2500);
  await expect(page.locator(".pane .row")).toHaveCount(1);
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
    { seq: 3, at: 1790000002, kind: "log", level: "info", message: "netfilter rebuilt" },
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
    { seq: 3, at: 1790000002, kind: "log", level: "info", message: "netfilter rebuilt" },
  ]);
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  const rows = page.locator(".pane .row");
  await expect(rows).toHaveCount(3);

  const search = page.getByPlaceholder("client or name");
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
  await expect(page.getByPlaceholder("client or name")).toHaveValue("youtube.com");
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

// Catches a stored, removed tab opening a tab that renders nothing.
test("a stored bypass tab opens a tab that exists", async ({ page }) => {
  await shell(page, []);
  await page.addInitScript(() => {
    localStorage.setItem("active_tab", JSON.stringify({ value: "bypass" }));
  });
  await page.goto("/");
  await expect(page.locator('[data-tabs-trigger][data-state="active"]')).toContainText("Groups");
  await expect(page.locator('[data-tabs-content][data-state="active"]')).toBeVisible();
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
      message: `m${since + i + 1}`,
    }));
    return route.fulfill({ json: { events, next: since + size, dropped: 0, level: "info" } });
  });
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
  await expect(page.getByText("m1027")).toBeVisible();
  expect(at.length).toBeGreaterThanOrEqual(2);
  expect(at[1] - at[0]).toBeLessThan(1000);
});

// Catches rows arriving under display:none (scrollHeight 0) leaving the tab open on its top row.
test("the pane follows to the bottom the first time its tab is opened", async ({ page }) => {
  const events = Array.from({ length: 80 }, (_, i) => ({
    seq: i + 1,
    at: 1790000000 + i,
    kind: "log",
    level: "info",
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
          events: [{ seq: 1, at: 1790000100, kind: "log", level: "info", message: "second run" }],
        }
      : {
          boot: "a",
          events: [
            { seq: 1, at: 1790000000, kind: "log", level: "info", message: "first run" },
            { seq: 2, at: 1790000001, kind: "log", level: "info", message: "first run, later" },
          ],
        };
    const fresh = run.events.filter((e) => e.seq > since);
    const next = fresh.length ? fresh[fresh.length - 1].seq : since;
    return route.fulfill({
      json: { events: fresh, next, dropped: 0, level: "info", boot: run.boot },
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
    message: `line ${seq}`,
  });

  async function live(page: Page, all: unknown[]) {
    await shellWith(page, (route) => {
      const since = Number(new URL(route.request().url()).searchParams.get("since") ?? 0);
      const fresh = (all as { seq: number }[]).filter((e) => e.seq > since);
      const next = fresh.length ? fresh[fresh.length - 1].seq : since;
      return route.fulfill({ json: { events: fresh, next, dropped: 0, level: "info" } });
    });
  }

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
