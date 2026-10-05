import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

type Record_ = { [key: string]: unknown };

const group = (id: string, name: string, extra: Record_ = {}) => ({
  id,
  name,
  interface: "wg0",
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [],
  live: true,
  ...extra,
});

const GROUPS = () => [
  group("0a000001", "Telegram"),
  group("0a000002", "Insta", { live: false, liveReason: "not-enabled" }),
  group("0a000003", "Speedtest", { interface: "nwg1", live: false, liveReason: "no-interface" }),
  group("0a000004", "Work", { enable: false, live: false, liveReason: "disabled" }),
  group("0a000005", "Tele2", { live: false, liveReason: "not-written" }),
  group("0a000006", "Unavailable", {
    list: {
      url: "https://example.com/list.txt",
      interval: 86400,
      lastUpdate: 1790000000,
      rulesTotal: 2,
      sync: { state: "idle", error: "", lastCheck: 1790000000 },
    },
  }),
];

async function setup(page: Page) {
  const daemon = {
    down: false,
    groups: GROUPS(),
    netfilter: {
      ok: false,
      error: "iptables-restore: line 56 failed",
      since: 1790000000,
    } as Record_,
    polls: 0,
    puts: [] as any[],
  };
  const strip = (records: any[], withRules: boolean) =>
    records.map(({ rules, ...g }) => (withRules ? { ...g, rules } : g));

  await signedIn(page);
  await page.route("**/interfaces", (route) =>
    route.fulfill({ json: { interfaces: [{ id: "wg0" }, { id: "nwg1" }] } }),
  );
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) =>
    daemon.down ? route.abort("connectionrefused") : route.fulfill({ json: daemon.netfilter }),
  );
  await page.route("**/system/config/save", (route) => route.fulfill({ json: {} }));
  await page.route(/\/groups(\?.*)?$/, async (route) => {
    const request = route.request();
    if (request.method() === "PUT") {
      const body = request.postDataJSON();
      daemon.puts.push(body);
      daemon.groups = body.groups.map((g: any) => ({ ...g, live: true }));
      await route.fulfill({ json: { groups: daemon.groups } });
      return;
    }
    const withRules = request.url().includes("with_rules=true");
    if (daemon.down) {
      await route.abort("connectionrefused");
      return;
    }
    if (!withRules) daemon.polls++;
    await route.fulfill({ json: { groups: strip(daemon.groups, withRules) } });
  });
  await page.goto("/");
  await expect(page.locator(".group")).toHaveCount(6);
  return daemon;
}

async function statusOf(page: Page, name: string) {
  const index = await page
    .locator("input.group-name")
    .evaluateAll(
      (inputs, wanted) => inputs.findIndex((i) => (i as HTMLInputElement).value === wanted),
      name,
    );
  expect(index, `a card named ${name}`).toBeGreaterThanOrEqual(0);
  return page.locator(".group").nth(index).locator(".live-status");
}

test.describe("A group's live state", () => {
  // Catches a state getting another's icon, or losing its accessible name.
  test("each state has its icon and name", async ({ page }) => {
    await setup(page);
    const expected: [string, string, string][] = [
      ["Telegram", "live", "circle-check"],
      ["Insta", "not-enabled", "circle-x"],
      ["Speedtest", "no-interface", "unplug"],
      ["Work", "disabled", "power-off"],
      ["Tele2", "not-written", "refresh-cw"],
      ["Unavailable", "live", "circle-check"],
    ];
    for (const [name, kind, lucide] of expected) {
      const status = await statusOf(page, name);
      await expect(status, name).toHaveAttribute("data-kind", kind);
      await expect(status.locator(`svg.lucide-${lucide}`), name).toHaveCount(1);
    }
    await expect(await statusOf(page, "Telegram")).toHaveAccessibleName("Working");
    await expect(await statusOf(page, "Work")).toHaveAccessibleName("Group off");
  });

  // Catches icons drifting with the place number or name, or off the card's middle.
  test("the icons form one column, centred on each card", async ({ page }) => {
    await setup(page);
    const boxes = await page.locator(".group-header").evaluateAll((headers) =>
      headers.map((h) => {
        const i = h.querySelector(".live-status")!.getBoundingClientRect();
        const n = h.querySelector("input.group-name")!.getBoundingClientRect();
        const r = h.getBoundingClientRect();
        return {
          iconLeft: i.left,
          iconMid: i.top + i.height / 2,
          iconSize: [i.width, i.height],
          cardMid: r.top + r.height / 2,
          cardHeight: r.height,
          nameLeft: n.left,
        };
      }),
    );
    const list = boxes[5];
    const plain = boxes[0];
    expect(list.cardHeight, "fixture: the list card is taller").toBeGreaterThan(
      plain.cardHeight + 20,
    );
    for (const b of boxes) {
      expect(b.iconSize).toEqual([26, 26]);
      expect(Math.abs(b.iconLeft - plain.iconLeft)).toBeLessThanOrEqual(0.5);
      expect(Math.abs(b.nameLeft - plain.nameLeft)).toBeLessThanOrEqual(0.5);
      expect(Math.abs(b.iconMid - b.cardMid)).toBeLessThanOrEqual(1);
      expect(b.nameLeft).toBeGreaterThan(b.iconLeft + 26);
    }
  });

  // Catches the tooltip opening for a mouse only, or naming the wrong state.
  test("the tooltip opens on hover and on keyboard focus", async ({ page }) => {
    await setup(page);
    const tip = page.getByRole("tooltip");

    await (await statusOf(page, "Speedtest")).hover();
    await expect(tip).toContainText("Waiting for interface nwg1");
    await expect(tip).toContainText("Tunnel nwg1 is off or not connected");
    await expect(tip).toContainText(/Checked \d+ s ago/);
    await page.mouse.move(0, 0);
    await expect(tip).toHaveCount(0);

    const tele2 = await statusOf(page, "Tele2");
    await tele2.focus();
    await expect(tip).toContainText("Rules are being rewritten");
    await expect(tip.locator("code")).toHaveText("iptables-restore: line 56 failed");
    await expect(tele2).toHaveAttribute("aria-describedby", (await tip.getAttribute("id"))!);
    await page.keyboard.press("Escape");
    await expect(tip).toHaveCount(0);

    await (await statusOf(page, "Work")).focus();
    await expect(tip).toContainText("The group is switched off");
    await expect(tip).not.toContainText("Checked");
  });

  // Catches live state being read once, or a poll's answer not merged into the cards.
  test("a change on the daemon shows within one poll, without a reload", async ({ page }) => {
    const daemon = await setup(page);
    await page.evaluate(() => ((window as any).__sameDocument = true));
    const insta = await statusOf(page, "Insta");
    await expect(insta).toHaveAttribute("data-kind", "not-enabled");

    daemon.groups = daemon.groups.map((g) =>
      g.name === "Insta" ? { ...g, live: true, liveReason: undefined } : g,
    );
    daemon.netfilter = { ok: false, firstWritePending: true };
    await expect(insta).toHaveAttribute("data-kind", "live", { timeout: 8000 });
    expect(daemon.polls).toBeGreaterThanOrEqual(1);
    expect(await page.evaluate(() => (window as any).__sameDocument)).toBe(true);

    await (await statusOf(page, "Tele2")).hover();
    await expect(page.getByRole("tooltip")).toContainText("First write of the rules since start");
  });

  // Catches stale green icons staying up while the daemon is silent, or not recovering.
  test("a daemon that stops answering greys every icon until it answers", async ({ page }) => {
    await page.clock.install();
    const daemon = await setup(page);
    const telegram = await statusOf(page, "Telegram");
    await expect(telegram).toHaveAttribute("data-kind", "live");

    daemon.down = true;
    await page.clock.runFor(10_000);
    await expect(telegram, "two missed polls are not silence yet").toHaveAttribute(
      "data-kind",
      "live",
    );
    await page.clock.runFor(10_000);
    for (const name of ["Telegram", "Insta", "Work", "Unavailable"]) {
      const status = await statusOf(page, name);
      await expect(status, name).toHaveAttribute("data-kind", "no-answer");
      await expect(status.locator("svg.lucide-circle-question-mark"), name).toHaveCount(1);
    }
    await telegram.hover();
    await expect(page.getByRole("tooltip")).toContainText("No answer from the daemon");
    await expect(page.getByRole("tooltip")).toContainText(/no answer from firc for \d+ s\./);
    await page.mouse.move(0, 0);

    daemon.down = false;
    await page.clock.runFor(5_000);
    await expect(telegram).toHaveAttribute("data-kind", "live");
    await expect(await statusOf(page, "Insta")).toHaveAttribute("data-kind", "not-enabled");
  });

  // Catches Escape closing only a tooltip opened by focus.
  test("Escape closes a tooltip opened by hover", async ({ page }) => {
    await setup(page);
    await (await statusOf(page, "Insta")).hover();
    await expect(page.getByRole("tooltip")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("tooltip")).toHaveCount(0);
  });

  // Catches a hidden tab polling, or a re-shown tab waiting a whole interval.
  test("a hidden tab does not poll, and polls once when shown", async ({ page }) => {
    const daemon = await setup(page);
    const setVisibility = (state: string) =>
      page.evaluate((s) => {
        Object.defineProperty(document, "visibilityState", { value: s, configurable: true });
        document.dispatchEvent(new Event("visibilitychange"));
      }, state);

    await setVisibility("hidden");
    const before = daemon.polls;
    await page.waitForTimeout(6000);
    expect(daemon.polls, "no poll while hidden").toBe(before);

    await setVisibility("visible");
    await expect.poll(() => daemon.polls, { timeout: 1000 }).toBe(before + 1);
  });

  // Catches an unsaved edit showing the daemon's state, or Save sending the daemon's fields back.
  test("an unsaved edit shows as such until Save brings the state back", async ({ page }) => {
    const daemon = await setup(page);
    const insta = await statusOf(page, "Insta");
    const telegram = await statusOf(page, "Telegram");

    await page.locator("input.group-name").nth(1).fill("Insta2");
    await expect(insta).toHaveAttribute("data-kind", "unsaved");
    await expect(insta.locator("svg.lucide-circle-dashed")).toHaveCount(1);
    await expect(telegram, "another card keeps its state").toHaveAttribute("data-kind", "live");
    await insta.hover();
    await expect(page.getByRole("tooltip")).toContainText("Changes not saved");

    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = daemon.puts[0].groups[1];
    expect("live" in sent || "liveReason" in sent).toBe(false);
    await expect(insta).toHaveAttribute("data-kind", "live");
  });
});
