import { expect, test, type Page } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";
import { answer, openSettings } from "./pages/settings";

const NOW = Math.floor(Date.now() / 1000);

const AUTOLIST = {
  "app.autolist.enabled": true,
  "app.autolist.mode": "candidates",
  "app.autolist.group": "",
  "app.autolist.failThreshold": 3,
  "app.autolist.failTime": 60,
  "app.autolist.retransThreshold": 3,
  "app.autolist.exclude": [],
  "app.autolist.recheck": false,
  "app.autolist.recheckInterval": 21600,
  "app.autolist.checkInterface": "",
};

const LIVE = ["enabled", "mode", "group", "checkInterface"].map((k) => `app.autolist.${k}`);

const GROUPS = [
  {
    id: "b10c4ed0",
    name: "Blocked",
    interface: "tunvless0",
    enable: true,
    devices: { allow: [], deny: [] },
    resolve: { tunnel: true, server: "" },
    live: true,
  },
];

const LIST_GROUP = {
  id: "115700a1",
  name: "Lists",
  interface: "ppp0",
  enable: true,
  list: { url: "https://example.invalid/l.txt" },
  devices: { allow: [], deny: [] },
  resolve: { tunnel: false, server: "" },
  live: true,
};

const BLOCK_GROUP = {
  id: "b10cb10c",
  name: "Ads",
  interface: "block",
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: false, server: "" },
  live: true,
};

async function settings(
  page: Page,
  over: Record<string, unknown> = {},
  locale = "en",
  groups: unknown[] = GROUPS,
) {
  const body = answer({ ...AUTOLIST, ...over });
  const classes: Record<string, string> = { ...body.classes };
  for (const k of LIVE) classes[k] = "live";
  body.classes = classes;
  await openSettings(page, (r) => r.fulfill({ json: body }), { groups, locale });
}

const row = (page: Page, key: string) => page.locator(`[data-row="${key}"]`);

test("the mode is a two-way segment that follows the saved value", async ({ page }) => {
  await settings(page, { "app.autolist.mode": "add" });
  const suggest = page.getByRole("button", { name: "Suggest" });
  const add = page.getByRole("button", { name: "Add by itself" });
  await expect(add).toHaveAttribute("aria-pressed", "true");
  await expect(suggest).toHaveAttribute("aria-pressed", "false");
  await suggest.click();
  await expect(suggest).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
});

test("an enabled autolist with no group marks the field and says why", async ({ page }) => {
  await settings(page);
  await expect(
    row(page, "app.autolist.group").getByText(
      "Choose a group: automatic adding will not turn on without one",
    ),
  ).toBeVisible();
  await expect(row(page, "app.autolist.group").locator(".autolist-group")).toHaveClass(/invalid/);
});

test("a list group is offered and shown by its name, a block group is not offered", async ({
  page,
}) => {
  await settings(page, { "app.autolist.group": "115700a1" }, "en", [
    ...GROUPS,
    LIST_GROUP,
    BLOCK_GROUP,
  ]);
  const trigger = row(page, "app.autolist.group").locator("[data-select-trigger]");
  await expect(trigger).toContainText("Lists");
  await expect(row(page, "app.autolist.group")).not.toContainText("A group that no longer exists");
  await trigger.click();
  await expect(page.getByRole("option", { name: /Lists/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Blocked/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Ads/ })).toHaveCount(0);
});

test("an empty group reads «не выбрана»", async ({ page }) => {
  await settings(page, {}, "ru");
  await expect(row(page, "app.autolist.group").locator("[data-select-trigger]")).toHaveText(
    "не выбрана",
  );
});

test("the recheck interval is shown in hours and saved in seconds", async ({ page }) => {
  const puts: unknown[] = [];
  const body = answer({ ...AUTOLIST });
  body.classes = { ...body.classes, "app.autolist.recheckInterval": "live" };
  await openSettings(
    page,
    async (r) => {
      if (r.request().method() === "PUT") {
        puts.push(r.request().postDataJSON());
        await r.fulfill({
          json: { applied: ["app.autolist.recheckInterval"], pendingRestart: [] },
        });
        return;
      }
      await r.fulfill({ json: body });
    },
    { groups: GROUPS },
  );
  const field = row(page, "app.autolist.recheckInterval");
  const input = field.getByRole("spinbutton");
  await expect(input).toHaveValue("6");
  await expect(input).toHaveAttribute("min", "1");
  await expect(input).toHaveAttribute("max", "168");
  await expect(input).toHaveAttribute("step", "1");
  await expect(field.locator(".unit")).toHaveText("h");
  await input.fill("12");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  const dialog = page.getByRole("dialog");
  const changed = dialog.locator('[data-key="app.autolist.recheckInterval"]');
  await expect(changed.locator(".was")).toHaveText("6 h");
  await expect(changed.locator(".now")).toHaveText("12 h");
  await dialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();
  expect(puts).toEqual([{ settings: { "app.autolist.recheckInterval": 43200 } }]);
});

test("a recheck interval that is not a whole hour reads as decimal hours", async ({ page }) => {
  await settings(page, { "app.autolist.recheckInterval": 600 }, "ru");
  const field = row(page, "app.autolist.recheckInterval");
  await expect(field.getByRole("spinbutton")).toHaveValue("0.17");
  await expect(field.locator(".unit")).toHaveText("ч");
});

test("a chosen group clears the message", async ({ page }) => {
  await settings(page, { "app.autolist.group": "b10c4ed0" });
  await expect(page.getByText("Choose a group: automatic adding will not turn on")).toHaveCount(0);
});

test("a disabled autolist asks for no group", async ({ page }) => {
  await settings(page, { "app.autolist.enabled": false });
  await expect(page.getByText("Choose a group: automatic adding will not turn on")).toHaveCount(0);
});

test("a zero TTL outside the rules shows the warning", async ({ page }) => {
  await settings(page, { "app.dnsProxy.unmatchedTtl": 0 });
  await expect(page.getByTestId("autolist-ttl-warning")).toContainText(
    "TTL of answers outside the rules",
  );
});

test("a positive TTL shows no warning", async ({ page }) => {
  await settings(page);
  await expect(page.getByTestId("autolist-ttl-warning")).toHaveCount(0);
});

test("the group's own interface is greyed in the check-through picker with the hint", async ({
  page,
}) => {
  await settings(page, { "app.autolist.group": "b10c4ed0" });
  const picker = row(page, "app.autolist.checkInterface");
  await expect(
    picker.getByText("Interfaces of group «Blocked» are unavailable", { exact: false }),
  ).toBeVisible();
  await picker.locator("[data-select-trigger]").click();
  await expect(page.getByRole("option", { name: /VLESS/ })).toHaveAttribute("data-disabled", "");
  await expect(page.getByRole("option", { name: /Broadband/ })).not.toHaveAttribute(
    "data-disabled",
    "",
  );
});

test("a link line leads to the journal's unopened tab", async ({ page }) => {
  await settings(page);
  await row(page, "app.autolist.mode")
    .getByRole("button", { name: /Not opening/ })
    .click();
  await expect(page).toHaveURL(/\/journal\/unopened$/);
});

const RULES = [
  { id: "a0000001", type: "namespace", rule: "rutracker.org", enable: true, autolist: "x" },
  { id: "a0000002", type: "namespace", rule: "example-news.com", enable: false, autolist: "x" },
  { id: "a0000003", type: "namespace", rule: "youtube.com", enable: true },
];

async function groupWithRules(page: Page, candidates: unknown[]) {
  const group = { ...GROUPS[0], rules: RULES };
  await signedIn(page);
  await page.route("**/interfaces", (r) =>
    r.fulfill({ json: { interfaces: [{ id: "tunvless0", role: "tunnel" }] } }),
  );
  await page.route("**/system/netfilter", (r) => r.fulfill({ json: { ok: true } }));
  await page.route("**/system/hosts", (r) =>
    r.fulfill({
      json: {
        hosts: [
          {
            mac: "aa:00:00:00:00:51",
            name: "iPad",
            ip: "192.168.1.51",
            ip6: [],
            active: true,
            registered: true,
            policy: "",
          },
        ],
      },
    }),
  );
  await page.route(/\/system\/autolist$/, (r) =>
    r.fulfill({
      json: {
        enabled: true,
        running: true,
        mode: "add",
        group: "b10c4ed0",
        failures: 0,
        failuresDay: 0,
        listed: 0,
        addedHour: 0,
        checking: false,
        checkedAt: 0,
        switchedOff: 0,
        switchedOn: 0,
        bypassed: [],
        candidates,
        probes: { usedHour: 0, queued: 0, running: null, results: [] },
      },
    }),
  );
  await page.route(/\/groups(\?.*)?$/, (r) => r.fulfill({ json: { groups: [group] } }));
  const groups = new GroupsPage(page);
  await groups.goto();
  await groups.expandGroup(0);
  return page.locator(".group-wrapper").first().locator(".rule");
}

test("an automatic rule carries the badge and a tooltip with the candidate's story", async ({
  page,
}) => {
  const rules = await groupWithRules(page, [
    {
      domain: "rutracker.org",
      host: "rutracker.org",
      why: "no-answer",
      fails: 3,
      clients: ["192.168.1.51"],
      lastAt: NOW - 120,
      state: "added",
      notes: 0,
    },
  ]);
  const badge = rules.nth(0).locator(".autolist-badge");
  await expect(badge).toHaveText("auto");
  await expect(rules.nth(2).locator(".autolist-badge")).toHaveCount(0);
  await badge.hover();
  const tip = page.getByRole("tooltip");
  await expect(tip).toContainText("Added automatically");
  await expect(tip).toContainText(
    "rutracker.org did not answer ClientHello 3 times in a row (iPad).",
  );
  await expect(tip).toContainText(
    "If you switch the rule off or change it, it becomes yours and the automation no longer touches it.",
  );
});

test("the tooltip falls back to the host once the daemon forgot the candidate", async ({
  page,
}) => {
  const rules = await groupWithRules(page, []);
  await rules.nth(0).locator(".autolist-badge").hover();
  await expect(page.getByRole("tooltip")).toContainText("Added automatically for rutracker.org.");
});

test("a rule the recheck switched off is dimmed with its own badge", async ({ page }) => {
  const rules = await groupWithRules(page, []);
  const off = rules.nth(1);
  await expect(off.locator(".autolist-badge")).toHaveText("auto · off by recheck");
  await expect(off.locator(".rule-row")).toHaveClass(/autolist-off/);
  await expect(rules.nth(0).locator(".rule-row")).not.toHaveClass(/autolist-off/);
});
