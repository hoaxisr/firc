import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

const NOW = Math.floor(Date.now() / 1000);
const DAEMON_NOW = NOW - 7200;

const NONE = {
  source: "none",
  servers: [],
  health: { window: 600, total: 0, fallbacks: 0, last: 0, reason: "", resting: false, since: 0 },
};

const HOSTS = [
  host("aa:00:00:00:00:03", "Phone", "192.168.1.7", ["fd00::7"]),
  host("aa:00:00:00:00:01", "Living room TV", "192.168.1.5", ["fd00::5"]),
  host("aa:00:00:00:00:02", "Desktop", "192.168.1.42"),
  host("", "", "192.168.1.8"),
];

function host(mac: string, name: string, ip: string, ip6: string[] = []) {
  return { mac, name, ip, ip6, active: true, registered: true, policy: "" };
}

type Owner = { id: string; name: string; interface: string; blocked: boolean } | null;
type Key = {
  name: string;
  client: string;
  queries: number;
  blocked: number;
  ago: number;
  owner: Owner;
};

const EXAMPLE = { id: "e1e1e1e1", name: "Example Group", interface: "nwg0", blocked: false };
const ADS = { id: "ad5ad5ad", name: "Ads", interface: "block", blocked: true };
const LOW = { id: "10101010", name: "Low route", interface: "nwg0", blocked: false };

const KEYS: Key[] = [
  key("googlevideo.com", "192.168.1.5", 120, 0, 0, null),
  key("googlevideo.com", "fd00::5", 50, 0, 5, null),
  key("googlevideo.com", "192.168.1.7", 41, 0, 30, null),
  key("googlevideo.com", "192.168.1.42", 10, 0, 400, null),
  key("ya.ru", "192.168.1.7", 70, 0, 10, null),
  key("ya.ru", "fd00::7", 30, 0, 20, null),
  key("ya.ru", "192.168.1.42", 15, 0, 900, null),
  key("ads.doubleclick.net", "192.168.1.42", 88, 88, 3, {
    ...ADS,
    interface: "nwg0",
    blocked: false,
  }),
  key("graph.facebook.com", "192.168.1.42", 50, 0, 1080, {
    ...EXAMPLE,
    interface: "block",
    blocked: true,
  }),
  key("low.example.org", "192.168.1.8", 12, 0, 7200, LOW),
  key("github.com", "192.168.1.42", 30, 0, 1200, null),
  key("github.com", "192.168.1.99", 10, 0, 1300, null),
  key("my printer.local", "192.168.1.42", 3, 0, 5000, null),
  key("7.1.168.192.in-addr.arpa", "192.168.1.7", 300, 0, 60, null),
];

function key(
  name: string,
  client: string,
  queries: number,
  blocked: number,
  ago: number,
  owner: Owner,
): Key {
  return { name, client, queries, blocked, ago, owner };
}

function answerStats(url: URL, extra: Key[] = []) {
  const device = url.searchParams.get("device");
  const q = (url.searchParams.get("q") ?? "").toLowerCase();
  const arpa = url.searchParams.get("arpa") === "1";
  const addrs = device ? device.split(",").map((a) => a.toLowerCase()) : null;
  const kept = [...KEYS, ...extra].filter(
    (k) => (arpa || !k.name.endsWith(".arpa")) && (!addrs || addrs.includes(k.client)),
  );
  const byName = new Map<string, Key[]>();
  for (const k of kept) byName.set(k.name, [...(byName.get(k.name) ?? []), k]);
  const all = [...byName.entries()].map(([name, ks]) => {
    const latest = [...ks].sort((a, b) => a.ago - b.ago)[0];
    return {
      name,
      queries: ks.reduce((s, k) => s + k.queries, 0),
      blocked: ks.reduce((s, k) => s + k.blocked, 0),
      last: DAEMON_NOW - latest.ago,
      owner: latest.owner,
      clients: [...ks]
        .sort((a, b) => b.queries - a.queries)
        .map((k) => ({ address: k.client, queries: k.queries })),
      clientsTotal: ks.length,
    };
  });
  const matched = all
    .filter((r) => r.name.includes(q))
    .sort((a, b) => b.queries - a.queries || a.name.localeCompare(b.name));
  return {
    window: 86400,
    now: DAEMON_NOW,
    since: DAEMON_NOW - 3 * 86400,
    queries: kept.reduce((s, k) => s + k.queries, 0),
    blocked: kept.reduce((s, k) => s + k.blocked, 0),
    domains: byName.size,
    rows: matched,
    matched: matched.length,
    offset: 0,
  };
}

const group = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
  id,
  name,
  interface: "block",
  block: "null",
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [],
  resolver: NONE,
  live: true,
  ...extra,
});

const EXAMPLE_GROUP = group(EXAMPLE.id, EXAMPLE.name, {
  interface: "nwg0",
  block: undefined,
  rules: [{ id: "e1e1e101", enable: true, rule: "facebook.com", type: "namespace" }],
});
const ADS_GROUP = group(ADS.id, ADS.name, {
  rules: [{ id: "ad5ad501", enable: true, rule: "doubleclick.net", type: "namespace" }],
});
const TRACKERS_GROUP = group("7ac7e125", "Trackers");
const KIDS_GROUP = group("k1d5b10c", "Kids block", {
  devices: { allow: ["mac:aa:00:00:00:00:03"], deny: [] },
});
const OFF_GROUP = group("0ff0ff00", "Old block", { enable: false });
const LOW_GROUP = group(LOW.id, LOW.name, { interface: "nwg0", block: undefined });

async function setup(page: Page, groups: Record<string, unknown>[], extra: Key[] = []) {
  const daemon = {
    groups: structuredClone(groups),
    puts: [] as any[],
    stats: [] as URL[],
  };
  await signedIn(page);
  await page.addInitScript(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
  await page.route("**/interfaces", (route) =>
    route.fulfill({
      json: { interfaces: [{ id: "blackhole" }, { id: "block" }, { id: "nwg0", name: "WARP" }] },
    }),
  );
  await page.route(/\/subscriptions(\?.*)?$/, (route) =>
    route.fulfill({ json: { subscriptions: [] } }),
  );
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: HOSTS } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route("**/system/config/save", (route) => route.fulfill({ json: {} }));
  await page.route(/\/system\/capture(\?.*)?$/, (route) =>
    route.fulfill({ json: { running: false } }),
  );
  await page.route(/\/system\/events(\?.*)?$/, (route) =>
    route.fulfill({ json: { events: [], next: 0, dropped: 0, boot: "b1" } }),
  );
  await page.route(/\/system\/dnsstats(\?.*)?$/, (route) => {
    const url = new URL(route.request().url());
    daemon.stats.push(url);
    return route.fulfill({ json: answerStats(url, extra) });
  });
  await page.route(/\/groups(\?.*)?$/, async (route) => {
    const request = route.request();
    if (request.method() === "PUT") {
      const body = request.postDataJSON();
      daemon.puts.push(body);
      daemon.groups = body.groups.map((g: any) => ({ ...g, resolver: NONE, live: true }));
      await route.fulfill({ json: { groups: daemon.groups } });
      return;
    }
    const withRules = request.url().includes("with_rules=true");
    await route.fulfill({
      json: {
        groups: daemon.groups.map(({ rules, ...g }: any) => (withRules ? { ...g, rules } : g)),
      },
    });
  });
  await page.goto("/journal/stats");
  await expect(page.locator(".stats-row").first()).toBeVisible();
  return daemon;
}

const row = (page: Page, name: string) =>
  page.locator(".stats-row").filter({
    has: page.locator(".dom", { hasText: new RegExp(`^${name.replace(/\./g, "\\.")}$`) }),
  });
const popover = (page: Page) => page.locator(".bp-editor");

async function openBlock(page: Page, name: string) {
  await row(page, name).getByRole("button", { name: "Блокировать" }).click();
  await expect(popover(page)).toBeVisible();
  return popover(page);
}

async function pickDevice(page: Page, label: string) {
  await page.locator(".stats-device [data-select-trigger]").click();
  const option = page.getByRole("option", { name: label, exact: true });
  await option.waitFor({ state: "attached" });
  await option.click();
}

async function groupsTab(page: Page) {
  await page.getByRole("tab", { name: "Группы" }).click();
}

const ruleOf = (page: Page, groupId: string) =>
  page.locator(`.rule[data-group-uuid="${groupId}"] input.pattern-input`);

test.describe("DNS stats", () => {
  // Catches rows counted in the browser, a lost total, or the domains count not in the tab label.
  test("the table shows the day's rows from the daemon", async ({ page }) => {
    const daemon = await setup(page, [EXAMPLE_GROUP, ADS_GROUP]);
    await expect(page.locator(".stats-row .dom")).toHaveText([
      "googlevideo.com",
      "ya.ru",
      "ads.doubleclick.net",
      "graph.facebook.com",
      "github.com",
      "low.example.org",
      "my printer.local",
    ]);
    await expect(page.locator(".stats-sum")).toHaveText(
      "за 24 ч: 529 запросов · 7 доменов · заблокировано 16,6 %",
    );
    await expect(page.getByRole("tab", { name: /Статистика запросов/ })).toContainText("7");
    const graph = row(page, "graph.facebook.com");
    await expect(graph.getByRole("button", { name: "Блокировать" })).toBeVisible();
    await expect(graph.locator(".already")).toHaveCount(0);
    const printer = row(page, "my printer.local");
    await expect(printer.getByRole("button")).toHaveText(["my printer.local"]);
    await expect(printer.locator(".already")).toHaveCount(0);
    const ya = row(page, "ya.ru");
    await expect(ya.locator(".total")).toHaveText("115");
    await expect(ya.locator(".dev .dn")).toHaveText(["Phone", "Desktop"]);
    await expect(ya.locator(".dev .da")).toHaveText(["192.168.1.7", "192.168.1.42"]);
    await expect(ya.locator(".last")).toHaveText("только что");
    await expect(row(page, "googlevideo.com").locator(".more")).toHaveText("и ещё 1");
    await expect(row(page, "graph.facebook.com").locator(".last")).toHaveText("18 мин назад");
    await expect(row(page, "low.example.org").locator(".last")).toHaveText("2 ч назад");
    await expect(row(page, "low.example.org").locator(".dev .dn")).toHaveText(["192.168.1.8"]);
    const ads = row(page, "ads.doubleclick.net");
    await expect(ads.locator(".pct")).toHaveText("100 %");
    await expect(ads.locator(".already")).toHaveText("в «Ads»");
    await expect(ads.getByRole("button", { name: "Блокировать" })).toHaveCount(0);
    expect(daemon.stats[0].searchParams.get("arpa")).toBeNull();

    await page.getByRole("searchbox", { name: "домен" }).fill("GOO");
    await expect(page.locator(".stats-row .dom")).toHaveText(["googlevideo.com"]);
    expect(daemon.stats.at(-1)!.searchParams.get("q")).toBe("GOO");
  });

  // Catches reverse lookups shown by default, or the switch not reaching the daemon as arpa=1.
  test("service names are hidden until показать служебные is ticked", async ({ page }) => {
    const daemon = await setup(page, [ADS_GROUP]);
    await expect(row(page, "7.1.168.192.in-addr.arpa")).toHaveCount(0);
    await page.getByRole("button", { name: /^Фильтр/ }).click();
    const panel = page.locator(".jh-panel");
    await expect(panel.getByRole("checkbox", { name: "показать служебные" })).not.toBeChecked();
    await panel.getByText("показать служебные").click();
    await expect(panel.getByRole("checkbox", { name: "показать служебные" })).toBeChecked();
    await expect(row(page, "7.1.168.192.in-addr.arpa")).toBeVisible();
    await expect(page.locator(".stats-row .dom").first()).toHaveText("7.1.168.192.in-addr.arpa");
    expect(daemon.stats.at(-1)!.searchParams.get("arpa")).toBe("1");
    await expect(page.getByRole("button", { name: "Фильтр, активно: 1" })).toBeVisible();
  });

  // Catches a device's v6 left out of device=, or the narrowing done on the page instead of the daemon.
  test("the device select narrows the rows", async ({ page }) => {
    const daemon = await setup(page, [ADS_GROUP]);
    await pickDevice(page, "Phone");
    await expect(page.locator(".stats-row .dom")).toHaveText(["ya.ru", "googlevideo.com"]);
    expect(daemon.stats.at(-1)!.searchParams.get("device")).toBe("192.168.1.7,fd00::7");
    await expect(row(page, "ya.ru").locator(".total")).toHaveText("100");
    await expect(row(page, "ya.ru").locator(".dev .dn")).toHaveText(["Phone"]);
    await expect(page.locator(".stats-sum")).toContainText("141 запрос · 2 домена");

    await pickDevice(page, "все устройства");
    await expect(page.locator(".stats-row")).toHaveCount(7);
    expect(daemon.stats.at(-1)!.searchParams.get("device")).toBeNull();
  });

  // Catches the rule saved at once, put into the wrong group, typed namespace, or not marked unsaved.
  test("Блокировать with one block group adds an unsaved domain rule and the row says не сохранено", async ({
    page,
  }) => {
    const daemon = await setup(page, [EXAMPLE_GROUP, ADS_GROUP, OFF_GROUP, KIDS_GROUP]);
    const pop = await openBlock(page, "ya.ru");
    await expect(pop.locator(".bp-head")).toHaveText("Блокировать ya.ru");
    await expect(pop.locator(".bp-line")).toHaveText("в группу «Ads»");
    await expect(pop.getByRole("radio")).toHaveCount(0);
    await pop.getByRole("button", { name: "Добавить" }).click();
    await expect(pop).toHaveCount(0);

    const ya = row(page, "ya.ru");
    await expect(ya.locator(".already")).toHaveText("в «Ads»");
    await expect(ya.locator(".uns")).toHaveText("не сохранено");
    await expect(row(page, "github.com").locator(".uns")).toHaveCount(0);
    expect(daemon.puts).toHaveLength(0);

    await groupsTab(page);
    await expect(ruleOf(page, ADS.id).first()).toHaveValue("ya.ru");
    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const ads = daemon.puts[0].groups.find((g: any) => g.id === ADS.id);
    expect(ads.rules[0]).toMatchObject({ rule: "ya.ru", type: "domain", enable: true });
    expect(ads.rules).toHaveLength(2);
    expect(daemon.puts[0].groups.map((g: any) => g.id)).toEqual([
      EXAMPLE.id,
      ADS.id,
      OFF_GROUP.id,
      KIDS_GROUP.id,
    ]);

    await page.getByRole("tab", { name: "Журнал" }).click();
    await expect(row(page, "ya.ru").locator(".already")).toHaveText("в «Ads»");
    await expect(row(page, "ya.ru").locator(".uns")).toHaveCount(0);
  });

  // Catches a second block group ignored, or the pick not honoured.
  test("with several block groups the popover asks which", async ({ page }) => {
    const daemon = await setup(page, [ADS_GROUP, TRACKERS_GROUP, OFF_GROUP]);
    const pop = await openBlock(page, "github.com");
    await expect(pop.getByRole("radio")).toHaveCount(2);
    await expect(pop.getByRole("radio", { name: /Ads/ })).toHaveAttribute("aria-checked", "true");
    await expect(pop.getByRole("radio", { name: /Old block/ })).toHaveCount(0);
    await expect(pop.getByRole("radio", { name: /Ads/ })).toContainText("правил: 1");
    await pop.getByRole("radio", { name: /Trackers/ }).click();
    await pop.getByRole("button", { name: "Добавить" }).click();
    await expect(row(page, "github.com").locator(".already")).toHaveText("в «Trackers»");

    await groupsTab(page);
    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const byId = (id: string) => daemon.puts[0].groups.find((g: any) => g.id === id);
    expect(byId(TRACKERS_GROUP.id).rules.map((r: any) => r.rule)).toEqual(["github.com"]);
    expect(byId(ADS.id).rules.map((r: any) => r.rule)).toEqual(["doubleclick.net"]);
  });

  // Catches a disabled or device-scoped group taken for everyone, or the new group put last.
  test("with none it says a group Блокировка will be created", async ({ page }) => {
    const daemon = await setup(page, [EXAMPLE_GROUP, OFF_GROUP, KIDS_GROUP]);
    const pop = await openBlock(page, "github.com");
    await expect(pop.locator(".bp-line")).toHaveText("будет создана группа «Блокировка» (0.0.0.0)");
    await pop.getByRole("button", { name: "Добавить" }).click();
    await expect(row(page, "github.com").locator(".already")).toHaveText("в «Блокировка»");
    await expect(row(page, "github.com").locator(".uns")).toHaveText("не сохранено");

    await groupsTab(page);
    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const [first, ...rest] = daemon.puts[0].groups;
    expect(first).toMatchObject({
      name: "Блокировка",
      interface: "block",
      block: "null",
      enable: true,
      devices: { allow: [], deny: [] },
    });
    expect(first.rules.map((r: any) => [r.rule, r.type])).toEqual([["github.com", "domain"]]);
    expect(rest.map((g: any) => g.id)).toEqual([EXAMPLE.id, OFF_GROUP.id, KIDS_GROUP.id]);
  });

  // Catches "только для" missing, a group for everyone taken for one device, or a new group admitting all.
  test("with a device selected it offers только для <device> and finds or creates its group", async ({
    page,
  }) => {
    const daemon = await setup(page, [ADS_GROUP, KIDS_GROUP]);
    await pickDevice(page, "Phone");
    let pop = await openBlock(page, "googlevideo.com");
    await expect(pop.getByRole("radio", { name: "для всех" })).toHaveAttribute(
      "aria-checked",
      "true",
    );
    await expect(pop.locator(".bp-line")).toHaveText("в группу «Ads»");
    await pop.getByRole("radio", { name: "только для Phone" }).click();
    await expect(pop.locator(".bp-line")).toHaveText("в группу «Kids block»");
    await pop.getByRole("button", { name: "Добавить" }).click();
    await expect(row(page, "googlevideo.com").locator(".already")).toHaveText("в «Kids block»");
    await pickDevice(page, "все устройства");
    await expect(
      row(page, "googlevideo.com").getByRole("button", { name: "Блокировать" }),
    ).toBeVisible();
    await expect(row(page, "googlevideo.com").locator(".already")).toHaveCount(0);

    await pickDevice(page, "Desktop");
    pop = await openBlock(page, "github.com");
    await pop.getByRole("radio", { name: "только для Desktop" }).click();
    await expect(pop.locator(".bp-line")).toHaveText(
      "будет создана группа «Блокировка · Desktop» (0.0.0.0)",
    );
    await pop.getByRole("button", { name: "Добавить" }).click();
    await expect(row(page, "github.com").locator(".already")).toHaveText(
      "в «Блокировка · Desktop»",
    );

    await pickDevice(page, "192.168.1.8");
    pop = await openBlock(page, "low.example.org");
    await pop.getByRole("radio", { name: "только для 192.168.1.8" }).click();
    await pop.getByRole("button", { name: "Добавить" }).click();

    await groupsTab(page);
    await page.locator("#save-changes").click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const groups = daemon.puts[0].groups;
    expect(
      groups.map((g: any) => [g.name, g.devices.allow, g.rules.map((r: any) => r.rule)]),
    ).toEqual([
      ["Блокировка · 192.168.1.8", ["192.168.1.8"], ["low.example.org"]],
      ["Блокировка · Desktop", ["mac:aa:00:00:00:00:02"], ["github.com"]],
      ["Ads", [], ["doubleclick.net"]],
      ["Kids block", ["mac:aa:00:00:00:00:03"], ["googlevideo.com"]],
    ]);
  });

  // Catches the warning missing for an owner above the target, or shown for one below it.
  test("the warning names a routing group above the target", async ({ page }) => {
    await setup(page, [EXAMPLE_GROUP, ADS_GROUP, LOW_GROUP]);
    let pop = await openBlock(page, "graph.facebook.com");
    await expect(pop.locator(".bp-warn")).toHaveText(
      "сейчас этим именем владеет «Example Group» выше — блокировка не сработает, пока она выше",
    );
    await page.keyboard.press("Escape");
    await expect(pop).toHaveCount(0);
    pop = await openBlock(page, "low.example.org");
    await expect(pop.locator(".bp-line")).toHaveText("в группу «Ads»");
    await expect(pop.locator(".bp-warn")).toHaveCount(0);
    await page.keyboard.press("Escape");
    await expect(row(page, "low.example.org").locator(".above")).toHaveCount(0);

    pop = await openBlock(page, "graph.facebook.com");
    await pop.getByRole("button", { name: "Добавить" }).click();
    const graph = row(page, "graph.facebook.com");
    await expect(graph.locator(".already")).toHaveText("в «Ads»");
    await expect(graph.locator(".uns")).toHaveText("не сохранено");
    await expect(graph.locator(".above")).toHaveText("«Example Group» выше");
  });

  // Catches a saved block claimed while a routing group above still owns the name.
  test("a saved block under a routing group above keeps the button and the warning", async ({
    page,
  }) => {
    const held = {
      ...ADS_GROUP,
      rules: [
        { id: "ad5ad5f0", enable: true, rule: "graph.facebook.com", type: "domain" },
        ...ADS_GROUP.rules,
      ],
    };
    await setup(page, [EXAMPLE_GROUP, held]);
    await expect(row(page, "github.com").locator(".already")).toHaveCount(0);
    const graph = row(page, "graph.facebook.com");
    await expect(graph.locator(".already")).toHaveCount(0);
    const pop = await openBlock(page, "graph.facebook.com");
    await expect(pop.locator(".bp-warn")).toContainText("«Example Group»");
    await page.keyboard.press("Escape");
    await expect(graph.locator(".above")).toHaveText("«Example Group» выше");
    await expect(row(page, "github.com").locator(".above")).toHaveCount(0);
  });

  // Catches the latest asker's device-scoped block group claimed for every device.
  test("a device group owning the name does not claim it for all devices", async ({ page }) => {
    const kids = { id: KIDS_GROUP.id, name: "Kids block", interface: "block", blocked: true };
    await setup(page, [ADS_GROUP, KIDS_GROUP], [key("tiktok.com", "192.168.1.7", 5, 5, 40, kids)]);
    const tiktok = row(page, "tiktok.com");
    await expect(tiktok.locator(".already")).toHaveCount(0);
    const pop = await openBlock(page, "tiktok.com");
    await expect(pop.locator(".bp-line")).toHaveText("в группу «Ads»");
    await page.keyboard.press("Escape");
    await pickDevice(page, "Phone");
    await expect(row(page, "tiktok.com").locator(".already")).toHaveText("в «Kids block»");
  });

  // Catches an address no host claims dropped from the select when the sub-tab changes.
  test("a chosen unclaimed address survives a sub-tab switch", async ({ page }) => {
    const daemon = await setup(page, [ADS_GROUP]);
    await pickDevice(page, "192.168.1.99");
    await expect(page.locator(".stats-row .dom")).toHaveText(["github.com"]);
    await page.getByRole("tab", { name: /События/ }).click();
    await page.getByRole("tab", { name: /Статистика запросов/ }).click();
    await expect(page.locator(".stats-device [data-select-trigger]")).toContainText("192.168.1.99");
    await expect(page.locator(".stats-row .dom")).toHaveText(["github.com"]);
    expect(daemon.stats.at(-1)!.searchParams.get("device")).toBe("192.168.1.99");
  });

  // Catches the Events pause or clear leaking onto the stats tab, whose counters are the daemon's.
  test("the tab shows no pause and no clear", async ({ page }) => {
    await setup(page, [ADS_GROUP]);
    await expect(page.getByRole("button", { name: "Пауза" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Очистить вид" })).toHaveCount(0);
    await page.getByRole("tab", { name: /События/ }).click();
    await expect(page.getByRole("button", { name: "Пауза" })).toBeVisible();
  });

  // Catches the stats polled while another tab is open, or never refreshed while open.
  test("the stats refresh every 10 s only while the tab is open", async ({ page }) => {
    await page.clock.install();
    const daemon = await setup(page, [ADS_GROUP]);
    const asked = daemon.stats.length;
    await page.clock.runFor(10_500);
    await expect.poll(() => daemon.stats.length).toBe(asked + 1);
    await page.getByRole("tab", { name: "Группы" }).click();
    await page.clock.runFor(30_000);
    await page.waitForTimeout(200);
    expect(daemon.stats.length).toBe(asked + 1);
    await page.getByRole("tab", { name: "Журнал" }).click();
    await expect.poll(() => daemon.stats.length).toBe(asked + 2);
    await page.getByRole("tab", { name: /События/ }).click();
    await page.clock.runFor(30_000);
    await page.waitForTimeout(200);
    expect(daemon.stats.length).toBe(asked + 2);
  });
});
