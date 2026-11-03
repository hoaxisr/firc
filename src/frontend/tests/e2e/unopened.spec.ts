import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

const NOW = Math.floor(Date.now() / 1000);

const HOSTS = [
  host("aa:00:00:00:00:51", "iPad", "192.168.1.51"),
  host("aa:00:00:00:00:42", "Desktop", "192.168.1.42"),
  host("aa:00:00:00:00:07", "Phone", "192.168.1.7"),
  host("aa:00:00:00:00:05", "Living room TV", "192.168.1.5"),
];

function host(mac: string, name: string, ip: string) {
  return { mac, name, ip, ip6: [], active: true, registered: true, policy: "" };
}

function candidate(domain: string, hostName: string, why: string, extra = {}) {
  return {
    domain,
    host: hostName,
    why,
    fails: 3,
    clients: ["192.168.1.51"],
    lastAt: NOW - 120,
    state: "candidate",
    notes: 0,
    ...extra,
  };
}

function address(addr: string, extra = {}) {
  return {
    address: addr,
    proto: "tcp",
    port: 443,
    name: "",
    ptr: "",
    ptrState: "none",
    outcome: "failed",
    how: "",
    group: "",
    why: "no-answer",
    fails: 4,
    clients: ["192.168.1.5"],
    firstAt: NOW - 900,
    lastAt: NOW - 120,
    groups: ["b10c4ed0"],
    ...extra,
  };
}

type ProbeResult = {
  host: string;
  verdict: string;
  why: string;
  bytes: number;
  at: number;
  error: string;
};

type Fake = {
  mode: string;
  candidates: ReturnType<typeof candidate>[];
  addresses: ReturnType<typeof address>[];
  calls: string[];
  adds: { search: string; body: unknown }[];
  dismissBody?: unknown;
  running?: string | null;
  results?: ProbeResult[];
  probeFail?: string;
  queueOnly?: boolean;
  off?: boolean;
  wanWarning?: string;
  ambiguousDay?: number;
};

function state(fake: Fake) {
  return {
    enabled: !fake.off,
    running: !fake.off,
    mode: fake.mode,
    group: "b10c4ed0",
    failures: 40,
    failuresDay: 23,
    ambiguousDay: fake.ambiguousDay ?? 0,
    ...(fake.wanWarning ? { wanWarning: fake.wanWarning } : {}),
    listed: fake.candidates.length,
    addedHour: 2,
    checking: false,
    checkedAt: 0,
    switchedOff: 0,
    switchedOn: 0,
    addresses: fake.addresses,
    candidates: fake.candidates,
    probes: {
      usedHour: 4,
      queued: 2,
      running: fake.running ?? null,
      results: fake.results ?? [
        {
          host: "cdn.some-vps.de",
          verdict: "blocked",
          why: "freeze",
          bytes: 15360,
          at: NOW - 600,
          error: "",
        },
      ],
    },
  };
}

const GROUP = {
  id: "b10c4ed0",
  name: "Blocked",
  interface: "nwg0",
  enable: true,
  devices: { allow: [], deny: [] },
  rules: [{ id: "ab12cd34", enable: true, rule: "rutracker.org", type: "namespace" }],
  resolve: { tunnel: true, server: "" },
  live: true,
};

async function shell(page: Page, fake: Fake) {
  await signedIn(page);
  await page.route("**/groups?with_rules=true", (route) =>
    route.fulfill({ json: { groups: [GROUP] } }),
  );
  await page.route(/\/groups(\?.*)?$/, (route) => route.fulfill({ json: { groups: [GROUP] } }));
  await page.route(/\/groups\/b10c4ed0\/rules(\?.*)?$/, (route) => {
    const req = route.request();
    fake.adds.push({ search: new URL(req.url()).search, body: req.postDataJSON() });
    return route.fulfill({ json: { id: "ee00ee00" } });
  });
  await page.route(/\/groups\/b10c4ed0\/rules\/ab12cd34/, (route) => {
    fake.calls.push(`${route.request().method()} ${new URL(route.request().url()).pathname}`);
    return route.fulfill({ json: {} });
  });
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: HOSTS } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route(/\/system\/capture(\?.*)?$/, (route) =>
    route.fulfill({ json: { running: false } }),
  );
  await page.route(/\/system\/events(\?.*)?$/, (route) =>
    route.fulfill({ json: { events: [], next: 0, dropped: 0 } }),
  );
  await page.route(/\/system\/settings(\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        settings: { "app.dnsProxy.unmatchedTtl": 60, "app.autolist.recheck": false },
        classes: {},
        pendingRestart: [],
        boot: "b",
        restarting: false,
        webUi: { port: 666, movedFrom: 0, lanAddress: "" },
      },
    }),
  );
  await page.route(/\/system\/autolist(\/.*)?$/, (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    fake.calls.push(`${req.method()} ${path}`);
    if (req.method() === "POST" && path.endsWith("/probe")) {
      if (fake.probeFail) {
        return route.fulfill({ status: 429, json: { error: fake.probeFail } });
      }
      if (!fake.queueOnly) fake.running = req.postDataJSON().host;
      return route.fulfill({ status: 202, json: state(fake) });
    }
    const d = path.match(/addresses\/([^/]+)\/dismiss$/);
    if (d) {
      const addr = decodeURIComponent(d[1]);
      fake.dismissBody = req.postDataJSON();
      fake.addresses = fake.addresses.filter((a) => a.address !== addr);
      return route.fulfill({ json: {} });
    }
    const m = path.match(/candidates\/([^/]+)\/(add|dismiss)$/);
    if (m) {
      const domain = decodeURIComponent(m[1]);
      if (m[2] === "dismiss") {
        fake.candidates = fake.candidates.filter((c) => c.domain !== domain);
      } else {
        fake.candidates = fake.candidates.map((c) =>
          c.domain === domain ? { ...c, state: "added" } : c,
        );
      }
    }
    return route.fulfill({ json: state(fake) });
  });
}

function a1(): Fake {
  return {
    mode: "candidates",
    calls: [],
    adds: [],
    addresses: [
      address("172.64.150.28", { name: "chat.openai.com" }),
      address("34.107.243.93", {
        why: "no-connect",
        ptr: "93.243.107.34.bc.googleusercontent.com",
        ptrState: "name",
        lastAt: NOW - 400,
      }),
      address("2606:4700::6810:84e5", { ptrState: "pending", lastAt: NOW - 800 }),
    ],
    candidates: [
      candidate("rutracker.org", "rutracker.org", "no-answer"),
      candidate("linkedin.com", "www.linkedin.com", "reset", {
        fails: 5,
        clients: ["192.168.1.42", "192.168.1.7"],
        lastAt: NOW - 5,
      }),
      candidate("some-vps.de", "cdn.some-vps.de", "freeze", {
        fails: 0,
        clients: ["192.168.1.42"],
        lastAt: NOW - 360,
      }),
      candidate("medium.com", "medium.com", "freeze", {
        fails: 0,
        state: "checking",
        notes: 2,
        clients: ["192.168.1.7"],
        lastAt: NOW - 60,
      }),
    ],
  };
}

async function open(page: Page) {
  await page.goto("/journal/unopened");
  await expect(page.getByRole("tab", { name: /Not opening/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
}

test("the tab lists each candidate with its reason, failures and device name", async ({ page }) => {
  await shell(page, a1());
  await open(page);

  await expect(page.getByRole("tab", { name: /Not opening/ })).toContainText("4");
  const rows = page.locator("[data-domain]");
  await expect(rows).toHaveCount(4);
  const first = rows.filter({ hasText: "rutracker.org" });
  await expect(first).toContainText("no answer to ClientHello");
  await expect(first).toContainText("iPad");
  await expect(first).toContainText("192.168.1.51");
  await expect(rows.filter({ hasText: "linkedin.com" })).toContainText(
    "reset before the server answered",
  );
  await expect(rows.filter({ hasText: "some-vps.de" })).toContainText("freeze at 15 KB");
  await expect(rows.filter({ hasText: "some-vps.de" })).toContainText(
    "confirmed by the router check",
  );
  await expect(rows.filter({ hasText: "medium.com" })).toContainText("checking by the router…");
});

test("an unanswered-SYN candidate wears the no-answer colour, not the grey of a waiting row", async ({
  page,
}) => {
  const fake = a1();
  fake.candidates.push(candidate("instagram.com", "www.instagram.com", "no-connect"));
  await shell(page, fake);
  await open(page);

  const pill = page.locator("[data-domain]", { hasText: "instagram.com" }).locator(".pill");
  await expect(pill).toHaveClass(/\bdrop\b/);
  await expect(
    page.locator("[data-domain]", { hasText: "rutracker.org" }).locator(".pill"),
  ).toHaveClass(/\bdrop\b/);
});

test("bypass addresses show as a table", async ({ page }) => {
  await shell(page, a1());
  await open(page);
  const rows = page.locator("[data-address]");
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0)).toContainText("172.64.150.28");
  await expect(rows.nth(0)).toContainText("chat.openai.com");
  await expect(rows.nth(0)).toContainText("tcp/443");
  await expect(rows.nth(0)).toContainText("PTR: —");
  await expect(rows.nth(0)).toContainText("Living room TV");
  await expect(rows.nth(1)).toContainText("34.107.243.93");
  await expect(rows.nth(1)).toContainText("PTR: 93.243.107.34.bc.googleusercontent.com");
  await expect(rows.nth(2)).toContainText("PTR: …");
  await expect(page.getByText("Addresses past firc")).toBeVisible();
  await expect(page.locator(".note")).toHaveCount(0);
});

test("the addresses table is absent when there are none", async ({ page }) => {
  const fake = a1();
  fake.addresses = [];
  await shell(page, fake);
  await open(page);
  await expect(page.locator("[data-domain]")).toHaveCount(4);
  await expect(page.getByText("Addresses past firc")).toHaveCount(0);
});

test("to group adds the exact address", async ({ page }) => {
  const fake = a1();
  await shell(page, fake);
  await open(page);
  const row = page.locator("[data-address='34.107.243.93']");
  await row.getByRole("button", { name: "To group" }).click();
  await page.getByRole("menuitem", { name: "Blocked" }).click();
  await expect.poll(() => fake.adds.length).toBe(1);
  expect(fake.adds[0].search).toBe("?save=true");
  expect(fake.adds[0].body).toEqual({
    type: "subnet",
    rule: "34.107.243.93/32",
    enable: true,
    proto: "tcp",
    ports: "443",
    comment: "93.243.107.34.bc.googleusercontent.com",
  });
  await expect(page.getByText("34.107.243.93 added to «Blocked»")).toBeVisible();
});

// Catches the groups tab stuck on its loading placeholder after an address was added from here.
test("after adding an address the groups tab shows its groups", async ({ page }) => {
  const fake = a1();
  await shell(page, fake);
  await open(page);
  const row = page.locator("[data-address='34.107.243.93']");
  await row.getByRole("button", { name: "To group" }).click();
  await page.getByRole("menuitem", { name: "Blocked" }).click();
  await expect(page.getByText("34.107.243.93 added to «Blocked»")).toBeVisible();
  await page.getByRole("tab", { name: "Groups" }).click();
  await expect(page.getByText("Loading groups...")).toHaveCount(0, { timeout: 5000 });
  await expect(page.getByText("Blocked").first()).toBeVisible();
});

test("an ipv6 row adds a subnet6 rule", async ({ page }) => {
  const fake = a1();
  await shell(page, fake);
  await open(page);
  await page
    .locator("[data-address='2606:4700::6810:84e5']")
    .getByRole("button", { name: "To group" })
    .click();
  await page.getByRole("menuitem", { name: "Blocked" }).click();
  await expect.poll(() => fake.adds.length).toBe(1);
  expect(fake.adds[0].body).toMatchObject({ type: "subnet6", rule: "2606:4700::6810:84e5/128" });
});

test("a row with no covering group has no menu", async ({ page }) => {
  const fake = a1();
  fake.addresses = [address("172.64.150.28", { groups: [] })];
  await shell(page, fake);
  await open(page);
  await expect(page.locator("[data-address]")).toHaveCount(1);
  await expect(page.getByRole("button", { name: "To group" })).toHaveCount(0);
});

test("a routed address links to its rule", async ({ page }) => {
  const fake = a1();
  await shell(page, fake);
  const routed = {
    ...GROUP,
    rules: [
      ...GROUP.rules,
      { id: "cd34ef56", enable: true, rule: "34.107.243.0/24", type: "subnet" },
    ],
  };
  await page.route("**/groups?with_rules=true", (route) =>
    route.fulfill({ json: { groups: [routed] } }),
  );
  await page.route(/\/groups(\?.*)?$/, (route) => route.fulfill({ json: { groups: [routed] } }));
  await open(page);
  const row = page.locator("[data-address='34.107.243.93']");
  await expect(row.getByRole("button", { name: "To the rule" })).toBeVisible();
  await expect(row.getByRole("button", { name: "To group" })).toHaveCount(0);
  await expect(
    page.locator("[data-address='172.64.150.28']").getByRole("button", { name: "To group" }),
  ).toBeVisible();
});

test("dismiss hides an address", async ({ page }) => {
  const fake = a1();
  await shell(page, fake);
  await open(page);
  await page
    .locator("[data-address='34.107.243.93']")
    .getByRole("button", { name: "Dismiss for a day" })
    .click();
  await expect(page.locator("[data-address]")).toHaveCount(2);
  await expect(page.locator("[data-address='34.107.243.93']")).toHaveCount(0);
  await expect(page.locator("[data-domain]")).toHaveCount(4);
  await expect(page.getByText("Automatic adding is off.")).toHaveCount(0);
  const post = fake.calls.indexOf("POST /api/v1/system/autolist/addresses/34.107.243.93/dismiss");
  expect(post).toBeGreaterThanOrEqual(0);
  expect(fake.calls.slice(post + 1)).toContain("GET /api/v1/system/autolist");
  expect(fake.dismissBody).toEqual({ proto: "tcp", port: 443 });
});

test("dismissing an ipv6 address sends it percent-encoded with its proto and port", async ({
  page,
}) => {
  const fake = a1();
  await shell(page, fake);
  await open(page);
  await page
    .locator("[data-address='2606:4700::6810:84e5']")
    .getByRole("button", { name: "Dismiss for a day" })
    .click();
  await expect(page.locator("[data-address='2606:4700::6810:84e5']")).toHaveCount(0);
  expect(fake.calls).toContain(
    "POST /api/v1/system/autolist/addresses/2606%3A4700%3A%3A6810%3A84e5/dismiss",
  );
  expect(fake.dismissBody).toEqual({ proto: "tcp", port: 443 });
});

test("the added rule's comment is the name before the PTR, empty without both", async ({
  page,
}) => {
  const fake = a1();
  fake.addresses = [
    address("2606:4700::6810:84e5", {
      name: "chatgpt.com",
      ptr: "edge.example.net",
      ptrState: "name",
    }),
    address("172.64.150.28"),
  ];
  await shell(page, fake);
  await open(page);
  await page
    .locator("[data-address='2606:4700::6810:84e5']")
    .getByRole("button", { name: "To group" })
    .click();
  await page.getByRole("menuitem", { name: "Blocked" }).click();
  await expect.poll(() => fake.adds.length).toBe(1);
  expect(fake.adds[0].body).toMatchObject({ comment: "chatgpt.com" });
  await page
    .locator("[data-address='172.64.150.28']")
    .getByRole("button", { name: "To group" })
    .click();
  await page.getByRole("menuitem", { name: "Blocked" }).click();
  await expect.poll(() => fake.adds.length).toBe(2);
  expect(fake.adds[1].body).toMatchObject({ rule: "172.64.150.28/32", comment: "" });
});

test("with no candidates but addresses the empty strip stays away", async ({ page }) => {
  const fake = a1();
  fake.candidates = [];
  await shell(page, fake);
  await open(page);
  await expect(page.locator("[data-address]")).toHaveCount(3);
  await expect(page.getByText(/^No failures yet\./)).toHaveCount(0);
  await expect(page.locator("[data-domain]")).toHaveCount(0);
  await expect(page.getByText("Domain", { exact: true })).toHaveCount(0);
});

test("with no candidates and no addresses the empty strip shows", async ({ page }) => {
  const fake = a1();
  fake.candidates = [];
  fake.addresses = [];
  await shell(page, fake);
  await open(page);
  await expect(page.getByText(/^No failures yet\./)).toBeVisible();
});

test("adding a candidate moves its row to added and says when it will open", async ({ page }) => {
  const fake = a1();
  await shell(page, fake);
  await open(page);

  const row = page.locator("[data-domain]", { hasText: "rutracker.org" });
  await row.getByRole("button", { name: "To «Blocked»" }).click();

  await expect(row).toHaveAttribute("data-state", "added");
  await expect(
    page.getByText("rutracker.org added to «Blocked». It will open within 60 s"),
  ).toBeVisible();
  expect(fake.calls).toContain("POST /api/v1/system/autolist/candidates/rutracker.org/add");
});

test("dismissing a candidate removes its row", async ({ page }) => {
  const fake = a1();
  await shell(page, fake);
  await open(page);

  const row = page.locator("[data-domain]", { hasText: "linkedin.com" });
  await row.getByRole("button", { name: "Dismiss for a day" }).click();

  await expect(page.locator("[data-domain]")).toHaveCount(3);
  await expect(page.locator("[data-domain]", { hasText: "linkedin.com" })).toHaveCount(0);
  expect(fake.calls).toContain("POST /api/v1/system/autolist/candidates/linkedin.com/dismiss");
});

test("Check asks the router to probe the host that failed", async ({ page }) => {
  const fake = a1();
  await shell(page, fake);
  await open(page);

  await page
    .locator(".row", { hasText: "linkedin.com" })
    .getByRole("button", { name: "Check" })
    .click();
  await expect.poll(() => fake.calls).toContain("POST /api/v1/system/autolist/probe");
});

test("in add mode Remove deletes the rule and then dismisses the candidate", async ({ page }) => {
  const fake = a1();
  fake.mode = "add";
  fake.candidates = [
    candidate("rutracker.org", "rutracker.org", "no-answer", { state: "added" }),
    candidate("example-news.com", "www.example-news.com", "reset", { state: "off" }),
  ];
  await shell(page, fake);
  await open(page);

  await expect(page.locator("[data-domain]")).toHaveCount(2);
  await expect(page.locator("[data-domain]", { hasText: "example-news.com" })).toContainText(
    "switched off by the recheck",
  );
  await page
    .locator(".row", { hasText: "rutracker.org" })
    .getByRole("button", { name: "Take out of the group" })
    .click();

  await expect(page.locator("[data-domain]", { hasText: "rutracker.org" })).toHaveCount(0);
  const del = fake.calls.indexOf("DELETE /api/v1/groups/b10c4ed0/rules/ab12cd34");
  const dismiss = fake.calls.indexOf(
    "POST /api/v1/system/autolist/candidates/rutracker.org/dismiss",
  );
  expect(del).toBeGreaterThanOrEqual(0);
  expect(dismiss).toBeGreaterThan(del);
});

test("To the rule opens the groups tab searching for the domain", async ({ page }) => {
  const fake = a1();
  fake.mode = "add";
  fake.candidates = [candidate("rutracker.org", "rutracker.org", "no-answer", { state: "added" })];
  await shell(page, fake);
  await open(page);

  await page.getByRole("button", { name: "To the rule" }).click();
  await expect(page.getByRole("tab", { name: "Groups" })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator(".group-controls-search input")).toHaveValue("rutracker.org");
});

test("at 390 px each candidate is a card without the column header", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await shell(page, a1());
  await open(page);

  await expect(page.locator("[data-domain]")).toHaveCount(4);
  await expect(page.locator(".head")).toHaveCount(2);
  await expect(page.locator(".head").first()).toBeHidden();
  await expect(page.locator(".head").last()).toBeHidden();
  const addr = page.locator("[data-address]").first();
  await expect(addr.locator(".devs")).toBeHidden();
  await expect(addr.locator(".meta")).toHaveText("tcp/443 · 4 failures · Living room TV");
  expect((await addr.boundingBox())!.width).toBeLessThanOrEqual(390);
  const row = page.locator("[data-domain]", { hasText: "rutracker.org" });
  await expect(row.locator(".meta")).toBeVisible();
  await expect(row.locator(".meta")).toContainText("3 failures");
  await expect(row.locator(".devs")).toBeHidden();
  const box = await row.boundingBox();
  expect(box!.width).toBeLessThanOrEqual(390);
});

test("when automatic adding is off the tab says so and offers the setting", async ({ page }) => {
  const fake = a1();
  await shell(page, fake);
  await page.route(/\/system\/autolist$/, (route) =>
    route.fulfill({ json: { ...state(fake), enabled: false, running: false, candidates: [] } }),
  );
  await open(page);

  await expect(page.getByText("Automatic adding is off.")).toBeVisible();
  await expect(page.locator("[data-domain]")).toHaveCount(0);
  await page.getByRole("button", { name: "Turn on in settings" }).click();
  await expect(page.getByRole("tab", { name: "Settings" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
});

const STATS_NOW = NOW - 7200;

function statsRow(name: string, queries: number, address: string, owner: unknown = null) {
  return {
    name,
    queries,
    blocked: owner ? queries : 0,
    last: STATS_NOW - 30,
    owner,
    clients: [{ address, queries }],
    clientsTotal: 1,
  };
}

const ADS = { id: "ad5ad5ad", name: "Ads", interface: "block", blocked: true };

function statsFake(): Fake {
  return {
    mode: "candidates",
    calls: [],
    adds: [],
    addresses: [],
    running: null,
    results: [],
    candidates: [candidate("some-vps.de", "cdn.some-vps.de", "freeze", { fails: 0 })],
  };
}

async function statsShell(page: Page, fake: Fake) {
  await shell(page, fake);
  await page.route(/\/system\/dnsstats(\?.*)?$/, (route) => {
    const rows = [
      statsRow("cdn.some-vps.de", 33, "192.168.1.42"),
      statsRow("api.telegram.org", 105, "192.168.1.7"),
      statsRow("tiny-api.io", 12, "192.168.1.51"),
      statsRow("broken.example", 9, "192.168.1.51"),
      statsRow("ads.doubleclick.net", 96, "192.168.1.51", ADS),
    ];
    return route.fulfill({
      json: {
        enabled: true,
        window: 86400,
        now: STATS_NOW,
        since: STATS_NOW - 3 * 86400,
        queries: 255,
        blocked: 96,
        domains: rows.length,
        rows,
        matched: rows.length,
        offset: 0,
      },
    });
  });
}

function finish(
  fake: Fake,
  hostName: string,
  verdict: string,
  why: string,
  bytes: number,
  error = "",
) {
  fake.running = null;
  fake.results = [{ host: hostName, verdict, why, bytes, at: NOW, error }];
}

async function openStats(page: Page) {
  await page.goto("/journal/stats");
  await expect(page.locator(".stats-row")).toHaveCount(5);
}

test("Won't open shows only while the list runs and only for a domain in no group", async ({
  page,
}) => {
  const fake = statsFake();
  await statsShell(page, fake);
  await openStats(page);

  await expect(page.getByRole("button", { name: "Won't open" })).toHaveCount(4);
  await expect(
    page.locator(".stats-row", { hasText: "ads.doubleclick.net" }).getByRole("button", {
      name: "Won't open",
    }),
  ).toHaveCount(0);
});

test("Won't open is absent while the automatic list is off", async ({ page }) => {
  const fake = statsFake();
  fake.off = true;
  await statsShell(page, fake);
  await openStats(page);

  await expect(page.getByRole("button", { name: "Block" }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Won't open" })).toHaveCount(0);
});

test("a blocked verdict names the freeze and turns the button into the add", async ({ page }) => {
  const fake = statsFake();
  await statsShell(page, fake);
  await openStats(page);

  const row = page.locator(".stats-row", { hasText: "cdn.some-vps.de" });
  await row.getByRole("button", { name: "Won't open" }).click();

  await expect(row).toContainText("the router is checking the site directly…");
  await expect(row.locator(".spin")).toBeVisible();
  await expect(row.getByRole("button", { name: "Won't open" })).toBeDisabled();
  expect(fake.calls).toContain("POST /api/v1/system/autolist/probe");

  finish(fake, "cdn.some-vps.de", "blocked", "freeze", 15360);
  await expect(row).toContainText("blocked: freeze at 15 KB → in the «Not opening» list");
  await expect(row.locator(".spin")).toHaveCount(0);

  await row.getByRole("button", { name: "To «Blocked»" }).click();
  await expect
    .poll(() => fake.calls)
    .toContain("POST /api/v1/system/autolist/candidates/some-vps.de/add");
  await expect(row.getByRole("button", { name: "To «Blocked»" })).toHaveCount(0);
  await expect(row.getByRole("button", { name: "Won't open" })).toHaveCount(0);
});

test("an open verdict says the site opens directly and rounds the answer to KB", async ({
  page,
}) => {
  const fake = statsFake();
  await statsShell(page, fake);
  await openStats(page);

  const row = page.locator(".stats-row", { hasText: "api.telegram.org" });
  await row.getByRole("button", { name: "Won't open" }).click();
  finish(fake, "api.telegram.org", "open", "", 65536 + 600);

  await expect(row).toContainText("opens directly (answer 65 KB) — not a block");
  await expect(row.getByRole("button", { name: "Won't open" })).toBeEnabled();
});

test("a short verdict says a freeze cannot be checked that way", async ({ page }) => {
  const fake = statsFake();
  await statsShell(page, fake);
  await openStats(page);

  const row = page.locator(".stats-row", { hasText: "tiny-api.io" });
  await row.getByRole("button", { name: "Won't open" }).click();
  finish(fake, "tiny-api.io", "short", "", 3072);

  await expect(row).toContainText(
    "opened with a short answer (3 KB): a freeze cannot be checked this way",
  );
});

test("an unknown verdict shows the error", async ({ page }) => {
  const fake = statsFake();
  await statsShell(page, fake);
  await openStats(page);

  const row = page.locator(".stats-row", { hasText: "broken.example" });
  await row.getByRole("button", { name: "Won't open" }).click();
  finish(fake, "broken.example", "unknown", "", 0, "no route to host");

  await expect(row).toContainText("could not check: no route to host");
});

test("a refused probe shows the route's message and no spinner stays", async ({ page }) => {
  const fake = statsFake();
  fake.probeFail = "the hourly limit of router checks is used up";
  await statsShell(page, fake);
  await openStats(page);

  const row = page.locator(".stats-row", { hasText: "tiny-api.io" });
  await row.getByRole("button", { name: "Won't open" }).click();

  await expect(page.getByText("the hourly limit of router checks is used up")).toBeVisible();
  await expect(row.locator(".spin")).toHaveCount(0);
  await expect(row.getByRole("button", { name: "Won't open" })).toBeEnabled();
});

test("at 390 px the verdict sits in the card without overflowing", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const fake = statsFake();
  await statsShell(page, fake);
  await openStats(page);

  const row = page.locator(".stats-row", { hasText: "cdn.some-vps.de" });
  await row.getByRole("button", { name: "Won't open" }).click();
  finish(fake, "cdn.some-vps.de", "blocked", "freeze", 15360);

  await expect(row).toContainText("blocked: freeze at 15 KB");
  const box = await row.boundingBox();
  expect(box!.width).toBeLessThanOrEqual(390);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});

test("a result that ages out leaves no spinner", async ({ page }) => {
  const fake = statsFake();
  await statsShell(page, fake);
  await openStats(page);

  const row = page.locator(".stats-row", { hasText: "tiny-api.io" });
  await row.getByRole("button", { name: "Won't open" }).click();
  finish(fake, "tiny-api.io", "short", "", 3072);
  await expect(row).toContainText("opened with a short answer (3 KB)");

  fake.results = [];
  await expect(row).not.toContainText("opened with a short answer", { timeout: 15000 });
  await expect(row.locator(".spin")).toHaveCount(0);
  await expect(row.getByRole("button", { name: "Won't open" })).toBeEnabled();
});

test("a re-probe shows the spinner at once", async ({ page }) => {
  const fake = statsFake();
  fake.queueOnly = true;
  fake.results = [
    { host: "tiny-api.io", verdict: "short", why: "", bytes: 3072, at: NOW - 600, error: "" },
  ];
  await statsShell(page, fake);
  await openStats(page);

  const row = page.locator(".stats-row", { hasText: "tiny-api.io" });
  await expect(row).toContainText("opened with a short answer (3 KB)");
  await row.getByRole("button", { name: "Won't open" }).click();

  await expect(row.locator(".spin")).toBeVisible();
  await expect(row.getByRole("button", { name: "Won't open" })).toBeDisabled();
  expect(fake.calls.filter((c) => c.endsWith("/probe"))).toHaveLength(1);

  fake.results = [
    { host: "tiny-api.io", verdict: "open", why: "", bytes: 65536, at: NOW, error: "" },
  ];
  await expect(row).toContainText("opens directly (answer 64 KB)");
  await expect(row.locator(".spin")).toHaveCount(0);
  await expect(row.getByRole("button", { name: "Won't open" })).toBeEnabled();
});

test("why the list is not running follows a translated lead", async ({ page }) => {
  const fake = a1();
  await page.addInitScript(() => {
    localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
  });
  await shell(page, fake);
  await page.route(/\/system\/autolist$/, (route) =>
    route.fulfill({
      json: {
        ...state(fake),
        running: false,
        whyOff: "the group blocks by DNS: nothing to route its names into",
      },
    }),
  );
  await page.goto("/journal/unopened");
  await expect(page.locator(".warn")).toHaveText(
    "Не запущено: the group blocks by DNS: nothing to route its names into",
  );
});

test("a WAN check without a route and ambiguous flows show in the strip", async ({ page }) => {
  const fake = a1();
  fake.wanWarning = "the check interface has no route: the WAN check cannot pass";
  fake.ambiguousDay = 3;
  await shell(page, fake);
  await open(page);
  const strip = page.getByTestId("autolist-strip");
  await expect(strip.getByTestId("autolist-wan-warning")).toHaveText(
    "The check interface has no route: the WAN check cannot pass, hosts without a connection stay unknown",
  );
  await expect(strip).toContainText("23 failures in 24 h · ambiguous today: 3 · router check");
});

test("the WAN warning and the ambiguous count are in Russian", async ({ page }) => {
  const fake = a1();
  fake.mode = "add";
  fake.wanWarning = "the check interface has no route: the WAN check cannot pass";
  fake.ambiguousDay = 1;
  await page.addInitScript(() => {
    localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
  });
  await shell(page, fake);
  await page.goto("/journal/unopened");
  const strip = page.getByTestId("autolist-strip");
  await expect(strip.getByTestId("autolist-wan-warning")).toHaveText(
    "Интерфейс проверки без маршрута: проверка WAN не может пройти, хосты без соединения останутся «неизвестно»",
  );
  await expect(strip).toContainText(
    "проверка роутером: 4 из 30 за час · неоднозначных за сутки: 1",
  );
});

test("no WAN warning and no ambiguous count when the daemon has none", async ({ page }) => {
  for (const mode of ["candidates", "add"]) {
    const fake = a1();
    fake.mode = mode;
    await shell(page, fake);
    await open(page);
    const strip = page.getByTestId("autolist-strip");
    await expect(strip).toContainText("router check");
    await expect(strip.getByTestId("autolist-wan-warning")).toHaveCount(0);
    await expect(strip).not.toContainText("ambiguous today");
  }
});

const autolistReads = (fake: Fake) =>
  fake.calls.filter((c) => c === "GET /api/v1/system/autolist").length;

test("the stats view with the list off reads it once", async ({ page }) => {
  const fake = statsFake();
  fake.off = true;
  await page.clock.install();
  await statsShell(page, fake);
  await openStats(page);
  await expect.poll(() => autolistReads(fake)).toBe(1);
  await page.clock.runFor(30_000);
  await page.waitForTimeout(300);
  expect(autolistReads(fake)).toBe(1);
});

test("a pending stats probe reads every 2 s and slows down after its result", async ({ page }) => {
  const fake = statsFake();
  fake.queueOnly = true;
  await page.clock.install();
  await statsShell(page, fake);
  await openStats(page);
  const row = page.locator(".stats-row", { hasText: "tiny-api.io" });
  await row.getByRole("button", { name: "Won't open" }).click();
  await expect(row.locator(".spin")).toBeVisible();
  let before = autolistReads(fake);
  await page.clock.runFor(10_000);
  await expect.poll(() => autolistReads(fake) - before).toBeGreaterThanOrEqual(5);
  await page.waitForTimeout(300);
  expect(autolistReads(fake) - before).toBeLessThanOrEqual(6);

  finish(fake, "tiny-api.io", "short", "", 3072);
  await page.clock.runFor(2_000);
  await expect(row).toContainText("opened with a short answer (3 KB)");
  await page.waitForTimeout(300);
  before = autolistReads(fake);
  await page.clock.runFor(10_000);
  await page.waitForTimeout(300);
  expect(autolistReads(fake) - before).toBeLessThanOrEqual(2);
});

test("the Journal reads the list again after it is enabled in Settings", async ({ page }) => {
  const fake = statsFake();
  fake.off = true;
  await statsShell(page, fake);
  const saved: Record<string, unknown> = {
    "app.dnsProxy.unmatchedTtl": 60,
    "app.autolist.enabled": false,
    "app.autolist.group": "b10c4ed0",
  };
  await page.route(/\/system\/settings(\?.*)?$/, (route) => {
    if (route.request().method() === "PUT") {
      Object.assign(saved, route.request().postDataJSON().settings);
      fake.off = false;
      return route.fulfill({ json: { applied: ["app.autolist.enabled"], pendingRestart: [] } });
    }
    return route.fulfill({
      json: {
        settings: saved,
        classes: { "app.autolist.enabled": "live", "app.autolist.group": "live" },
        pendingRestart: [],
        boot: "b",
        restarting: false,
        webUi: { port: 666, movedFrom: 0, lanAddress: "" },
      },
    });
  });
  await openStats(page);
  await expect(page.getByRole("button", { name: "Won't open" })).toHaveCount(0);

  await page.getByRole("tab", { name: "Settings" }).click();
  await page.getByRole("switch", { name: "Look for sites that do not open" }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();

  await page.getByRole("tab", { name: "Journal" }).click();
  await page.getByRole("tab", { name: /DNS stats/ }).click();
  await expect(page.getByRole("button", { name: "Won't open" }).first()).toBeVisible();
});

function bypass(addr: string, extra = {}) {
  return address(addr, {
    outcome: "bypass",
    how: "answer",
    group: "b10c4ed0",
    why: "",
    proto: "udp",
    port: 3478,
    fails: 5,
    ...extra,
  });
}

test("a bypass row says past firc, its group and how", async ({ page }) => {
  const fake = a1();
  fake.addresses = [
    bypass("203.0.113.9"),
    bypass("203.0.113.10", { how: "sni", fails: 1, group: "gone0000" }),
    bypass("203.0.113.11", { how: "ptr", fails: 22, port: 443 }),
  ];
  await shell(page, fake);
  await open(page);
  const row = page.locator("[data-address='203.0.113.9']");
  await expect(row.locator(".pill")).toHaveText("past firc");
  await expect(row).toContainText("→ «Blocked» · by firc's answer");
  await expect(row.locator(".port")).toHaveText("udp/3478");
  await expect(row.locator(".num")).toHaveText("5");
  await expect(row).not.toContainText("no answer to ClientHello");
  await expect(page.locator("[data-address='203.0.113.10']")).toContainText(
    "→ «gone0000» · by SNI",
  );
  await expect(page.locator("[data-address='203.0.113.11']")).toContainText("· by PTR");
});

test("a bypass row counts connections in Russian", async ({ page }) => {
  const fake = a1();
  fake.addresses = [
    bypass("203.0.113.9", { fails: 1 }),
    bypass("203.0.113.10", { fails: 3 }),
    bypass("203.0.113.11", { fails: 5 }),
  ];
  await page.addInitScript(() => {
    localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
  });
  await shell(page, fake);
  await page.goto("/journal/unopened");
  const meta = (a: string) => page.locator(`[data-address='${a}'] .meta`);
  await expect(meta("203.0.113.9")).toContainText("1 соединение");
  await expect(meta("203.0.113.10")).toContainText("3 соединения");
  await expect(meta("203.0.113.11")).toContainText("5 соединений");
  await expect(page.locator("[data-address='203.0.113.9'] .pill")).toHaveText("мимо firc");
  await expect(page.locator("[data-address='203.0.113.9']")).toContainText(
    "→ «Blocked» · по ответу firc",
  );
});

test("a udp bypass adds its own proto and port", async ({ page }) => {
  const fake = a1();
  fake.addresses = [bypass("203.0.113.9", { name: "stun.example.net" })];
  await shell(page, fake);
  await open(page);
  await page
    .locator("[data-address='203.0.113.9']")
    .getByRole("button", { name: "To group" })
    .click();
  await page.getByRole("menuitem", { name: "Blocked" }).click();
  await expect.poll(() => fake.adds.length).toBe(1);
  expect(fake.adds[0].body).toEqual({
    type: "subnet",
    rule: "203.0.113.9/32",
    enable: true,
    proto: "udp",
    ports: "3478",
    comment: "stun.example.net",
  });
});

test("a failed row still shows its cause", async ({ page }) => {
  await shell(page, a1());
  await open(page);
  const row = page.locator("[data-address='172.64.150.28']");
  await expect(row.locator(".pill")).toHaveText("no answer to ClientHello");
  await expect(row).not.toContainText("→ «");
  await expect(row.locator(".meta")).toContainText("4 failures");
});

test("the addresses table counts attempts and the candidates table failures", async ({ page }) => {
  await shell(page, a1());
  await open(page);
  const heads = page.locator(".card .head");
  await expect(heads.nth(0)).toContainText("Failures");
  await expect(heads.nth(1)).toContainText("Attempts");
  await expect(heads.nth(1)).not.toContainText("Failures");
});
