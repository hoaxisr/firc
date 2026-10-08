import { expect, test, type Page } from "@playwright/test";

import { dragTo } from "./pages/drag";
import { signedIn } from "./pages/session";

type ListRule = {
  enable: boolean;
  id: string;
  rule: string;
  type: string;
  proto?: string;
  ports?: string;
};

type ListGroup = {
  id: string;
  name: string;
  interface: string;
  enable: boolean;
  devices: { allow: string[]; deny: string[] };
  rules: ListRule[];
  list: {
    url: string;
    interval: number;
    lastUpdate: number;
    sync: { state: string; error: string; lastCheck: number };
    rules: ListRule[];
  };
};

const makeListGroup = (
  id: string,
  url: string,
  name = `Group ${id}`,
  listRules: ListRule[] = [
    { enable: true, id: `${id.slice(0, 4)}aaaa`, rule: `${id}.example.com`, type: "domain" },
  ],
): ListGroup => ({
  id,
  name,
  interface: "eth0",
  enable: true,
  devices: { allow: [], deny: [] },
  rules: [],
  list: {
    url,
    interval: 86400,
    lastUpdate: 1700000000,
    sync: { state: "idle", error: "", lastCheck: 1800000000 },
    rules: listRules,
  },
});

function groupRes(group: ListGroup) {
  if (!group.list) return { ...group };
  const { rules: listRules, ...listMeta } = group.list;
  return { ...group, list: { ...listMeta, rulesTotal: listRules.length } };
}

const doneStream = (group: ListGroup) =>
  `event: done\ndata: ${JSON.stringify(groupRes(group))}\n\n`;

const readSizeParam = (params: URLSearchParams, name: string, dflt: number): number | null => {
  const raw = params.get(name);
  if (raw === null || raw === "") return dflt;
  if (!/^[0-9]+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
};

async function setupGroupLists(page: Page, data: ListGroup[], options: { expand?: boolean } = {}) {
  const { expand = true } = options;
  let groups = structuredClone(data);
  let savedBody: { groups: any[] } | null = null;
  let syncBody: { url?: string } | null = null;
  const patchBodies: { id: string; body: { rules: { id: string }[] } }[] = [];
  const writeUrls: string[] = [];
  const pageUrls: string[] = [];
  const streamUrls: string[] = [];
  let writeAttempts = 0;
  let configSaves = 0;

  await signedIn(page);
  await page.route("**/interfaces", async (route) =>
    route.fulfill({ json: { interfaces: ["eth0", "wlan0"] } }),
  );

  await page.route(/\/groups(\?.*)?$/, async (route) => {
    if (route.request().method() === "PUT") {
      writeAttempts++;
      writeUrls.push(route.request().url());
      savedBody = route.request().postDataJSON();
      groups = (savedBody?.groups ?? []).map((g: any) => {
        const existing = groups.find((x) => x.id === g.id);
        let list = existing?.list;
        if ("list" in g) {
          if (g.list === null || g.list === undefined) {
            list = undefined as any;
          } else if (list && list.url === g.list.url) {
            list = { ...list, interval: g.list.interval };
          } else {
            list = {
              url: g.list.url,
              interval: g.list.interval,
              lastUpdate: 1800000000,
              sync: { state: "queued", error: "", lastCheck: 0 },
              rules: [{ enable: true, id: "87654321", rule: "synced.example.com", type: "domain" }],
            };
          }
        }
        return structuredClone({ ...g, rules: g.rules ?? existing?.rules ?? [], list });
      });
      await route.fulfill({ json: { groups: groups.map(groupRes) } });
      return;
    }

    await route.fulfill({ json: { groups: groups.map(groupRes) } });
  });

  await page.route("**/system/config/save*", async (route) => {
    configSaves++;
    await route.fulfill({ json: { status: "ok" } });
  });

  await page.route(/\/groups\/[0-9a-f]{8}\/list\/rules(\?.*)?$/, async (route) => {
    const id = route.request().url().replace(/\?.*$/, "").split("/").at(-3) ?? "";
    const group = groups.find((item) => item.id === id);

    if (route.request().method() === "GET") {
      pageUrls.push(route.request().url());
      if (!group?.list) {
        await route.fulfill({ status: 404, json: { error: "group has no list" } });
        return;
      }
      const requestUrl = new URL(route.request().url());
      const offset = readSizeParam(requestUrl.searchParams, "offset", 0);
      if (offset === null) {
        await route.fulfill({ status: 400, json: { error: "invalid offset" } });
        return;
      }
      const asked = readSizeParam(requestUrl.searchParams, "limit", 50);
      if (asked === null) {
        await route.fulfill({ status: 400, json: { error: "invalid limit" } });
        return;
      }
      const limit = Math.min(asked || 50, 500);
      const q = (requestUrl.searchParams.get("q") ?? "").toLowerCase();
      const matches = group.list.rules.filter((r) => !q || r.rule.toLowerCase().includes(q));
      await route.fulfill({
        json: {
          total: group.list.rules.length,
          matched: matches.length,
          offset,
          rules: matches.slice(offset, offset + limit),
        },
      });
      return;
    }

    const body = route.request().postDataJSON();
    writeUrls.push(route.request().url());
    patchBodies.push({ id, body });
    if (!group?.list) {
      await route.fulfill({ status: 404, json: { error: "group has no list" } });
      return;
    }
    const staged: { rule: ListRule; edit: any }[] = [];
    for (const edit of body.rules ?? []) {
      if (edit.rule !== undefined) {
        await route.fulfill({
          status: 400,
          json: { error: "a list's pattern comes from the list itself" },
        });
        return;
      }
      const rule = group.list.rules.find((r) => r.id === edit.id);
      if (!rule) {
        await route.fulfill({ status: 404, json: { error: "rule not found" } });
        return;
      }
      staged.push({ rule, edit });
    }
    for (const { rule, edit } of staged) {
      if (edit.enable !== undefined) rule.enable = edit.enable;
      if (edit.type !== undefined) rule.type = edit.type;
    }
    await route.fulfill({ json: { status: "ok" } });
  });

  await page.route("**/groups/*/list/sync", async (route) => {
    syncBody = route.request().postDataJSON();
    const id = route.request().url().split("/").at(-3);
    const group = groups.find((item) => item.id === id);
    if (!group?.list) {
      await route.fulfill({ status: 404, json: { error: "group has no list" } });
      return;
    }

    group.list.url = syncBody?.url ?? group.list.url;
    group.list.rules = [
      { enable: true, id: "87654321", rule: "synced.example.com", type: "domain" },
    ];
    group.list.lastUpdate = 1800000000;
    group.list.sync = { state: "queued", error: "", lastCheck: group.list.sync.lastCheck };

    await route.fulfill({ status: 202, json: groupRes(group) });
  });

  await page.route("**/groups/*/list/sync/events", async (route) => {
    const id = route
      .request()
      .url()
      .replace(/\/list\/sync\/events.*$/, "")
      .split("/")
      .at(-1);
    const group = groups.find((item) => item.id === id);
    if (!group?.list) {
      await route.fulfill({ status: 404, json: { error: "group has no list" } });
      return;
    }
    streamUrls.push(route.request().url());
    group.list.sync = { state: "idle", error: "", lastCheck: group.list.sync.lastCheck };
    await route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      headers: { "Cache-Control": "no-cache" },
      body: doneStream(group),
    });
  });

  await page.goto("/");
  await expect(page.locator(".group-wrapper")).toHaveCount(data.length);
  if (expand) {
    for (let i = 0; i < data.length; i++) {
      await page.locator("[data-collapsible-trigger]").nth(i).click();
    }
  }

  return {
    get savedBody() {
      return savedBody;
    },
    get patchBodies() {
      return patchBodies;
    },
    get writeUrls() {
      return writeUrls;
    },
    get pageUrls() {
      return pageUrls;
    },
    get streamUrls() {
      return streamUrls;
    },
    get configSaves() {
      return configSaves;
    },
    get writeAttempts() {
      return writeAttempts;
    },
    get groups() {
      return groups;
    },
    get syncBody() {
      return syncBody;
    },
  };
}

test.describe("Groups with a list", () => {
  test("edits an existing list's URL and saves it", async ({ page }) => {
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    const urlInput = page.locator(".list-url-input").first();
    await expect(urlInput).toHaveValue("https://old.example/list.txt");

    await urlInput.fill("https://new.example/list.txt");

    const saveButton = page.locator("#save-changes");
    await expect(saveButton).not.toHaveClass(/inactive/);
    await saveButton.click();

    await expect(page.getByText("Saved")).toBeVisible();
    expect(state.savedBody?.groups[0].list.url).toBe("https://new.example/list.txt");
  });

  // Catches a Save sending the list's fetched rules back, which hits the 1 MiB body cap.
  test("saves a rule edit without sending the list back", async ({ page }) => {
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    await expect(page.locator(".list-rule")).toHaveCount(1);
    const toggle = page.locator(".list-rule [data-switch-root]").first();
    await expect(toggle).toBeVisible();
    await toggle.click();

    const saveButton = page.locator("#save-changes");
    await expect(saveButton).not.toHaveClass(/inactive/);
    await saveButton.click();
    await expect(page.getByText("Saved")).toBeVisible();

    await expect(page.locator(".list-rule [data-switch-root]").first()).toHaveAttribute(
      "aria-checked",
      "false",
    );

    expect(state.pageUrls[0]).toContain("offset=0");
    expect(state.savedBody?.groups[0].list).not.toHaveProperty("rules");
    expect(state.patchBodies).toHaveLength(1);
    expect(state.patchBodies[0].id).toBe("a1b2c3d4");
    expect(state.patchBodies[0].body.rules).toHaveLength(1);
    expect(state.patchBodies[0].body.rules[0]).toEqual({ id: "a1b2aaaa", enable: false });
    expect(state.groups[0].list.rules).toHaveLength(1);
    expect(state.groups[0].list.rules[0].enable).toBe(false);

    expect(state.writeUrls).toHaveLength(2);
    expect(state.writeUrls[0]).not.toContain("save=true");
    expect(state.writeUrls[1]).toContain("save=true");
  });

  // A sync replaces rule ids; a stale baseline hides an edit to a new rule, so no PATCH goes out.
  test("a rule edit made after a sync is not lost", async ({ page }) => {
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    await page.locator('[data-value="Sync List"] button').first().click();
    await expect(page.getByText("Synced", { exact: true })).toBeVisible();

    await expect(page.locator(".list-rule")).toHaveCount(1);
    const toggle = page.locator(".list-rule [data-switch-root]").first();
    await expect(toggle).toBeVisible();
    await toggle.click();

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(state.patchBodies).toHaveLength(1);
    expect(state.patchBodies[0].body.rules[0]).toEqual({ id: "87654321", enable: false });
    expect(state.groups[0].list.rules[0].enable).toBe(false);
  });

  // Catches a PATCH addressing the dialog preview's ids instead of the ids the sync handed out.
  test("a rule edit right after adding addresses the daemon's ids", async ({ page }) => {
    const state = await setupGroupLists(page, []);

    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    await dialog.locator("#gd-name").fill("New List Group");
    await dialog.locator('[aria-label="List by URL"]').click();
    await dialog.locator("#gd-url").fill("https://new.example/list.txt");
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    const saveButton = page.locator("#save-changes");
    await expect(saveButton).not.toHaveClass(/inactive/);
    await saveButton.click();
    await expect(page.getByText("Saved")).toBeVisible();
    await expect(page.getByText("Saved")).toBeHidden();

    await expect(page.locator(".list-rule")).toHaveCount(1);
    expect(state.syncBody).toBeNull();

    const toggle = page.locator(".list-rule [data-switch-root]").first();
    await expect(toggle).toBeVisible();
    await toggle.click();

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(state.patchBodies.at(-1)?.body.rules[0]).toEqual({ id: "87654321", enable: false });
  });

  // Catches the page ignoring the PUT's `queued` and showing no rules until a reload.
  test("a list group added and saved shows its rules without a Sync click", async ({ page }) => {
    const state = await setupGroupLists(page, []);

    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    await dialog.locator("#gd-name").fill("New List Group");
    await dialog.locator('[aria-label="List by URL"]').click();
    await dialog.locator("#gd-url").fill("https://new.example/list.txt");
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();

    await expect(page.locator(".list-rule")).toHaveCount(1);
    await expect(page.locator(".list-rule").first()).toContainText("synced.example.com");
    expect(state.streamUrls).toHaveLength(1);
    expect(state.syncBody).toBeNull();
  });

  // Catches Sync on an unsaved group posting to a 404 and toasting a failure.
  test("Sync waits until the group is saved", async ({ page }) => {
    const state = await setupGroupLists(page, []);

    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    await dialog.locator("#gd-name").fill("New List Group");
    await dialog.locator('[aria-label="List by URL"]').click();
    await dialog.locator("#gd-url").fill("https://new.example/list.txt");
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    const sync = page.getByRole("button", { name: "Save the group to sync its list" });
    await expect(sync).toHaveAttribute("aria-disabled", "true");
    await sync.click({ force: true });
    await page.waitForTimeout(300);
    expect(state.syncBody).toBeNull();
    await expect(page.getByText("Failed to sync")).toHaveCount(0);

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();
    await expect(page.getByRole("button", { name: "Sync List" })).toHaveAttribute(
      "aria-disabled",
      "false",
    );
  });

  // Catches an unsaved group asking for its list rules and toasting a 404 before Save.
  test("an unsaved list group asks for no rules and toasts nothing", async ({ page }) => {
    const state = await setupGroupLists(page, []);

    await page.locator('[data-value="Add Group"] button').click();
    const dialog = page.getByRole("dialog");
    await dialog.locator("#gd-name").fill("New List Group");
    await dialog.locator('[aria-label="List by URL"]').click();
    await dialog.locator("#gd-url").fill("https://new.example/list.txt");
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    await page.waitForTimeout(300);
    expect(state.pageUrls).toHaveLength(0);
    await expect(page.getByText("Request failed")).toHaveCount(0);

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();
    await expect(page.locator(".list-rule")).toHaveCount(1);
    await expect(page.getByText("Request failed")).toHaveCount(0);
  });

  test("a Save that fails part way through still persists what landed", async ({ page }) => {
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    await page.route(/\/groups\/[^/]+\/list\/rules(\?.*)?$/, async (route) => {
      if (route.request().method() !== "PATCH") {
        await route.fallback();
        return;
      }
      await route.fulfill({ status: 500, json: { error: "nope" } });
    });

    const toggle = page.locator(".list-rule [data-switch-root]").first();
    await expect(toggle).toBeVisible();
    await toggle.click();
    await page.locator("#save-changes").click();

    await expect.poll(() => state.configSaves).toBe(1);
    expect(state.savedBody?.groups[0].name).toBeDefined();
  });

  test("a Save that lands nothing does not write the config", async ({ page }) => {
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    let refused = 0;
    await page.route(/\/groups(\?.*)?$/, async (route) => {
      if (route.request().method() === "PUT") {
        refused++;
        await route.fulfill({ status: 413, json: { error: "too large" } });
        return;
      }
      await route.fallback();
    });

    const toggle = page.locator(".list-rule [data-switch-root]").first();
    await expect(toggle).toBeVisible();
    await toggle.click();
    await page.locator("#save-changes").click();

    await expect.poll(() => refused, { timeout: 5000 }).toBe(1);
    await page.waitForTimeout(500);
    expect(state.configSaves).toBe(0);
  });

  test("a Save whose answer is lost still asks for a write", async ({ page }) => {
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    await page.route(/\/groups(\?.*)?$/, async (route) => {
      if (route.request().method() === "PUT") {
        await route.abort("connectionreset");
        return;
      }
      await route.fallback();
    });

    const toggle = page.locator(".list-rule [data-switch-root]").first();
    await expect(toggle).toBeVisible();
    await toggle.click();
    await page.locator("#save-changes").click();

    await expect.poll(() => state.configSaves, { timeout: 5000 }).toBe(1);
  });

  test("a second Ctrl+S during a save does not start another one", async ({ page }) => {
    await setupGroupLists(page, [makeListGroup("a1b2c3d4", "https://old.example/list.txt")]);
    let configSaves = 0;
    await page.route("**/system/config/save*", async (route) => {
      configSaves++;
      await route.fulfill({ json: { status: "ok" } });
    });

    await page.route(/\/groups\/[^/]+\/list\/rules(\?.*)?$/, async (route) => {
      if (route.request().method() !== "PATCH") {
        await route.fallback();
        return;
      }
      await new Promise((r) => setTimeout(r, 600));
      await route.fulfill({ status: 500, json: { error: "nope" } });
    });

    const toggle = page.locator(".list-rule [data-switch-root]").first();
    await expect(toggle).toBeVisible();
    await toggle.click();

    await page.keyboard.press("Control+s");
    await page.waitForTimeout(150);
    await page.keyboard.press("Control+s");

    await expect.poll(() => configSaves, { timeout: 8000 }).toBe(1);
    await page.waitForTimeout(800);
    expect(configSaves).toBe(1);
  });

  test("prevents saving duplicate list URLs", async ({ page }) => {
    await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://one.example/list.txt", "One"),
      makeListGroup("b1c2d3e4", "https://two.example/list.txt", "Two"),
    ]);

    const urlInputs = page.locator(".list-url-input");
    await urlInputs.first().fill("https://two.example/list.txt");

    await expect(urlInputs.first()).toHaveClass(/invalid/);
    await expect(page.locator(".url-error")).toHaveText([
      "List already exists",
      "List already exists",
    ]);
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
  });

  test("syncs with the edited unsaved list URL", async ({ page }) => {
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    await page.locator(".list-url-input").first().fill("https://new.example/list.txt");
    await page.locator('[data-value="Sync List"] button').first().click();
    await expect(page.getByText("Synced", { exact: true })).toBeVisible();

    expect(state.syncBody?.url).toBe("https://new.example/list.txt");
    await expect(page.locator(".list-url-input").first()).toHaveValue(
      "https://new.example/list.txt",
    );
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);

    await expect(page.locator(".list-rule")).toContainText("synced.example.com");
  });

  test("the panel shows the fetch progress while the sync runs", async ({ page }) => {
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    let streams = 0;
    await page.route("**/groups/*/list/sync/events", async (route) => {
      streams++;
      if (streams === 1) {
        await route.fulfill({
          status: 200,
          contentType: "text/event-stream",
          body: `event: progress\ndata: ${JSON.stringify({
            stage: "fetch",
            bytes: 3145728,
            total: 7786120,
          })}\n\n`,
        });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 1500));
      await route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: `event: done\ndata: ${JSON.stringify(groupRes(state.groups[0]))}\n\n`,
      });
    });

    await page.locator('[data-value="Sync List"] button').first().click();

    const bar = page.locator(".sync-progress progress");
    await expect(bar).toBeVisible();
    await expect(bar).toHaveJSProperty("value", 3145728);
    await expect(bar).toHaveJSProperty("max", 7786120);
    await expect(page.locator(".sync-progress-text")).toHaveText("fetching 3.1 / 7.8 MB");

    await expect(page.getByText("Synced", { exact: true })).toBeVisible();
    await expect(page.locator(".sync-progress")).toHaveCount(0);
  });

  test("a sync error is shown on the record", async ({ page }) => {
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    await page.route("**/groups/*/list/sync/events", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: `event: error\ndata: ${JSON.stringify({ error: "fetch failed: HTTP 404" })}\n\n`,
      });
    });

    await expect(page.locator(".list-rule")).toHaveCount(1);
    const pagesBefore = state.pageUrls.length;
    expect(pagesBefore).toBeGreaterThan(0);

    await page.locator('[data-value="Sync List"] button').first().click();

    await expect(page.getByText("Sync failed: fetch failed: HTTP 404")).toBeVisible();
    await expect(page.locator(".sync-error")).toHaveText("fetch failed: HTTP 404");
    expect(state.pageUrls.length).toBe(pagesBefore);
  });

  test("an edit on page one survives a visit to page two", async ({ page }) => {
    const groupId = "a1b2c3d4";
    const manyRules = Array.from({ length: 60 }, (_, i) => ({
      enable: true,
      id: `${groupId.slice(0, 4)}${i.toString(16).padStart(4, "0")}`,
      rule: `rule-${i}.example.com`,
      type: "domain",
    }));
    const group = makeListGroup(groupId, "https://old.example/list.txt");
    group.list.rules = manyRules;

    const state = await setupGroupLists(page, [group]);

    await expect(page.locator(".list-rule")).toHaveCount(50);

    const firstRuleId = manyRules[0].id;
    const toggle = page.locator(".list-rule [data-switch-root]").first();
    await expect(toggle).toBeVisible();
    await toggle.click();

    await page.getByTitle("Next Page").click();
    await expect(page.locator(".list-rule")).toHaveCount(10);
    expect(state.pageUrls.some((url) => url.includes("offset=50"))).toBe(true);

    await page.getByTitle("Previous Page").click();
    await expect(page.locator(".list-rule")).toHaveCount(50);

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(state.patchBodies).toHaveLength(1);
    expect(state.patchBodies[0].body.rules).toEqual([{ id: firstRuleId, enable: false }]);
  });

  test("a sync resets the pager to the page the reload actually returned", async ({ page }) => {
    const groupId = "a1b2c3d4";
    const manyRules = Array.from({ length: 60 }, (_, i) => ({
      enable: true,
      id: `${groupId.slice(0, 4)}${i.toString(16).padStart(4, "0")}`,
      rule: `rule-${i}.example.com`,
      type: "domain",
    }));
    const group = makeListGroup(groupId, "https://old.example/list.txt");
    group.list.rules = manyRules;

    const state = await setupGroupLists(page, [group]);

    await page.route("**/groups/*/list/sync", async (route) => {
      const syncedRules = Array.from({ length: 60 }, (_, i) => ({
        enable: true,
        id: `synced${i.toString(16).padStart(4, "0")}`,
        rule: `synced-${i}.example.com`,
        type: "domain",
      }));
      state.groups[0].list.rules = syncedRules;
      state.groups[0].list.lastUpdate = 1900000000;
      await route.fulfill({ status: 202, json: groupRes(state.groups[0]) });
    });

    await expect(page.locator(".list-rule")).toHaveCount(50);

    await page.getByTitle("Next Page").click();
    await expect(page.locator(".list-rule")).toHaveCount(10);
    await expect(page.locator(".page-number")).toHaveText("2 / 2");

    await page.locator('[data-value="Sync List"] button').first().click();
    await expect(page.getByText("Synced", { exact: true })).toBeVisible();

    await expect(page.locator(".page-number")).toHaveText("1 / 2");
    await expect(page.locator(".list-rule-number").first()).toHaveText("1");
  });

  test("a failed page load does not retry without end", async ({ page }) => {
    await setupGroupLists(page, [makeListGroup("a1b2c3d4", "https://old.example/list.txt")], {
      expand: false,
    });

    let getCount = 0;
    let answer = 500;
    await page.route(/\/groups\/[0-9a-f]{8}\/list\/rules(\?.*)?$/, async (route) => {
      if (route.request().method() !== "GET") {
        await route.fallback();
        return;
      }
      getCount++;
      if (answer !== 200) {
        await route.fulfill({ status: 500, json: { error: "nope" } });
        return;
      }
      await route.fulfill({
        json: {
          total: 1,
          matched: 1,
          offset: 0,
          rules: [{ enable: true, id: "a1b20001", rule: "back.example.com", type: "domain" }],
        },
      });
    });

    await page.locator("[data-collapsible-trigger]").first().click();
    await expect(page.getByText("Request failed: nope")).toBeVisible();
    await page.waitForTimeout(500);

    expect(getCount).toBe(1);

    answer = 200;
    await page.locator("[data-collapsible-trigger]").first().click();
    await page.locator("[data-collapsible-trigger]").first().click();
    await expect(page.locator(".list-rule")).toHaveCount(1);
    await page.waitForTimeout(500);
    expect(getCount).toBe(2);
  });

  test("search is answered by the daemon", async ({ page }) => {
    const group = makeListGroup("a1b2c3d4", "https://old.example/list.txt");
    group.list.rules = [
      { enable: true, id: "a1b20001", rule: "alpha.example.com", type: "domain" },
      { enable: true, id: "a1b20002", rule: "beta.example.net", type: "domain" },
    ];

    const state = await setupGroupLists(page, [group]);

    await expect(page.locator(".list-rule")).toHaveCount(2);

    await page
      .locator('[data-tabs-content][data-state="active"] .group-controls-search .search-container')
      .click();
    await page
      .locator('[data-tabs-content][data-state="active"] .group-controls-search .search-input')
      .fill("example.net");

    await expect.poll(() => state.pageUrls.some((url) => url.includes("q=example.net"))).toBe(true);
    await expect(page.locator(".list-rule")).toHaveCount(1);
    await expect(page.locator(".list-rule")).toContainText("beta.example.net");
  });

  test("clearing the search reloads the page the daemon filtered", async ({ page }) => {
    const group = makeListGroup("a1b2c3d4", "https://old.example/list.txt");
    group.list.rules = [
      { enable: true, id: "a1b20001", rule: "alpha.example.com", type: "domain" },
      { enable: true, id: "a1b20002", rule: "beta.example.net", type: "domain" },
    ];

    const state = await setupGroupLists(page, [group]);

    await expect(page.locator(".list-rule")).toHaveCount(2);

    const search = page.locator(
      '[data-tabs-content][data-state="active"] .group-controls-search .search-input',
    );
    await page
      .locator('[data-tabs-content][data-state="active"] .group-controls-search .search-container')
      .click();
    await search.fill("example.net");
    await expect(page.locator(".list-rule")).toHaveCount(1);

    const unfilteredBefore = state.pageUrls.filter((url) => !url.includes("q=")).length;
    await search.fill("");

    await expect(page.locator(".list-rule")).toHaveCount(2);
    expect(state.pageUrls.filter((url) => !url.includes("q=")).length).toBe(unfilteredBefore + 1);
  });

  test("sets a group's device selector and saves it", async ({ page }) => {
    await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
    await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
    const state = await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://old.example/list.txt"),
    ]);

    const devicesButton = page.locator(".group-actions button", {
      has: page.locator(".devices-icon"),
    });
    await expect(devicesButton).toHaveAttribute("aria-label", "Every device");

    await devicesButton.click();
    await page.locator("#devices-allow").fill("192.168.1.0/24");
    await page.locator("#devices-deny").fill("");
    await page.locator(".modal form button[type=submit]").click();

    const saveButton = page.locator("#save-changes");
    await expect(saveButton).not.toHaveClass(/inactive/);
    await saveButton.click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(state.savedBody?.groups[0].devices).toEqual({ allow: ["192.168.1.0/24"], deny: [] });
    await expect(devicesButton).toHaveAttribute("aria-label", "1 device");
  });

  test("a_hand_rule_edit_in_a_list_group_sends_no_list_rules", async ({ page }) => {
    const group = makeListGroup("a1b2c3d4", "https://old.example/list.txt");
    group.rules = [{ enable: true, id: "handrule", rule: "hand.example.com", type: "domain" }];
    const state = await setupGroupLists(page, [group]);

    const handToggle = page.locator(".rule [data-switch-root]").first();
    await expect(handToggle).toBeVisible();
    await handToggle.click();

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(state.patchBodies).toHaveLength(0);
    expect(state.savedBody?.groups[0].rules[0].enable).toBe(false);
  });

  test("a_group_without_a_list_shows_no_list_section", async ({ page }) => {
    const group = makeListGroup("a1b2c3d4", "https://old.example/list.txt");
    (group as any).list = undefined;
    group.rules = [{ enable: true, id: "handrule", rule: "hand.example.com", type: "domain" }];
    await setupGroupLists(page, [group]);

    await expect(page.locator(".list-badge")).toHaveCount(0);
    await expect(page.getByText("From the list")).toHaveCount(0);
    await expect(page.locator(".list-rule")).toHaveCount(0);
    await expect(page.locator(".rule")).toHaveCount(1);
  });

  test("a_changed_list_rule_is_marked", async ({ page }) => {
    await setupGroupLists(page, [makeListGroup("a1b2c3d4", "https://old.example/list.txt")]);

    await expect(page.locator(".changed-tag")).toHaveCount(0);

    const toggle = page.locator(".list-rule [data-switch-root]").first();
    await expect(toggle).toBeVisible();
    await toggle.click();

    await expect(page.locator(".changed-tag")).toHaveCount(1);
    await expect(page.getByText("changed", { exact: true })).toBeVisible();

    await toggle.click();
    await expect(page.locator(".changed-tag")).toHaveCount(0);
  });

  // Catches a sing-box rule's protocol and ports being editable, or the type select left unlocked.
  test("a_list_rule_shows_its_protocol_and_ports_read_only", async ({ page }) => {
    await setupGroupLists(page, [
      makeListGroup("a1b2c3d4", "https://lists.example/discord.json", "Discord", [
        { enable: true, id: "a1b2aaaa", rule: "discord.com", type: "namespace" },
        {
          enable: true,
          id: "a1b2bbbb",
          rule: "66.22.192.0/18",
          type: "subnet",
          proto: "udp",
          ports: "50000-50099,19200-19400",
        },
      ]),
    ]);
    const row = page.locator('.list-rule[data-uuid="a1b2bbbb"]');
    await expect(row.locator(".list-rule-spec")).toHaveText("udp 50000-50099,19200-19400");
    await expect(row.locator(".select-wrap")).toHaveClass(/disabled/);
    await expect(page.locator('.list-rule[data-uuid="a1b2aaaa"] .list-rule-spec')).toHaveCount(0);
  });

  test("the_place_number_follows_a_drag", async ({ page }) => {
    const manual = { ...makeListGroup("aaaaaaa1", "") } as any;
    delete manual.list;
    manual.name = "Manual";

    const listGroup = makeListGroup("bbbbbbb2", "https://old.example/list.txt", "Listed");

    const state = await setupGroupLists(page, [manual, listGroup]);

    await expect(page.locator(".place-number").nth(0)).toHaveText("1");
    await expect(page.locator(".place-number").nth(1)).toHaveText("2");

    await dragTo(
      page,
      page.locator(".group-wrapper").nth(1).locator(".group-grip"),
      page.locator(".group-wrapper").nth(0),
      "before",
    );

    await expect(page.locator(".group-wrapper").nth(0).locator("input.group-name")).toHaveValue(
      "Listed",
    );
    await expect(page.locator(".place-number").nth(0)).toHaveText("1");
    await expect(page.locator(".place-number").nth(1)).toHaveText("2");

    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(state.savedBody?.groups.map((g: any) => g.id)).toEqual(["bbbbbbb2", "aaaaaaa1"]);
  });
});
