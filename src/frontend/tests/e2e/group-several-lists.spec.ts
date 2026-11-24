import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

type Rule = { enable: boolean; id: string; rule: string; type: string };

type List = {
  id: string;
  url: string;
  interval: number;
  lastUpdate: number;
  sync: { state: string; error: string; lastCheck: number };
  rules: Rule[];
};

type Group = {
  id: string;
  name: string;
  interface: string;
  enable: boolean;
  devices: { allow: string[]; deny: string[] };
  rules: Rule[];
  lists: List[];
};

const GID = "a1b2c3d4";

const listId = (n: number) => (0x0a000000 + n).toString(16).padStart(8, "0");

const makeList = (n: number, url = `https://lists${n}.example/list.txt`): List => ({
  id: listId(n),
  url,
  interval: 21600,
  lastUpdate: 1700000000,
  sync: { state: "idle", error: "", lastCheck: 1800000000 },
  rules: [
    { enable: true, id: (0x0b000000 + n).toString(16), rule: `l${n}.example.com`, type: "domain" },
  ],
});

const makeGroup = (lists: List[]): Group => ({
  id: GID,
  name: "Social",
  interface: "eth0",
  enable: true,
  devices: { allow: [], deny: [] },
  rules: [],
  lists,
});

const listRes = ({ rules, ...meta }: List) => ({ ...meta, rulesTotal: rules.length });
const groupRes = (group: Group) => ({ ...group, lists: group.lists.map(listRes) });

async function setup(page: Page, data: Group[]) {
  let groups = structuredClone(data);
  const puts: any[] = [];
  const syncs: string[] = [];

  await signedIn(page);
  await page.route("**/interfaces", (route) =>
    route.fulfill({ json: { interfaces: ["eth0", "wlan0"] } }),
  );
  await page.route("**/system/config/save*", (route) => route.fulfill({ json: { status: "ok" } }));
  await page.route(/\/groups(\?.*)?$/, async (route) => {
    if (route.request().method() === "PUT") {
      const body = route.request().postDataJSON();
      puts.push(body);
      groups = body.groups.map((g: any) => {
        const was = groups.find((x) => x.id === g.id);
        return {
          ...g,
          lists: g.lists.map(
            (item: any) =>
              was?.lists.find((l) => l.id === item.id && l.url === item.url) ?? {
                ...item,
                lastUpdate: 0,
                sync: { state: "idle", error: "", lastCheck: 0 },
                rules: [],
              },
          ),
        };
      });
    }
    await route.fulfill({ json: { groups: groups.map(groupRes) } });
  });
  await page.route(/\/groups\/[0-9a-f]{8}\/lists\/[0-9a-f]{8}\/rules(\?.*)?$/, async (route) => {
    const parts = route.request().url().replace(/\?.*$/, "").split("/");
    const list = groups
      .find((g) => g.id === parts.at(-4))
      ?.lists.find((l) => l.id === parts.at(-2));
    if (!list) {
      await route.fulfill({ status: 404, json: { error: "group has no such list" } });
      return;
    }
    await route.fulfill({
      json: { total: list.rules.length, matched: list.rules.length, offset: 0, rules: list.rules },
    });
  });

  await page.route(/\/groups\/[0-9a-f]{8}(\/lists\/[0-9a-f]{8})?\/sync$/, async (route) => {
    syncs.push(new URL(route.request().url()).pathname.replace(/^.*\/groups\//, ""));
    const group = groups.find((g) => route.request().url().includes(g.id))!;
    await route.fulfill({ status: 202, json: groupRes(group) });
  });
  await page.route("**/groups/*/sync/events", (route) =>
    route.fulfill({ status: 200, contentType: "text/event-stream", body: "" }),
  );

  await page.goto("/");
  await expect(page.locator(".group-wrapper")).toHaveCount(data.length);
  return { puts, syncs };
}

async function openSettings(page: Page) {
  await page.getByRole("button", { name: "Group Settings" }).first().click();
  return page.getByRole("dialog");
}

test.describe("A group with several lists", () => {
  // Catches the dialog replacing the group's list instead of adding a second one, or the new list going out without the group's interval.
  test("a group takes a second list", async ({ page }) => {
    const state = await setup(page, [makeGroup([makeList(1)])]);

    const dialog = await openSettings(page);
    await dialog.locator("#gd-url").fill("https://two.example/list.txt");
    await dialog.getByRole("button", { name: "Add list", exact: true }).click();
    await expect(dialog.locator(".gd-list-url")).toHaveCount(2);
    await expect(dialog.locator("#gd-url")).toHaveValue("");
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    await expect(page.locator(".list-header")).toHaveCount(2);
    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();

    const lists = state.puts[0].groups[0].lists;
    expect(lists).toHaveLength(2);
    expect(lists[0]).toEqual({
      id: listId(1),
      url: "https://lists1.example/list.txt",
      interval: 21600,
    });
    expect(lists[1].url).toBe("https://two.example/list.txt");
    expect(lists[1].interval).toBe(21600);
    expect(lists[1].id).toMatch(/^[0-9a-f]{8}$/);
    expect(lists[1].id).not.toBe(listId(1));
  });

  // Catches one list's failure hiding the other list's rules, or the error landing on the wrong list.
  test("one failing list shows its error and the other its rules", async ({ page }) => {
    const failing = makeList(2, "https://fail.example/list.txt");
    failing.rules = [];
    failing.sync = { state: "error", error: "fetch failed: HTTP 404", lastCheck: 1800000000 };
    await setup(page, [makeGroup([makeList(1), failing])]);
    await page.locator("[data-collapsible-trigger]").first().click();

    const headers = page.locator(".list-header");
    await expect(headers).toHaveCount(2);
    await expect(headers.nth(0).locator(".sync-error")).toHaveCount(0);
    await expect(headers.nth(1).locator(".sync-error")).toHaveText("fetch failed: HTTP 404");
    await expect(page.locator(".list-rule")).toHaveCount(1);
    await expect(page.locator(".list-rule")).toContainText("l1.example.com");
  });

  // Catches the dialog letting a group take more lists than the daemon accepts.
  test("the seventeenth list cannot be added", async ({ page }) => {
    await setup(page, [makeGroup(Array.from({ length: 15 }, (_, i) => makeList(i + 1)))]);

    const dialog = await openSettings(page);
    const add = dialog.getByRole("button", { name: "Add list", exact: true });
    await dialog.locator("#gd-url").fill("https://sixteen.example/list.txt");
    await add.click();
    await expect(dialog.locator(".gd-list-url")).toHaveCount(16);
    await expect(add).toBeDisabled();
    await expect(dialog.locator("#gd-url")).toBeDisabled();
    await expect(dialog).toContainText("A group holds at most 16 lists");
  });

  // Catches a removed list leaving its rules on the card or going back to the daemon.
  test("removing a list drops its rows", async ({ page }) => {
    const state = await setup(page, [makeGroup([makeList(1), makeList(2)])]);
    await page.locator("[data-collapsible-trigger]").first().click();
    await expect(page.locator(".list-rule")).toHaveCount(2);

    const dialog = await openSettings(page);
    await dialog.getByRole("button", { name: "Remove list" }).nth(1).click();
    await expect(dialog.locator(".gd-list-url")).toHaveCount(1);
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    await expect(page.locator(".list-header")).toHaveCount(1);
    await expect(page.locator(".list-rule")).toHaveCount(1);
    await expect(page.locator(".list-rule")).toContainText("l1.example.com");
    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(state.puts[0].groups[0].lists.map((l: any) => l.id)).toEqual([listId(1)]);
  });

  // Catches the dialog taking the same address twice into one group.
  test("a list already in the group is not added again", async ({ page }) => {
    await setup(page, [makeGroup([makeList(1)])]);

    const dialog = await openSettings(page);
    await dialog.locator("#gd-url").fill("https://lists1.example/list.txt");
    await expect(dialog).toContainText("List already exists");
    await expect(dialog.getByRole("button", { name: "Add list", exact: true })).toBeDisabled();
    await expect(dialog.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  });

  // Catches Enter in an empty url field being swallowed instead of saving the dialog.
  test("Enter in an empty url field saves the dialog", async ({ page }) => {
    await setup(page, [makeGroup([makeList(1)])]);

    const dialog = await openSettings(page);
    await dialog.locator("#gd-url").press("Enter");
    await dialog.waitFor({ state: "hidden" });
  });

  // Catches the group button syncing one list, or a list's own button syncing the whole group.
  test("the group button syncs every list and a list's button only that list", async ({ page }) => {
    const state = await setup(page, [makeGroup([makeList(1), makeList(2)])]);

    await page.getByRole("button", { name: "Sync all lists" }).click();
    await expect.poll(() => state.syncs).toEqual([`${GID}/sync`]);
    await page.getByRole("button", { name: "Sync this list" }).nth(1).click();
    await expect.poll(() => state.syncs).toEqual([`${GID}/sync`, `${GID}/lists/${listId(2)}/sync`]);
  });

  // Catches the dialog's interval reaching only some of the group's lists.
  test("the dialog's interval goes to every list", async ({ page }) => {
    const state = await setup(page, [makeGroup([makeList(1), makeList(2)])]);

    const dialog = await openSettings(page);
    await dialog.locator(".interval-select [data-select-trigger]").click();
    await page.getByRole("option", { name: "once an hour" }).click();
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    await page.locator("#save-changes").click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(state.puts[0].groups[0].lists.map((l: any) => l.interval)).toEqual([3600, 3600]);
  });

  // Catches lists that share an address prefix showing the same clipped text with nothing to tell them apart.
  test("lists that share a prefix are named by their file", async ({ page }) => {
    const base = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set";
    await setup(page, [
      makeGroup([
        makeList(1, `${base}/geosite-telegram.srs`),
        makeList(2, `${base}/geosite-instagram.srs`),
      ]),
    ]);

    await expect(page.locator(".list-header .list-name")).toHaveText([
      "geosite-telegram.srs",
      "geosite-instagram.srs",
    ]);
    const dialog = await openSettings(page);
    await expect(dialog.locator(".gd-list-name")).toHaveText([
      "geosite-telegram.srs",
      "geosite-instagram.srs",
    ]);
  });
});
