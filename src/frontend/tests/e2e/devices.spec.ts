import { expect, test, type Page } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

const HOSTS = [
  {
    mac: "aa:00:00:00:00:01",
    name: "TV",
    ip: "192.168.1.5",
    ip6: ["fd00::5"],
    active: true,
    registered: true,
    policy: "Policy0",
  },
  {
    mac: "aa:00:00:00:00:02",
    name: "Laptop",
    ip: "192.168.1.6",
    ip6: [],
    active: false,
    registered: true,
    policy: "",
  },
  {
    mac: "aa:00:00:00:00:03",
    name: "Phone",
    ip: "192.168.1.7",
    ip6: [],
    active: true,
    registered: true,
    policy: "Policy0",
  },
];

const POLICIES = [{ name: "Policy0", description: "Kids", devices: 5 }];

async function stub(
  page: Page,
  devices: { allow: string[]; deny: string[] },
  hosts = HOSTS,
  policies: { name: string; description: string; devices: number }[] = POLICIES,
) {
  await page.route("**/groups?with_rules=true", (route) =>
    route.fulfill({
      json: {
        groups: [
          { id: "0a1b2c3d", name: "Media", interface: "eth0", enable: true, devices, rules: [] },
        ],
      },
    }),
  );
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: ["eth0"] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies } }));
}

async function openDevices(page: Page) {
  await page
    .locator("button", { has: page.locator(".devices-icon") })
    .first()
    .click();
  await expect(page.locator(".modal .seg")).toBeVisible();
}

const row = (page: Page, mac: string) => page.locator(`li.host[data-mac="aa:00:00:00:00:${mac}"]`);
const switchOf = (page: Page, mac: string) => row(page, mac).locator("[role=switch]");
const policySwitch = (page: Page, name: string) =>
  page.locator(`li.host[data-policy="${name}"] [role=switch]`);
const done = (page: Page) => page.locator(".modal form button[type=submit]");
const macOrder = (page: Page) =>
  page.locator("li.host[data-mac]").evaluateAll((els) => els.map((el) => el.dataset.mac));

async function savedDevices(page: Page, groupsPage: GroupsPage) {
  let saved: any = null;
  await page.route("**/groups?save=true", async (route) => {
    saved = route.request().postDataJSON();
    await route.fulfill({ json: {} });
  });
  await page.locator(".modal form button[type=submit]").click();
  await groupsPage.save();
  await expect.poll(() => saved?.groups?.[0]?.devices).toBeTruthy();
  return saved.groups[0].devices;
}

test.describe("Device dialog", () => {
  let groupsPage: GroupsPage;

  // Catches the card counting entries instead of devices, or using the policy count before the hosts arrive.
  test("the card's button says what the selection means", async ({ page }) => {
    await stub(page, { allow: ["policy:Kids"], deny: [] });
    await groupsPage.goto();
    const button = page.locator("button", { has: page.locator(".devices-icon") }).first();
    await expect(button).toHaveAttribute("aria-label", "2 devices");
  });

  test("a deny-only selection is every device but those", async ({ page }) => {
    await stub(page, { allow: [], deny: ["mac:aa:00:00:00:00:02"] });
    await groupsPage.goto();
    const button = page.locator("button", { has: page.locator(".devices-icon") }).first();
    await expect(button).toHaveAttribute("aria-label", "All but 1");
  });

  test.beforeEach(async ({ page }) => {
    groupsPage = new GroupsPage(page);
    await signedIn(page);
  });

  // Catches a switch-off in the all-devices mode writing anything but a deny of the MAC.
  test("switching a device off in «для всех» saves a deny of its MAC", async ({ page }) => {
    await stub(page, { allow: [], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await expect(page.locator(".seg .mode-all")).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator(".works-for")).toHaveText("works for 3 of 3");
    const [seg, all, only] = await Promise.all(
      [".modal .seg", ".seg .mode-all", ".seg .mode-only"].map((sel) =>
        page.locator(sel).boundingBox(),
      ),
    );
    expect(Math.abs(all!.width - only!.width)).toBeLessThanOrEqual(1);
    expect(only!.x + only!.width).toBeGreaterThan(seg!.x + seg!.width - 8);
    await expect(page.locator(".future")).toHaveText("New devices: the group will work for them.");
    await expect(switchOf(page, "02")).toHaveAttribute("aria-label", "Laptop (192.168.1.6)");
    await switchOf(page, "02").click();
    await expect(switchOf(page, "02")).toHaveAttribute("aria-checked", "false");
    await expect(row(page, "02").locator(".note")).toHaveText("excluded");
    await expect(page.locator(".works-for")).toHaveText("works for 2 of 3");
    expect(await savedDevices(page, groupsPage)).toEqual({
      allow: [],
      deny: ["mac:aa:00:00:00:00:02"],
    });
  });

  // Catches a policy switch-on not writing an allow, or a host switched off not writing a deny of its MAC.
  test("«только»: a policy on and one of its devices off saves allow policy, deny mac", async ({
    page,
  }) => {
    await stub(page, { allow: [], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await page.locator(".seg .mode-only").click();
    await expect(page.locator(".future")).toHaveText(
      "New devices: the group will not work for them until you switch them on.",
    );
    await policySwitch(page, "Policy0").click();
    await expect(row(page, "03").locator(".note")).toHaveText("on through policy Kids");
    await expect(switchOf(page, "03")).toHaveAttribute("aria-checked", "true");
    await switchOf(page, "03").click();
    await expect(row(page, "03").locator(".note")).toHaveText("excluded from Kids");
    await expect(switchOf(page, "01")).toHaveAttribute("aria-checked", "true");
    await expect(page.locator(".works-for")).toHaveText("works for 1 of 3");
    expect(await savedDevices(page, groupsPage)).toEqual({
      allow: ["policy:Policy0"],
      deny: ["mac:aa:00:00:00:00:03"],
    });
  });

  // Catches a denied policy's hosts staying on or enabled.
  test("a policy off in «для всех» locks its devices off", async ({ page }) => {
    await stub(page, { allow: [], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await policySwitch(page, "Policy0").click();
    const policyNote = await policySwitch(page, "Policy0").getAttribute("aria-describedby");
    expect(policyNote).toBeTruthy();
    await expect(page.locator(`[id="${policyNote}"]`)).toHaveText("excluded");
    await expect(switchOf(page, "01")).toHaveAttribute("aria-checked", "false");
    await expect(switchOf(page, "01")).toBeDisabled();
    await expect(row(page, "01").locator(".note")).toHaveText("off by policy Kids");
    const described = await switchOf(page, "01").getAttribute("aria-describedby");
    expect(described).toBeTruthy();
    await expect(page.locator(`[id="${described}"]`)).toHaveText("off by policy Kids");
    await expect(switchOf(page, "02")).toBeEnabled();
    expect(await savedDevices(page, groupsPage)).toEqual({ allow: [], deny: ["policy:Policy0"] });
  });

  // Catches rows being reordered by the switch (selected-first) so a switched row jumps.
  test("a switched row keeps its position", async ({ page }) => {
    await stub(page, { allow: [], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    const before = await macOrder(page);
    expect(before).toEqual(["aa:00:00:00:00:03", "aa:00:00:00:00:01", "aa:00:00:00:00:02"]);
    await switchOf(page, "01").click();
    await expect(row(page, "01").locator(".note")).toHaveText("excluded");
    expect(await macOrder(page)).toEqual(before);
    await page.locator(".seg .mode-only").click();
    await switchOf(page, "02").click();
    await expect(switchOf(page, "02")).toHaveAttribute("aria-checked", "true");
    expect(await macOrder(page)).toEqual(before);
  });

  // Catches Done saving only-selected mode with nothing on, which the daemon reads as every device.
  test("«Готово» is disabled in «только» while nothing is on", async ({ page }) => {
    await stub(page, { allow: [], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await page.locator(".seg .mode-only").click();
    await expect(page.locator(".works-for")).toHaveText("works for 0 of 3");
    await expect(done(page)).toBeDisabled();
    await expect(page.locator(".done-hint")).toContainText("Switch on at least one device");
    await switchOf(page, "02").click();
    await expect(done(page)).toBeEnabled();
    await expect(page.locator(".done-hint")).toHaveCount(0);
    expect(await savedDevices(page, groupsPage)).toEqual({
      allow: ["mac:aa:00:00:00:00:02"],
      deny: [],
    });
  });

  // Catches choosing all-devices keeping an allow or dropping a deny.
  test("choosing «для всех» drops the allows and keeps the denies", async ({ page }) => {
    await stub(page, {
      allow: ["policy:Policy0", "mac:aa:00:00:00:00:02", "10.0.0.0/8"],
      deny: ["mac:aa:00:00:00:00:03"],
    });
    await groupsPage.goto();
    await openDevices(page);
    await expect(page.locator(".seg .mode-only")).toHaveAttribute("aria-pressed", "true");
    await page.locator(".seg .mode-all").click();
    await expect(page.locator(".seg .mode-all")).toHaveAttribute("aria-pressed", "true");
    await expect(switchOf(page, "01")).toHaveAttribute("aria-checked", "true");
    await expect(switchOf(page, "03")).toHaveAttribute("aria-checked", "false");
    expect(await savedDevices(page, groupsPage)).toEqual({
      allow: [],
      deny: ["mac:aa:00:00:00:00:03"],
    });
  });

  // Catches a policy denied under its other spelling staying on, or getting a second switch.
  test("a policy denied by its other spelling is one switch, off", async ({ page }) => {
    await stub(page, { allow: ["policy:Policy0"], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await expect(policySwitch(page, "Policy0")).toHaveAttribute("aria-checked", "true");
    await page.locator("button.manual-toggle").click();
    await page.locator("#devices-deny").fill("policy:Kids");
    await expect(policySwitch(page, "Policy0")).toHaveAttribute("aria-checked", "false");
    await expect(page.locator("li.host[data-policy]")).toHaveCount(1);
    await expect(row(page, "01").locator(".note")).toHaveText("off by policy Kids");
  });

  // Catches a live switch for a policy no key can name, or one that does not say why.
  test("a policy no key can name has a disabled switch that says why", async ({ page }) => {
    await stub(page, { allow: [], deny: [] }, HOSTS, [
      { name: "Policy1", description: "Policy0", devices: 0 },
      { name: "Policy0", description: "", devices: 2 },
    ]);
    await groupsPage.goto();
    await openDevices(page);
    await expect(policySwitch(page, "Policy0")).toBeDisabled();
    const note = await policySwitch(page, "Policy0").getAttribute("aria-describedby");
    expect(note).toBeTruthy();
    await expect(page.locator(`[id="${note}"]`)).toHaveText(
      "unreachable: its name is taken by the description of policy Policy1",
    );
    await expect(policySwitch(page, "Policy1")).toBeEnabled();
  });

  // Catches the mode derived from the allow alone, so switching its device off flips it to all-devices.
  test("a typed allow keeps «только» once its device is switched off", async ({ page }) => {
    await stub(page, { allow: [], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await page.locator("button.manual-toggle").click();
    await page.locator("#devices-allow").fill("mac:aa:00:00:00:00:02");
    await expect(page.locator(".seg .mode-only")).toHaveAttribute("aria-pressed", "true");
    await expect(switchOf(page, "02")).toHaveAttribute("aria-checked", "true");
    await switchOf(page, "02").click();
    await expect(page.locator(".seg .mode-only")).toHaveAttribute("aria-pressed", "true");
    await expect(switchOf(page, "02")).toHaveAttribute("aria-checked", "false");
    await expect(done(page)).toBeDisabled();
  });

  // Catches the shared Switch dropping its focus outline on :focus-visible.
  test("a switch reached by Tab shows a focus ring", async ({ page }) => {
    await stub(page, { allow: [], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await page.locator(".host-search").focus();
    await page.keyboard.press("Tab");
    const ring = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement;
      const st = getComputedStyle(el);
      return [el.getAttribute("role"), st.outlineStyle, st.outlineWidth];
    });
    expect(ring).toEqual(["switch", "solid", "2px"]);
  });

  // Catches an unlisted mac: entry having no row, vanishing when switched off, or staying in the selector.
  test("an unknown mac row is shown, can be switched off and stays", async ({ page }) => {
    await stub(page, { allow: ["mac:aa:00:00:00:00:99", "mac:aa:00:00:00:00:01"], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await expect(row(page, "99").locator(".name")).toHaveText("aa:00:00:00:00:99");
    await expect(row(page, "99").locator(".meta")).toHaveText("not on the network now");
    await expect(switchOf(page, "99")).toHaveAttribute("aria-checked", "true");
    await expect(page.locator(".works-for")).toHaveText("works for 1 of 3");
    await switchOf(page, "99").click();
    await expect(switchOf(page, "99")).toHaveAttribute("aria-checked", "false");
    expect(await savedDevices(page, groupsPage)).toEqual({
      allow: ["mac:aa:00:00:00:00:01"],
      deny: [],
    });
  });

  // Catches an address entry shown as a checked row, a bad line marked only on submit, or Done closing over it.
  test("«Вручную» holds address entries and marks a bad line as it is typed", async ({ page }) => {
    await stub(page, { allow: ["192.168.1.0/24"], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await expect(switchOf(page, "01")).toHaveAttribute("aria-checked", "true");
    await expect(row(page, "01").locator(".note")).toHaveText("on through a manual entry");
    await page.locator("button.manual-toggle").click();
    await expect(page.locator("#devices-allow")).toHaveValue("192.168.1.0/24");
    await page.locator("#devices-allow").fill("192.168.1.0/24\nlaptop.lan");
    await expect(page.locator(".modal .error")).toContainText("laptop.lan");
    await expect(page.locator("#devices-allow")).toHaveClass(/invalid/);
    await page.locator(".modal form button[type=submit]").click();
    await expect(page.locator(".modal")).toHaveAttribute("data-state", "open");
    await page.locator("#devices-allow").fill("192.168.2.0/24");
    expect(await savedDevices(page, groupsPage)).toEqual({ allow: ["192.168.2.0/24"], deny: [] });
  });

  // Catches an empty host list leaving the manual block shut with no explanation.
  test("with no hosts the manual block is open and says why", async ({ page }) => {
    await stub(page, { allow: [], deny: [] }, []);
    await groupsPage.goto();
    await openDevices(page);
    await expect(page.locator("#devices-allow")).toBeVisible();
    await expect(page.getByText("The router lists no devices", { exact: false })).toBeVisible();
  });

  // Catches opening and closing the dialog rewriting a selector that joinSelector would reorder.
  test("«Готово» with nothing touched leaves the group unchanged", async ({ page }) => {
    await stub(page, {
      allow: ["192.168.1.0/24", "policy:Policy0", "mac:AA-00-00-00-00-01"],
      deny: [],
    });
    await groupsPage.goto();
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
    await openDevices(page);
    await page.locator(".modal form button[type=submit]").click();
    await expect(page.locator(".modal .seg")).toHaveCount(0);
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
  });

  // Catches an unnamed host with an IP being shown by its bare MAC.
  test("an unnamed host with an address is told apart by it, not just its MAC", async ({
    page,
  }) => {
    await stub(page, { allow: [], deny: [] }, [
      {
        mac: "aa:00:00:00:00:09",
        name: "",
        ip: "192.168.1.9",
        ip6: [],
        active: true,
        registered: true,
        policy: "",
      },
    ]);
    await groupsPage.goto();
    await openDevices(page);
    await expect(switchOf(page, "09")).toHaveAttribute(
      "aria-label",
      "192.168.1.9 (aa:00:00:00:00:09)",
    );
  });

  // Catches a row's switch or a mode half pushed off a phone screen, or the dialog scrolling sideways.
  test("at 400 px a row keeps its switch and nothing overflows", async ({ page }) => {
    await stub(page, { allow: [], deny: [] });
    await groupsPage.goto();
    await openDevices(page);
    await page.setViewportSize({ width: 400, height: 800 });
    const tv = row(page, "01");
    for (const el of [
      tv.locator("[role=switch]"),
      page.locator(".seg .mode-all"),
      page.locator(".seg .mode-only"),
    ]) {
      const box = await el.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.x + box!.width).toBeLessThanOrEqual(400);
    }
    await expect(tv).toContainText("TV");
    const overflow = await page.evaluate(() => {
      const modal = document.querySelector(".modal") as HTMLElement;
      return {
        page: document.documentElement.scrollWidth,
        modal: modal.scrollWidth - modal.clientWidth,
      };
    });
    expect(overflow.page).toBeLessThanOrEqual(400);
    expect(overflow.modal).toBeLessThanOrEqual(0);
    const inner = await page.evaluate(() => {
      const fits = (el: Element) => el.scrollWidth <= el.clientWidth;
      return {
        body: fits(document.querySelector(".modal .body")!),
        rows: [...document.querySelectorAll("li.host[data-mac]")].map(fits),
        names: [...document.querySelectorAll("li.host .name")].map(
          (el) => el.getBoundingClientRect().width,
        ),
      };
    });
    expect(inner.body).toBe(true);
    expect(inner.rows).toEqual([true, true, true]);
    for (const width of inner.names) expect(width).toBeGreaterThan(0);
  });

  test("rows keep a gap from the scrollbar of a scrolling list", async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 600 });
    const many = Array.from({ length: 14 }, (_, i) => ({
      mac: `aa:00:00:00:01:${String(i).padStart(2, "0")}`,
      name: `Host ${i}`,
      ip: `192.168.1.${20 + i}`,
      ip6: [],
      active: true,
      registered: true,
      policy: "",
    }));
    await stub(page, { allow: [], deny: [] }, many);
    await groupsPage.goto();
    await openDevices(page);
    const m = await page.locator(".modal .body").evaluate((body) => {
      const edge = body.getBoundingClientRect().left + body.clientLeft + body.clientWidth;
      const right = Math.max(
        ...Array.from(body.querySelectorAll("li.host")).map(
          (el) => el.getBoundingClientRect().right,
        ),
      );
      return {
        scrolls: body.scrollHeight > body.clientHeight,
        gap: edge - right,
        bar: getComputedStyle(body, "::-webkit-scrollbar").width,
        thumb: getComputedStyle(body, "::-webkit-scrollbar-thumb").backgroundColor,
        bg: getComputedStyle(body.closest(".modal")!).backgroundColor,
        overflowX: body.scrollWidth > body.clientWidth,
      };
    });
    expect(m.scrolls).toBe(true);
    expect(m.gap).toBeGreaterThanOrEqual(4);
    expect(m.bar).toBe("8px");
    expect(m.thumb).not.toBe(m.bg);
    expect(m.thumb).not.toBe("rgba(0, 0, 0, 0)");
    expect(m.overflowX).toBe(false);
  });
});
