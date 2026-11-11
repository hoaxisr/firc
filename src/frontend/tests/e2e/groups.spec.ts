import { expect, test, type Page } from "@playwright/test";

import { answerConfirm } from "./pages/confirm";
import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

test.describe("Groups Management", () => {
  let groupsPage: GroupsPage;

  test.beforeEach(async ({ page }) => {
    groupsPage = new GroupsPage(page);

    await signedIn(page);

    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({ json: { groups: [] } });
    });

    await page.route("**/interfaces", async (route) => {
      await route.fulfill({ json: { interfaces: ["eth0", "wlan0"] } });
    });

    await groupsPage.goto();
  });

  // Catches a rule arriving from the server being validated only on input, so Save stays enabled until a 400.
  test("a rule the daemon will refuse is flagged before Save is pressed", async ({ page }) => {
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "aaaaaaaa",
              name: "legacy",
              interface: "eth0",
              enable: true,
              rules: [
                {
                  id: "bbbbbbbb",
                  name: "pasted url",
                  type: "domain",
                  rule: "https://vk.com",
                  enable: true,
                },
                { id: "cccccccc", name: "fine", type: "domain", rule: "example.com", enable: true },
              ],
            },
          ],
        },
      });
    });
    await groupsPage.goto();

    await expect(page.locator(".rule")).toHaveCount(2);
    await expect(page.locator(".rule .pattern-input").first()).toHaveClass(/invalid/);
    await expect(page.locator(".rule .pattern-input").nth(1)).not.toHaveClass(/invalid/);
    await expect(groupsPage.saveButton).toHaveClass(/fail/);
  });

  // A group made through the dialog has no rules; there is no inline add with a default rule.
  test("should create a new group through the dialog", async ({ page }) => {
    await expect(page.locator(".group-wrapper")).toHaveCount(0);
    await expect(page.getByText("No groups yet")).toBeVisible();

    await groupsPage.createGroup("Through the dialog");

    await expect(page.locator(".group-wrapper")).toHaveCount(1);
    await expect((await groupsPage.getGroupHeader(0)).locator("input.group-name")).toHaveValue(
      "Through the dialog",
    );

    await expect(page.locator(".rule")).toHaveCount(0);
  });

  test("should edit group name", async ({ page }) => {
    await groupsPage.createGroup();
    const newName = "My Test Group";
    await groupsPage.setGroupName(0, newName);

    const input = (await groupsPage.getGroupHeader(0)).locator("input.group-name");
    await expect(input).toHaveValue(newName);
  });

  test("should add a rule to a group", async ({ page }) => {
    await groupsPage.createGroup();
    await expect(page.locator(".rule")).toHaveCount(0);

    await groupsPage.addRuleToGroup(0);

    await expect(page.locator(".rule")).toHaveCount(1);
  });

  test("should save changes", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);

    await groupsPage.setGroupName(0, "Valid Group");
    await groupsPage.setRulePattern(0, 0, "domain.com");

    await expect(groupsPage.saveButton).not.toHaveClass(/inactive|fail/);

    let saveRequestReceived = false;
    await page.route("**/groups?save=true", async (route) => {
      saveRequestReceived = true;
      const body = route.request().postDataJSON();
      expect(body.groups).toHaveLength(1);
      expect(body.groups[0].name).toBe("Valid Group");
      await route.fulfill({ status: 200, json: {} });
    });

    await groupsPage.save();

    await expect.poll(() => saveRequestReceived).toBe(true);
    await expect(page.getByText("Saved")).toBeVisible();
  });

  // Catches a group added while the list is still loading, wiped when the list arrives.
  test("Add waits for the group list, and a group added after it stays", async ({ page }) => {
    let release: () => void = () => {};
    const held = new Promise<void>((r) => (release = r));
    await page.unroute("**/groups?with_rules=true");
    await page.route("**/groups?with_rules=true", async (route) => {
      await held;
      await route.fulfill({ json: { groups: [] } });
    });
    await page.goto("/");
    await expect(groupsPage.addGroupButton).toHaveClass(/inactive/);
    release();
    await expect(groupsPage.addGroupButton).not.toHaveClass(/inactive/);
    await groupsPage.createGroup("kept");
    await expect(page.locator(".group-wrapper")).toHaveCount(1);
  });

  test("should enable save after switching rule type to IPv6 for IPv6 pattern", async ({
    page,
  }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);

    await groupsPage.setGroupName(0, "IPv6 Group");
    await groupsPage.setRulePattern(0, 0, "2001:db8::1");

    await expect(groupsPage.saveButton).toHaveClass(/fail/);

    await groupsPage.setRuleType(0, 0, "IPv6 subnet");

    await expect(
      (await groupsPage.getRule(0, 0)).locator(".pattern .pattern-input"),
    ).not.toHaveClass(/invalid/);
    await expect(groupsPage.saveButton).not.toHaveClass(/inactive|fail/);
  });

  // Catches a subnet rule losing its protocol and ports on the round trip.
  test("a subnet rule keeps the protocol and ports it was given", async ({ page }) => {
    let saved: unknown = null;

    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({ json: saved ?? { groups: [] } });
    });
    await page.route("**/groups?save=true", async (route) => {
      saved = route.request().postDataJSON();
      await route.fulfill({ status: 200, json: {} });
    });

    await groupsPage.goto();
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    await groupsPage.setGroupName(0, "Subnet Group");
    await groupsPage.setRulePattern(0, 0, "10.0.0.0/8");
    await groupsPage.setRuleType(0, 0, "IPv4 subnet");

    const pill = (await groupsPage.getRule(0, 0)).locator(".rule-ports");
    const editor = page.locator(".rule-ports-editor");

    await expect(pill).toHaveText("any protocol");
    await groupsPage.openRulePorts(0, 0);
    await expect(editor.getByRole("textbox", { name: "Ports" })).toHaveCount(0);

    await groupsPage.setRuleProto(0, 0, "UDP");
    await expect(pill).toHaveText("UDP · all ports");

    await groupsPage.addRulePorts(0, 0, "0");
    await expect(editor.getByRole("status")).toHaveText("A port is 1 to 65535");
    await expect(editor.locator(".port-token")).toHaveCount(0);
    await expect(pill).toHaveText("UDP · all ports");

    await groupsPage.addRulePorts(0, 0, "53,1000-2000");
    await expect(editor.locator(".port-token")).toHaveText(["53", "1000–2000"]);
    await expect(pill).toHaveText("UDP · 53, 1000–2000");
    await groupsPage.closeRulePorts();
    await expect(pill).not.toHaveClass(/invalid/);
    await expect(groupsPage.saveButton).not.toHaveClass(/inactive|fail/);

    await groupsPage.save();
    await expect(page.getByText("Saved")).toBeVisible();

    const sentRule = (saved as any).groups[0].rules[0];
    expect(sentRule.proto).toBe("udp");
    expect(sentRule.ports).toBe("53,1000-2000");

    await groupsPage.goto();
    const reloaded = await groupsPage.getRule(0, 0);
    await expect(reloaded.locator(".rule-ports")).toHaveText("UDP · 53, 1000–2000");
  });

  // Catches protocol and ports staying on a non-subnet rule, which the daemon answers with a 400.
  test("changing the type away from a subnet drops the protocol and ports", async ({ page }) => {
    let saved: any = null;
    await page.route("**/groups?save=true", async (route) => {
      saved = route.request().postDataJSON();
      await route.fulfill({ status: 200, json: {} });
    });

    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    await groupsPage.setGroupName(0, "Mixed Group");
    await groupsPage.setRulePattern(0, 0, "10.0.0.0/8");
    await groupsPage.setRuleType(0, 0, "IPv4 subnet");
    await groupsPage.setRuleProto(0, 0, "TCP");
    await groupsPage.addRulePorts(0, 0, "443");
    await expect((await groupsPage.getRule(0, 0)).locator(".rule-ports")).toHaveText("TCP · 443");
    await groupsPage.closeRulePorts();

    await groupsPage.setRuleType(0, 0, "Namespace");
    await groupsPage.setRulePattern(0, 0, "example.com");
    await expect((await groupsPage.getRule(0, 0)).locator(".rule-ports")).toHaveCount(0);

    await expect(groupsPage.saveButton).not.toHaveClass(/inactive|fail/);
    await groupsPage.save();
    await expect(page.getByText("Saved")).toBeVisible();

    const sentRule = saved.groups[0].rules[0];
    expect("proto" in sentRule).toBe(false);
    expect("ports" in sentRule).toBe(false);
  });

  // Catches a ports list without a protocol being hidden, leaving Save enabled for a 400.
  test("a ports list that arrives without a protocol is shown and holds Save", async ({ page }) => {
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "aaaaaaaa",
              name: "hand edited",
              interface: "eth0",
              enable: true,
              rules: [
                {
                  id: "bbbbbbbb",
                  name: "no protocol",
                  type: "subnet",
                  rule: "10.0.0.0/8",
                  ports: "53",
                  enable: true,
                },
              ],
            },
          ],
        },
      });
    });
    await groupsPage.goto();
    await groupsPage.expandGroup(0);

    const pill = (await groupsPage.getRule(0, 0)).locator(".rule-ports");
    await expect(pill).toBeVisible();
    await expect(pill).toHaveText("any protocol · 53");
    await expect(pill).toHaveClass(/invalid/);

    await groupsPage.setGroupName(0, "hand edited twice");
    await expect(groupsPage.saveButton).toHaveClass(/fail/);

    await groupsPage.setRuleProto(0, 0, "UDP");
    await expect(pill).toHaveText("UDP · 53");
    await expect(pill).not.toHaveClass(/invalid/);
    await expect(groupsPage.saveButton).not.toHaveClass(/inactive|fail/);
  });

  // Catches an invalid rule on an unrendered page not holding Save; only a check over the data can.
  test("a protocol on a rule that cannot carry one holds Save from another page", async ({
    page,
  }) => {
    const rules = Array.from({ length: 60 }, (_, i) => ({
      id: (10000000 + i).toString(),
      name: `rule ${i}`,
      type: "domain",
      rule: `r${i}.example.com`,
      enable: true,
      ...(i === 55 ? { proto: "tcp" } : {}),
    }));

    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "aaaaaaaa",
              name: "big",
              interface: "eth0",
              enable: true,
              rules,
            },
          ],
        },
      });
    });
    await groupsPage.goto();
    await groupsPage.expandGroup(0);

    await expect(page.locator(".rule")).toHaveCount(50);
    await expect(page.locator(".rule .invalid")).toHaveCount(0);

    await groupsPage.setGroupName(0, "big and edited");
    await expect(groupsPage.saveButton).toHaveClass(/fail/);
  });

  test("should delete a rule", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    await groupsPage.addRuleToGroup(0);
    await expect(page.locator(".rule")).toHaveCount(2);

    await groupsPage.deleteRule(0, 0);
    await expect(page.locator(".rule")).toHaveCount(1);
  });

  test("should delete a group", async ({ page }) => {
    await groupsPage.createGroup();
    await expect(page.locator(".group-wrapper")).toHaveCount(1);

    await groupsPage.deleteGroup(0);
    await answerConfirm(page, true);
    await expect(page.locator(".group-wrapper")).toHaveCount(0);
  });

  test("should sort rules", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    await groupsPage.setRulePattern(0, 0, "b.example.com");

    await groupsPage.addRuleToGroup(0);
    await groupsPage.setRulePattern(0, 0, "a.example.com");

    const rules = page.locator(".rule");
    await expect(rules.nth(0).locator(".pattern-input")).toHaveValue("a.example.com");
    await expect(rules.nth(1).locator(".pattern-input")).toHaveValue("b.example.com");

    const patternHeader = page
      .locator(".group-rules-header-column.clickable")
      .filter({ hasText: "Pattern" });
    await patternHeader.click();

    await expect(rules.nth(0).locator(".pattern-input")).toHaveValue("a.example.com");
    await expect(rules.nth(1).locator(".pattern-input")).toHaveValue("b.example.com");

    await patternHeader.click();
    await expect(rules.nth(0).locator(".pattern-input")).toHaveValue("b.example.com");
    await expect(rules.nth(1).locator(".pattern-input")).toHaveValue("a.example.com");
  });

  test("should keep a newly added rule after cycling sort states", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    await groupsPage.setGroupName(0, "Sorted Group");

    await groupsPage.setRulePattern(0, 0, "b.example.com");

    await groupsPage.addRuleToGroup(0);
    await groupsPage.setRulePattern(0, 0, "a.example.com");

    const patternHeader = page
      .locator(".group-rules-header-column.clickable")
      .filter({ hasText: "Pattern" });

    await patternHeader.click();

    await groupsPage.addRuleToGroup(0);
    await groupsPage.setRulePattern(0, 0, "c.example.com");

    await expect(page.locator(".rule")).toHaveCount(3);

    await patternHeader.click();
    await patternHeader.click();

    await expect(page.locator(".rule")).toHaveCount(3);
    const rulePatterns = await page
      .locator(".rule .pattern-input")
      .evaluateAll((elements) => elements.map((element) => (element as HTMLInputElement).value));
    const patterns = ["a.example.com", "b.example.com", "c.example.com"];
    expect(rulePatterns).toHaveLength(3);
    expect(rulePatterns).toEqual(expect.arrayContaining(patterns));

    let savedRules: Record<string, unknown>[] = [];
    await page.route("**/groups?save=true", async (route) => {
      const body = route.request().postDataJSON();
      expect(body.groups).toHaveLength(1);
      expect(body.groups[0].rules).toHaveLength(3);
      savedRules = body.groups[0].rules;
      await route.fulfill({ status: 200, json: {} });
    });

    await expect(groupsPage.saveButton).not.toHaveClass(/inactive|fail/);
    await groupsPage.save();

    await expect(page.getByText("Saved")).toBeVisible();
    expect(savedRules.map((rule) => rule.rule)).toEqual(expect.arrayContaining(patterns));
    expect(savedRules.filter((rule) => "name" in rule)).toEqual([]);
  });

  test("should toggle group enabled state", async ({ page }) => {
    await groupsPage.createGroup();
    const groupHeader = await groupsPage.getGroupHeader(0);
    const toggle = groupHeader.locator(".enable-group");

    await expect(toggle).toHaveAttribute("aria-checked", "true");

    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-checked", "false");
  });

  test("should collapse and expand group", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    await expect(page.locator(".group-rules")).toBeVisible();

    const groupHeader = await groupsPage.getGroupHeader(0);
    const collapseTrigger = groupHeader.locator("[data-collapsible-trigger]");

    await collapseTrigger.click();
    await expect(page.locator(".group-rules")).toBeHidden();

    await collapseTrigger.click();
    await expect(page.locator(".group-rules")).toBeVisible();
  });

  // Catches the toolbar toggle missing a group, or reaching a group the search hides.
  test("the toolbar toggle opens and closes every shown group, and only those", async ({
    page,
  }) => {
    const group = (id: string, name: string) => ({
      id,
      name,
      interface: "eth0",
      enable: true,
      rules: [
        { id: `${id.slice(0, 7)}f`, name: "", type: "domain", rule: `${name}.com`, enable: true },
      ],
    });
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            group("aaaaaaa1", "alpha"),
            group("aaaaaaa2", "beta"),
            group("aaaaaaa3", "gamma"),
          ],
        },
      });
    });
    await groupsPage.goto();

    const toggle = page.locator("#toggle-groups");
    const trigger = (id: string) =>
      page.locator(`.group[data-uuid="${id}"] [data-collapsible-trigger]`);
    const ids = ["aaaaaaa1", "aaaaaaa2", "aaaaaaa3"];

    await groupsPage.expandGroup(1);
    await toggle.click();
    for (const id of ids) await expect(trigger(id)).toHaveAttribute("aria-expanded", "false");

    await toggle.click();
    for (const id of ids) await expect(trigger(id)).toHaveAttribute("aria-expanded", "true");

    await toggle.click();
    await groupsPage.expandGroup(0);
    await groupsPage.search("beta");
    await expect(page.locator(".group:visible")).toHaveCount(1);
    await expect(toggle).toHaveAttribute("aria-label", "Expand All");
    await toggle.click();
    await expect(trigger("aaaaaaa2")).toHaveAttribute("aria-expanded", "true");

    await groupsPage.searchInput.fill("");
    await expect(trigger("aaaaaaa1")).toHaveAttribute("aria-expanded", "true");
    await expect(trigger("aaaaaaa3")).toHaveAttribute("aria-expanded", "false");
  });

  test("should paginate rules", async ({ page }) => {
    const rules = Array.from({ length: 60 }, (_, i) => ({
      id: (10000000 + i).toString(), // 8 digit decimal string is mostly valid? Hex is safer.
      name: `Rule ${i}`,
      rule: `rule${i}`,
      type: "namespace",
      enable: true,
    }));

    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "12345678",
              name: "Large Group",
              rules: rules,
              enable: true,
              interface: "",
            },
          ],
        },
      });
    });

    await groupsPage.goto();

    await expect(page.locator(".group-rules-header-column.total")).toHaveText("#60");

    const groupRules = page.locator(".group-rules");
    if (!(await groupRules.isVisible())) {
      await page
        .locator(".group-wrapper")
        .first()
        .locator("[data-collapsible-trigger]:visible")
        .first()
        .click();
    }
    await expect(groupRules).toBeVisible();

    await expect(page.locator(".rule")).toHaveCount(50);

    await expect(page.getByTitle("Next Page")).toBeVisible();

    await page.getByTitle("Next Page").click();

    await expect(page.locator(".rule")).toHaveCount(10);
  });

  test("should toggle rule enabled state", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    const rule = await groupsPage.getRule(0, 0);
    const toggle = rule.locator('.actions button[role="switch"]');

    await expect(toggle).toHaveAttribute("aria-checked", "true");

    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-checked", "false");
  });
});

test.describe("Groups layout", () => {
  const rule = (id: string, type: string, text: string, extra: Record<string, unknown> = {}) => ({
    id,
    name: "",
    type,
    rule: text,
    enable: true,
    ...extra,
  });

  async function openGroups(
    page: Page,
    width: number,
    groups: unknown[],
    {
      locale = "ru",
      expand = true,
      interfaces = ["eth0", "wlan0"] as unknown[],
    }: { locale?: string; expand?: boolean; interfaces?: unknown[] } = {},
  ) {
    await page.setViewportSize({ width, height: 900 });
    await signedIn(page);
    await page.addInitScript(
      (value) => localStorage.setItem("locale", JSON.stringify({ value })),
      locale,
    );
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({ json: { groups } });
    });
    await page.route("**/interfaces", async (route) => {
      await route.fulfill({ json: { interfaces } });
    });
    await page.route(/\/list\/rules(\?.*)?$/, async (route) => {
      const rules = [rule("ccccccc1", "domain", "google.com"), rule("ccccccc2", "domain", "x.com")];
      await route.fulfill({ json: { total: 2, matched: 2, offset: 0, rules } });
    });
    await page.goto("/");
    await expect(page.locator(".group-wrapper")).toHaveCount(groups.length);
    if (!expand) return;
    for (const trigger of await page.locator("[data-collapsible-trigger]").all()) {
      if ((await trigger.getAttribute("aria-expanded")) !== "true") await trigger.click();
    }
  }

  const ruleGroup = {
    id: "aaaaaaa1",
    name: "Telegram",
    interface: "eth0",
    enable: true,
    rules: [
      rule("bbbbbbb1", "namespace", "oaiusercontent.com", { comment: "chat" }),
      rule("bbbbbbb2", "subnet", "149.154.160.0/20", { proto: "udp", ports: "596-599,1400" }),
      rule("bbbbbbb3", "subnet", "91.108.4.0/22"),
    ],
  };

  for (const width of [768, 1024]) {
    // Catches the ports chip shrinking before the pattern field, so "any protocol" ends in an ellipsis.
    test(`at ${width} the ports chip shows its whole summary`, async ({ page }) => {
      await openGroups(page, width, [ruleGroup]);
      const chips = page.locator(".rule-ports");
      await expect(chips).toHaveCount(2);
      const cut = await page.$$eval(".rule-ports-summary", (els) =>
        els.map((e) => e.scrollWidth > e.clientWidth),
      );
      expect(cut).toEqual([false, false]);
      await expect(chips.first()).toHaveAttribute("title", "UDP · 596–599, 1400");
    });
  }

  for (const [width, locale] of [
    [360, "ru"],
    [390, "ru"],
    [360, "en"],
  ] as const) {
    // Catches the actions column eating the pattern field on a phone, and the comment icon floating between the lines.
    test(`at ${width} ${locale} the pattern gets the row's width and the comment sits with the actions`, async ({
      page,
    }) => {
      await openGroups(page, width, [ruleGroup], { locale });
      await expect(page.locator(".rule")).toHaveCount(3);
      const boxes = await page.$$eval(".rule", (rules) =>
        rules.map((r) => {
          const box = (s: string) => (r.querySelector(s) as HTMLElement).getBoundingClientRect();
          const label = r.querySelector(".pattern .label") as HTMLElement;
          const input = r.querySelector(".pattern-input") as HTMLInputElement;
          const type = r.querySelector(".type .selected-value") as HTMLElement;
          return {
            typeCut: type.scrollWidth > type.clientWidth,
            row: box(".rule-row").width,
            input: box(".pattern-input"),
            inputCut: input.scrollWidth > input.clientWidth,
            labelCut: label.scrollWidth > label.clientWidth,
            label: box(".pattern .label"),
            type: box(".type"),
            pattern: box(".pattern"),
            comment: box(".rule-comment"),
            switch: box('[role="switch"]'),
          };
        }),
      );
      for (const b of boxes) {
        expect(b.input.width).toBeGreaterThan(b.row * 0.6);
        expect(b.inputCut).toBe(false);
        expect(b.typeCut).toBe(false);
        expect(b.labelCut).toBe(false);
        expect(b.label.right).toBeLessThanOrEqual(b.input.left + 0.5);
        const mid = b.comment.top + b.comment.height / 2;
        expect(mid).toBeGreaterThanOrEqual(b.type.top);
        expect(mid).toBeLessThanOrEqual(b.type.bottom);
        expect(Math.abs(mid - (b.switch.top + b.switch.height / 2))).toBeLessThan(2);
        expect(b.comment.bottom).toBeLessThanOrEqual(b.pattern.top + 0.5);
      }
    });
  }

  // Catches the duplicate warning taking the type line's width on a phone, cutting "Namespace".
  test("at 360 a rule with a duplicate warning keeps its type whole", async ({ page }) => {
    const twin = (id: string, name: string, ruleId: string) => ({
      id,
      name,
      interface: "eth0",
      enable: true,
      devices: { allow: [], deny: [] },
      rules: [rule(ruleId, "namespace", "youtube.com")],
    });
    await openGroups(page, 360, [
      twin("aaaaaaa5", "One", "ccccccc1"),
      twin("aaaaaaa6", "Two", "ccccccc2"),
    ]);
    const row = page.locator(".group-wrapper").nth(1).locator(".rule").first();
    await expect(row.locator(".duplicate-indicator")).toBeVisible();
    const m = await row.evaluate((r) => {
      const box = (s: string) => (r.querySelector(s) as HTMLElement).getBoundingClientRect();
      const type = r.querySelector(".type .selected-value") as HTMLElement;
      const input = r.querySelector(".pattern-input") as HTMLElement;
      return {
        typeCut: type.scrollWidth > type.clientWidth,
        icon: box(".duplicate-indicator"),
        pattern: box(".pattern"),
        input: input.getBoundingClientRect(),
      };
    });
    expect(m.typeCut).toBe(false);
    const mid = m.icon.top + m.icon.height / 2;
    expect(mid).toBeGreaterThanOrEqual(m.pattern.top);
    expect(mid).toBeLessThanOrEqual(m.pattern.bottom);
    expect(m.icon.left).toBeGreaterThanOrEqual(m.input.right - 0.5);
  });

  const listGroup = {
    id: "aaaaaaa2",
    name: "Bad Bad Services",
    interface: "eth0",
    enable: true,
    rules: [],
    list: {
      url: "https://services.should.be.blocked.example/list.txt",
      interval: 86400,
      lastUpdate: 1700000000,
      sync: { state: "idle", error: "", lastCheck: 1800000000 },
      rulesTotal: 2,
    },
  };

  for (const width of [360, 768, 1440]) {
    // Catches the list sections' headings and rows sitting flush with the card edge, or a heading torn in two.
    test(`at ${width} a list group's headings and rows keep an inset`, async ({ page }) => {
      await openGroups(page, width, [listGroup]);
      await expect(page.locator(".list-rule")).toHaveCount(2);
      const m = await page.evaluate(() => {
        const card = document.querySelector(".group") as HTMLElement;
        const left = card.getBoundingClientRect().left;
        const heads = [...card.querySelectorAll(".rules-section-header h3")].map((h) => {
          const range = document.createRange();
          range.selectNodeContents(h);
          const tops = new Set([...range.getClientRects()].map((r) => Math.round(r.top)));
          return { inset: h.getBoundingClientRect().left - left, lines: tops.size };
        });
        const firstText = [...card.querySelectorAll(".list-rule")].map((row) => {
          const label = row.querySelector(".list-rule-pattern .label") as HTMLElement;
          const shown = getComputedStyle(label).display !== "none";
          const text = document.createRange();
          text.selectNodeContents(
            shown ? label : (row.querySelector(".list-rule-number") as HTMLElement),
          );
          return {
            inset: text.getBoundingClientRect().left - left,
            cut: shown && label.scrollWidth > label.clientWidth,
          };
        });
        return { heads, firstText };
      });
      expect(m.heads).toHaveLength(2);
      for (const h of m.heads) {
        expect(h.inset).toBeGreaterThanOrEqual(8);
        expect(h.lines).toBe(1);
      }
      for (const r of m.firstText) {
        expect(r.inset).toBeGreaterThanOrEqual(8);
        expect(r.cut).toBe(false);
      }
    });
  }

  for (const width of [768, 1440]) {
    // Catches the type select centred in its column, so types of different lengths start at different places, and headers off their values.
    test(`at ${width} rule columns line up with their headers`, async ({ page }) => {
      await openGroups(page, width, [
        {
          ...ruleGroup,
          rules: [...ruleGroup.rules, rule("bbbbbbb4", "wildcard", "*.youtube-nocookie.com")],
        },
        listGroup,
      ]);
      await expect(page.locator(".list-rule")).toHaveCount(2);
      const m = await page.evaluate(() => {
        const textLeft = (el: Element) => {
          const node = [...el.childNodes].find((n) => n.nodeType === 3 && n.textContent!.trim());
          const range = document.createRange();
          range.selectNodeContents(node ?? el);
          return range.getBoundingClientRect().left;
        };
        const head = (sel: string, i: number) =>
          textLeft(document.querySelectorAll(sel)[i] as Element);
        return {
          types: [...document.querySelectorAll(".rule .type .selected-value")].map(textLeft),
          patterns: [...document.querySelectorAll(".rule .pattern-input")].map(
            (e) => e.getBoundingClientRect().left,
          ),
          typeHead: head(".group-rules-header-column", 1),
          patternHead: head(".group-rules-header-column", 2),
          listTypes: [...document.querySelectorAll(".list-rule-type .selected-value")].map(
            textLeft,
          ),
          listPatterns: [...document.querySelectorAll(".list-rule-value")].map(textLeft),
          listTypeHead: head(".list-rules-header-column", 1),
          listPatternHead: head(".list-rules-header-column", 2),
        };
      });
      for (const x of m.types) expect(Math.abs(x - m.typeHead)).toBeLessThan(2);
      for (const x of m.patterns) expect(Math.abs(x - m.patternHead)).toBeLessThan(2);
      for (const x of m.listTypes) expect(Math.abs(x - m.listTypeHead)).toBeLessThan(2);
      for (const x of m.listPatterns) expect(Math.abs(x - m.listPatternHead)).toBeLessThan(2);
    });
  }

  for (const width of [768, 1024, 1440]) {
    // Catches the interface select hugging its label, so the card's columns move with the interface name, and the duplicate mark floating far from the name.
    test(`at ${width} the group header columns stay put`, async ({ page }) => {
      const group = (id: string, name: string, iface: string) => ({
        id,
        name,
        interface: iface,
        enable: true,
        devices: { allow: [], deny: [] },
        rules: [rule(`b${id.slice(1)}`, "namespace", "same.example.com")],
      });
      await openGroups(
        page,
        width,
        [group("aaaaaaa1", "YouTube", "nwg0"), group("aaaaaaa2", "Telegram", "nwg1")],
        {
          expand: false,
          interfaces: [
            { id: "nwg0", name: "WARP", role: "tunnel" },
            { id: "nwg1", name: "AmneziaWG NL", role: "tunnel" },
          ],
        },
      );
      await expect(page.locator(".group-duplicate-menu-trigger")).toHaveCount(1);
      const m = await page.$$eval(".group-header", (heads) =>
        heads.map((h) => {
          const range = document.createRange();
          range.selectNodeContents(h.querySelector(".iface-select .selected-value")!);
          const mirror = h.querySelector(".name-mirror") as HTMLElement;
          const text = document.createRange();
          text.selectNodeContents(mirror);
          const input = h.querySelector("input.group-name") as HTMLInputElement;
          const ctx = document.createElement("canvas").getContext("2d")!;
          const cs = getComputedStyle(input);
          ctx.font = `${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
          const warn = h.querySelector(".group-duplicate-menu-trigger");
          return {
            text: range.toString(),
            label: range.getBoundingClientRect().left,
            open: h.querySelector(".iface-select .selected-open")!.getBoundingClientRect().left,
            nameEnd: input.getBoundingClientRect().left + ctx.measureText(input.value).width,
            warn: warn ? warn.getBoundingClientRect().left : null,
          };
        }),
      );
      expect(m).toHaveLength(2);
      expect(m.map((x) => x.text.trim())).toEqual(["WARP", "AmneziaWG NL"]);
      expect(Math.abs(m[0].label - m[1].label)).toBeLessThan(1);
      expect(Math.abs(m[0].open - m[1].open)).toBeLessThan(1);
      const marked = m.find((x) => x.warn !== null)!;
      expect(marked.warn! - marked.nameEnd).toBeGreaterThanOrEqual(0);
      expect(marked.warn! - marked.nameEnd).toBeLessThan(40);
    });
  }

  // Catches a match deep in a long pattern left behind the ellipsis, also once the field narrows after the search.
  test("a match deep in a long pattern is scrolled into view at any width", async ({ page }) => {
    const pattern =
      "^([a-z0-9-]+\\.)*(cdn-assets-prefix|static-content-mirror|googlevideo|youtube)\\.(com|net)$";
    await openGroups(
      page,
      1440,
      [{ ...ruleGroup, rules: [...ruleGroup.rules, rule("bbbbbbb9", "regex", pattern)] }],
      {
        expand: false,
      },
    );
    await new GroupsPage(page).search("youtube");
    await page.locator("[data-collapsible-trigger]").click();
    const markShown = () =>
      page.evaluate(() => {
        const overlay = document.querySelector(
          ".rule[data-uuid='bbbbbbb9'] .search-highlight-overlay",
        )!;
        const m = overlay.querySelector("mark")!.getBoundingClientRect();
        const o = overlay.getBoundingClientRect();
        return o.width > 0 && m.left >= o.left - 0.5 && m.right <= o.right + 0.5;
      });
    const mark = page.locator(".rule[data-uuid='bbbbbbb9'] .search-highlight-overlay mark");
    await expect(mark).toHaveCount(1);
    await expect.poll(markShown).toBe(true);
    for (const width of [768, 360]) {
      await page.setViewportSize({ width, height: 900 });
      await expect.poll(markShown).toBe(true);
    }
  });

  for (const width of [360, 390]) {
    // Catches the block answer, the interface select and the list's update select left under 32 px to tap on a phone.
    test(`at ${width} the header's small controls are 32 px to tap`, async ({ page }) => {
      await openGroups(page, width, [
        { ...ruleGroup, id: "aaaaaaa3", interface: "block", block: "nxdomain" },
        listGroup,
      ]);
      const reach = (sel: string) =>
        page.$$eval(sel, (els) =>
          els.map((el) => {
            const r = el.getBoundingClientRect();
            const x = r.left + Math.min(r.width / 2, 12);
            let n = 0;
            for (let y = Math.floor(r.top) - 24; y <= Math.ceil(r.bottom) + 24; y++) {
              const hit = document.elementFromPoint(x, y);
              if (hit && (hit === el || el.contains(hit))) n++;
            }
            return n;
          }),
        );
      for (const sel of [
        ".block-answer",
        ".group-header .iface-select [data-select-trigger]",
        ".update-interval [data-select-trigger]",
      ]) {
        const heights = await reach(sel);
        expect(heights.length, sel).toBeGreaterThan(0);
        for (const h of heights) expect(h, sel).toBeGreaterThanOrEqual(32);
      }
    });
  }

  for (const [width, locale] of [
    [360, "ru"],
    [390, "ru"],
    [360, "en"],
  ] as const) {
    // Catches the order hint leaving its last word alone on a line.
    test(`at ${width} ${locale} the order hint ends with no lone word`, async ({ page }) => {
      await openGroups(page, width, [], { locale, expand: false });
      const tops = await page.locator(".order-hint").evaluate((el) => {
        const node = el.firstChild!;
        const text = node.textContent!;
        const out: number[] = [];
        let at = 0;
        for (const word of text.split(/[ ]+/)) {
          const start = text.indexOf(word, at);
          at = start + word.length;
          if (!word.trim()) continue;
          const range = document.createRange();
          range.setStart(node, start);
          range.setEnd(node, at);
          out.push(Math.round(range.getBoundingClientRect().top));
        }
        return out;
      });
      expect(tops.length).toBeGreaterThan(2);
      expect(tops.at(-1)).toBe(tops.at(-2));
    });
  }
});
