import { expect, test } from "@playwright/test";

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

    expect(saveRequestReceived).toBe(true);

    await expect(page.getByText("Saved")).toBeVisible();
    expect(saveRequestReceived).toBe(true);
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

    const rule = await groupsPage.getRule(0, 0);
    const ports = rule.locator(".ports-input");

    await expect(ports).toBeDisabled();

    await groupsPage.setRuleProto(0, 0, "UDP");
    await expect(ports).toBeEnabled();

    await groupsPage.setRulePorts(0, 0, "53,");
    await expect(ports).toHaveClass(/invalid/);
    await expect(groupsPage.saveButton).toHaveClass(/fail/);

    await groupsPage.setRulePorts(0, 0, "53,1000-2000");
    await expect(ports).not.toHaveClass(/invalid/);
    await expect(groupsPage.saveButton).not.toHaveClass(/inactive|fail/);

    await groupsPage.save();
    await expect(page.getByText("Saved")).toBeVisible();

    const sentRule = (saved as any).groups[0].rules[0];
    expect(sentRule.proto).toBe("udp");
    expect(sentRule.ports).toBe("53,1000-2000");

    await groupsPage.goto();
    const reloaded = await groupsPage.getRule(0, 0);
    await expect(reloaded.locator(".pattern [data-select-trigger]")).toHaveText(/UDP/);
    await expect(reloaded.locator(".ports-input")).toHaveValue("53,1000-2000");
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
    await groupsPage.setRulePorts(0, 0, "443");

    await groupsPage.setRuleType(0, 0, "Namespace");
    await groupsPage.setRulePattern(0, 0, "example.com");
    await expect((await groupsPage.getRule(0, 0)).locator(".ports-input")).toHaveCount(0);

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

    const ports = (await groupsPage.getRule(0, 0)).locator(".ports-input");
    await expect(ports).toBeVisible();
    await expect(ports).toHaveValue("53");
    await expect(ports).toBeEnabled();
    await expect(ports).toHaveClass(/invalid/);

    await groupsPage.setGroupName(0, "hand edited twice");
    await expect(groupsPage.saveButton).toHaveClass(/fail/);

    await groupsPage.setRuleProto(0, 0, "UDP");
    await expect(ports).not.toHaveClass(/invalid/);
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
    await expect(page.locator(".rule input.invalid")).toHaveCount(0);

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

    page.on("dialog", (dialog) => dialog.accept());

    await groupsPage.deleteGroup(0);
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
      await page.locator("[data-collapsible-trigger]").first().click();
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
