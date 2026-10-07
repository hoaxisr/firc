import { expect, type Locator, type Page } from "@playwright/test";

export class GroupsPage {
  readonly page: Page;
  readonly saveButton: Locator;
  readonly groupList: Locator;
  readonly addGroupButton: Locator;
  readonly searchContainer: Locator;
  readonly searchInput: Locator;

  constructor(page: Page) {
    this.page = page;
    this.saveButton = page.locator("#save-changes");
    this.groupList = page.locator(".group-list");
    this.addGroupButton = page.locator('[data-value="Add Group"]').locator("button");
    this.searchContainer = page.locator(
      '[data-tabs-content][data-state="active"] .group-controls-search .search-container',
    );
    this.searchInput = page.locator(
      '[data-tabs-content][data-state="active"] .group-controls-search .search-input',
    );
  }

  async goto() {
    await this.page.goto("/");
    await expect(this.addGroupButton).not.toHaveClass(/inactive/);
  }

  async search(query: string) {
    await this.searchContainer.click();
    await this.searchInput.fill(query);
  }

  // A server-loaded group renders collapsed, so its rows have no box to click; a new group lands at the END of the list.
  async createGroup(name = "") {
    await this.addGroupButton.click();
    const dialog = this.page.getByRole("dialog");
    await dialog.locator("#gd-name").fill(name);
    await dialog.getByRole("button", { name: "Create", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
  }

  async openGroupSettings(index: number) {
    const header = await this.getGroupHeader(index);
    const settingsBtn = header.locator('[data-value="Group Settings"]').locator("button");
    await settingsBtn.click();
    await this.page.getByRole("dialog").waitFor({ state: "visible" });
  }

  async getGroup(index: number) {
    return this.page.locator(`.group-wrapper`).nth(index);
  }

  async getGroupHeader(index: number) {
    return this.page.locator(`.group-header[data-group-index="${index}"]`);
  }

  async setGroupName(index: number, name: string) {
    const header = await this.getGroupHeader(index);
    const input = header.locator("input.group-name");
    await input.fill(name);
  }

  async addRuleToGroup(groupIndex: number) {
    const header = await this.getGroupHeader(groupIndex);
    const addRuleBtn = header.locator('[data-value="Add Rule"]').locator("button");
    await addRuleBtn.click();
  }

  async getRule(groupIndex: number, ruleIndex: number) {
    const group = await this.getGroup(groupIndex);
    return group.locator(`.rule[data-index="${ruleIndex}"]`);
  }

  async setRulePattern(groupIndex: number, ruleIndex: number, pattern: string) {
    const rule = await this.getRule(groupIndex, ruleIndex);
    await rule.locator(".pattern .pattern-input").fill(pattern);
  }

  async expandGroup(index: number) {
    const header = await this.getGroupHeader(index);
    await header.locator("[data-collapsible-trigger]").click();
  }

  async setRuleProto(groupIndex: number, ruleIndex: number, protoLabel: string) {
    const rule = await this.getRule(groupIndex, ruleIndex);
    await rule.locator(".pattern [data-select-trigger]").click();
    await this.page.getByRole("option", { name: protoLabel, exact: true }).click();
  }

  async setRulePorts(groupIndex: number, ruleIndex: number, ports: string) {
    const rule = await this.getRule(groupIndex, ruleIndex);
    await rule.locator(".ports-input").fill(ports);
  }

  async setRuleType(groupIndex: number, ruleIndex: number, typeLabel: string) {
    const rule = await this.getRule(groupIndex, ruleIndex);
    const trigger = rule.locator(".type [data-select-trigger]");
    await trigger.click();
    await this.page.getByRole("option", { name: typeLabel }).click();
  }

  async save() {
    await this.saveButton.click();
  }

  async deleteGroup(index: number) {
    const header = await this.getGroupHeader(index);
    const deleteBtn = header.locator('[data-value="Delete Group"]').locator("button");
    await deleteBtn.click();
  }

  async deleteRule(groupIndex: number, ruleIndex: number) {
    const rule = await this.getRule(groupIndex, ruleIndex);
    const deleteBtn = rule.locator('[data-value="Delete Rule"]').locator("button");
    await deleteBtn.click();
  }
}
