import { expect, test } from "@playwright/test";

import { answerConfirm } from "./pages/confirm";
import { state, stubDaemon, tunnel, TunnelsPage } from "./pages/TunnelsPage";

const SUB = {
  id: "s1",
  kind: "subscription",
  name: "Provider",
  url: "https://sub.example/feed",
  interval: 21600,
};
const LINK = { id: "l1", kind: "link", link: "vless://u@h.example:443#Solo" };

async function saved(page: import("@playwright/test").Page, extra = {}, rows = 3) {
  const daemon = await stubDaemon(page, {
    tunnels: [tunnel("a", "tunvless0", { sources: [SUB, LINK], ...extra })],
    states: [state("a", "tunvless0")],
  });
  const tunnels = new TunnelsPage(page);
  await tunnels.open();
  await tunnels.expand("a");
  await expect(tunnels.nodeRows("a")).toHaveCount(rows);
  return { daemon, tunnels };
}

test.describe("Tunnel editor", () => {
  // Catches a preview request per keystroke, or the match count never shown.
  test("typing a filter asks for one preview after the debounce and shows the count", async ({
    page,
  }) => {
    await page.clock.install();
    const { daemon, tunnels } = await saved(page);
    await expect(tunnels.card("a")).toContainText("3 of 3 match");
    const before = daemon.previews.length;

    await tunnels.filter("a").pressSequentially("B", { delay: 0 });
    await tunnels.filter("a").pressSequentially("|C", { delay: 0 });
    await page.clock.runFor(400);
    await expect(tunnels.card("a")).toContainText("2 of 3 match");
    await page.clock.runFor(5000);
    await tunnels.settle();

    expect(daemon.previews.length).toBe(before + 1);
    expect(daemon.previews.at(-1)?.tunnel.filter).toBe("B|C");
    await expect(tunnels.nodeNames("a")).toHaveText(["B", "C"]);
  });

  // Catches the exclude switch not reaching `exclude`, or excluding the wrong key.
  test("the node switch writes exclude into the save", async ({ page }) => {
    const { daemon, tunnels } = await saved(page);
    await tunnels.nodeRows("a").nth(1).getByRole("switch").click();
    await expect(tunnels.nodeRows("a").nth(1)).toContainText("excluded by hand");
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].exclude).toEqual(["0000000a:B"]);

    await tunnels.nodeRows("a").nth(1).getByRole("switch").click();
    await tunnels.save.click();
    await expect.poll(() => daemon.puts.length).toBe(2);
    expect(daemon.puts[1].tunnels[0].exclude).toEqual([]);
  });

  // Catches a drop writing only the visible keys, or the hidden ones landing before them.
  test("dragging B above A writes order with the filtered-out key kept last", async ({ page }) => {
    const { daemon, tunnels } = await saved(
      page,
      { filter: "^[AB]$", order: ["0000000a:C", "0000000a:A", "0000000a:B"] },
      2,
    );
    await expect(tunnels.nodeNames("a")).toHaveText(["A", "B"]);

    await tunnels.drag(tunnels.nodeRows("a").nth(1), tunnels.nodeRows("a").nth(0), "before");
    await expect(tunnels.nodeNames("a")).toHaveText(["B", "A"]);
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();

    expect(daemon.puts[0].tunnels[0].order).toEqual(["0000000a:B", "0000000a:A", "0000000a:C"]);
  });

  // Catches the column or "By latency" reading the handshake, which ranks a near relay first.
  test("checking nodes shows first byte and to the node, and By latency sorts by first byte", async ({
    page,
  }) => {
    const { daemon, tunnels } = await saved(page);
    daemon.probeAnswer = (_body, route) =>
      route.fulfill({
        json: {
          nodes: [
            { key: "0000000a:A", ok: true, handshakeMs: 18, firstByteMs: 1400, why: "" },
            { key: "0000000a:B", ok: false, handshakeMs: null, firstByteMs: null, why: "timeout" },
            { key: "0000000a:C", ok: true, handshakeMs: 113, firstByteMs: 300, why: "" },
          ],
        },
      });
    const card = tunnels.card("a");
    await card.locator("button", { hasText: "Check nodes" }).click();
    await expect(tunnels.nodeRows("a").nth(0).locator(".lat")).toHaveText(
      /^1400 ms\s*to the node 18 ms$/,
    );
    await expect(tunnels.nodeRows("a").nth(2).locator(".lat")).toHaveText(
      /^300 ms\s*to the node 113 ms$/,
    );
    expect(daemon.probes[0].tunnel.id).toBe("a");

    await card.locator("button", { hasText: "By latency" }).click();
    await expect(tunnels.nodeNames("a")).toHaveText(["C", "A", "B"]);
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].order).toEqual(["0000000a:C", "0000000a:A", "0000000a:B"]);
  });

  // Catches the second number shown without the words that tell it from the first, at any width.
  test("the to-the-node number explains both numbers on a phone too", async ({ page }) => {
    const { daemon, tunnels } = await saved(page);
    await page.setViewportSize({ width: 390, height: 844 });
    daemon.probeAnswer = (_body, route) =>
      route.fulfill({
        json: {
          nodes: [{ key: "0000000a:A", ok: true, handshakeMs: 18, firstByteMs: 1400, why: "" }],
        },
      });
    await tunnels.card("a").locator("button", { hasText: "Check nodes" }).click();
    await tunnels.nodeRows("a").nth(0).getByText("to the node 18 ms").hover();
    const bubble = page.locator("#global-tooltip");
    await expect(bubble).toBeVisible();
    await expect(bubble).toContainText("first byte through the node");
    await expect(bubble).toContainText("nearby relay");
  });

  // Catches the reset leaving the saved order in the save, or the rows in the sorted order.
  test("As in the subscription empties order and puts the rows back in source order", async ({
    page,
  }) => {
    const { daemon, tunnels } = await saved(page, {
      order: ["0000000a:C", "0000000a:B", "0000000a:A"],
    });
    await expect(tunnels.nodeNames("a")).toHaveText(["C", "B", "A"]);
    const reset = tunnels.card("a").locator("button", { hasText: "As in the subscription" });
    await expect(reset).not.toHaveClass(/inactive/);

    await reset.click();
    await expect(tunnels.nodeNames("a")).toHaveText(["A", "B", "C"]);
    await expect(reset).toHaveClass(/inactive/);
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].order).toEqual([]);
  });

  // Catches the reset offered when there is no saved order to drop.
  test("As in the subscription is inactive while the order is empty", async ({ page }) => {
    const { tunnels } = await saved(page);
    const reset = tunnels.card("a").locator("button", { hasText: "As in the subscription" });
    await expect(reset).toHaveClass(/inactive/);
  });

  // Catches a repeated key from the daemon blanking the section or showing a node twice.
  test("a preview repeating a key lists each node once", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const row = (key: string, name: string, extra = {}) => ({
      key,
      name,
      source: "Provider",
      excluded: false,
      isNew: false,
      missing: false,
      overCap: false,
      skipReason: "",
      ...extra,
    });
    const daemon = await stubDaemon(page, {
      tunnels: [tunnel("a", "tunvless0", { sources: [SUB] })],
      states: [state("a", "tunvless0")],
    });
    daemon.previewAnswer = (_body, route) =>
      route.fulfill({
        json: {
          matched: 3,
          total: 3,
          subscriptions: [],
          nodes: [
            row("0000000a:C", "C"),
            row("0000000a:A", "A", { missing: true }),
            row("0000000a:A", "A", { isNew: true }),
            row("0000000a:B", "B"),
          ],
        },
      });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.expand("a");
    await expect(tunnels.nodeNames("a")).toHaveText(["C", "A", "B"]);
    await expect(tunnels.nodeRows("a").nth(1)).toContainText("not in the sources");
    expect(errors).toEqual([]);
  });

  // Catches the list blanking or repeating rows after a latency sort is saved and reopened.
  test("a saved latency order lists every node once after collapse and expand", async ({
    page,
  }) => {
    const { daemon, tunnels } = await saved(page);
    daemon.probeAnswer = (_body, route) =>
      route.fulfill({
        json: {
          nodes: [
            { key: "0000000a:A", ok: true, handshakeMs: 10, firstByteMs: 300, why: "" },
            { key: "0000000a:B", ok: true, handshakeMs: 10, firstByteMs: 200, why: "" },
            { key: "0000000a:C", ok: true, handshakeMs: 10, firstByteMs: 100, why: "" },
          ],
        },
      });
    const card = tunnels.card("a");
    await card.locator("button", { hasText: "Check nodes" }).click();
    await expect(tunnels.nodeRows("a").nth(2).locator(".lat")).not.toHaveText("");
    await card.locator("button", { hasText: "By latency" }).click();
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].order).toEqual(["0000000a:C", "0000000a:B", "0000000a:A"]);

    await card.getByRole("button", { name: "Collapse", exact: true }).click();
    await expect(tunnels.nodeRows("a")).toHaveCount(0);
    await tunnels.expand("a");
    await expect(tunnels.nodeNames("a")).toHaveText(["C", "B", "A"]);
  });

  // Catches a probe answer outliving the sources it measured.
  test("probe results are dropped when the sources change", async ({ page }) => {
    const { daemon, tunnels } = await saved(page);
    daemon.probeAnswer = (_body, route) =>
      route.fulfill({
        json: {
          nodes: [{ key: "0000000a:A", ok: true, handshakeMs: 90, firstByteMs: 120, why: "" }],
        },
      });
    const card = tunnels.card("a");
    await card.locator("button", { hasText: "Check nodes" }).click();
    await expect(tunnels.nodeRows("a").nth(0).locator(".lat")).toHaveText(
      /^120 ms\s*to the node 90 ms$/,
    );

    await card
      .locator(".src")
      .filter({ hasText: "Solo" })
      .getByRole("button", { name: "Delete" })
      .click();
    await answerConfirm(page, true);
    await expect(card.getByText("Solo")).toHaveCount(0);
    await expect(tunnels.nodeRows("a").nth(0).locator(".lat")).toHaveText("");
    await expect(card.locator("button", { hasText: "By latency" })).toHaveClass(/inactive/);
  });

  // Catches a probe offered, or sent, for a tunnel the daemon does not know yet.
  test("Check nodes is inactive on an unsaved tunnel", async ({ page }) => {
    const daemon = await stubDaemon(page);
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.addTunnel();
    await tunnels.addLink("tunnel1", "vless://u@h.example:443#Solo");
    const button = tunnels.card("tunnel1").locator("button", { hasText: "Check nodes" });
    await expect(button).toHaveClass(/inactive/);
    await button.click();
    await tunnels.settle();
    expect(daemon.probes).toEqual([]);
  });

  // Catches a probe 409 passing without a word, or showing the wrong cause.
  test("a probe already running shows a toast", async ({ page }) => {
    const { daemon, tunnels } = await saved(page);
    daemon.probeAnswer = (_body, route) =>
      route.fulfill({ status: 409, json: { error: "a probe is running" } });
    await tunnels.card("a").locator("button", { hasText: "Check nodes" }).click();
    await expect(page.getByText("A check is already running")).toBeVisible();
  });

  // Catches a filter refusal shown away from the filter, or another field's refusal marking the filter.
  test("a preview refusal lands by its field", async ({ page }) => {
    const { daemon, tunnels } = await saved(page);
    const filter = tunnels.filter("a");

    daemon.previewAnswer = (_body, route) =>
      route.fulfill({ status: 400, json: { error: "bad regular expression", field: "filter" } });
    await filter.fill("(");
    const inline = tunnels.card("a").locator(".problem:not(.top)");
    await expect(inline).toHaveText("bad regular expression");
    await expect(filter).toHaveClass(/invalid/);
    await expect(tunnels.card("a").locator(".problem.top")).toHaveCount(0);

    daemon.previewAnswer = (_body, route) =>
      route.fulfill({ status: 400, json: { error: "bad url", field: "sources[0].url" } });
    await filter.fill("x");
    const top = tunnels.card("a").locator(".problem.top");
    await expect(top).toHaveText("sources[0].url: bad url");
    await expect(filter).not.toHaveClass(/invalid/);
    await expect(inline).toHaveCount(0);
  });

  // Catches the browser's own URL bubble pre-empting the dialog's message.
  test("the subscription URL field does not use native validation", async ({ page }) => {
    await stubDaemon(page);
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.addTunnel();
    await tunnels.card("tunnel1").getByRole("button", { name: "Subscription" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Name").fill("Provider");
    const url = dialog.getByLabel("URL");
    await url.fill("ftp://nope");
    expect(await url.evaluate((el: HTMLInputElement) => el.type)).toBe("text");
    await dialog.getByRole("button", { name: "Add", exact: true }).click();
    await expect(dialog.getByRole("alert")).toHaveText(
      "The URL must start with http:// or https://",
    );
    expect(await url.evaluate((el: HTMLInputElement) => el.validity.valid)).toBe(true);
  });

  // Catches the edited flag dropped: an untouched Apply would rewrite a stored override that equals today's default and light Save.
  test("applying an untouched subscription keeps its stored headers and Save inactive", async ({
    page,
  }) => {
    const { daemon, tunnels } = await saved(page, {
      sources: [{ ...SUB, headers: { "User-Agent": "firc/0.4.1" } }, LINK],
    });
    await tunnels.sourceRow("a", "Provider").getByRole("button", { name: "Edit" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByRole("textbox", { name: /^Value of/ })).toHaveCount(5);
    await dialog.getByRole("button", { name: "Apply" }).click();
    await expect(dialog).toBeHidden();
    await expect(tunnels.sourceRow("a", "Provider")).toContainText("own headers");
    await expect(tunnels.save).toHaveClass(/inactive/);
    expect(daemon.puts).toHaveLength(0);
  });

  // Catches a refused header name accepted by the dialog and failing only after Save.
  test("a header the fetch sets itself blocks Apply with a message naming it", async ({ page }) => {
    const { tunnels } = await saved(page);
    await tunnels.sourceRow("a", "Provider").getByRole("button", { name: "Edit" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: /Request headers/ }).click();
    await dialog.getByRole("button", { name: "Add header" }).click();
    await dialog.getByRole("textbox", { name: "Header name" }).nth(5).fill("host");
    await dialog.getByRole("textbox", { name: "Value of host" }).fill("x");
    await dialog.getByRole("button", { name: "Apply" }).click();
    await expect(dialog.getByRole("alert")).toHaveText("Header host is set by the fetch itself");
    await expect(dialog).toBeVisible();
  });

  // Catches a value typed back to its default still saved as an override.
  test("a header edited and put back to its default is not saved as an override", async ({
    page,
  }) => {
    const { daemon, tunnels } = await saved(page);
    await tunnels.sourceRow("a", "Provider").getByRole("button", { name: "Edit" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: /Request headers/ }).click();
    const value = dialog.getByRole("textbox", { name: /^(Value of|Header value)/ }).nth(4);
    await value.fill("Other");
    await value.fill("Ultra (KN-1810)");
    await dialog.getByRole("button", { name: "Apply" }).click();
    await expect(tunnels.sourceRow("a", "Provider")).not.toContainText("own headers");
    expect(daemon.puts).toHaveLength(0);
  });

  // Catches a header edit saved as the whole set, a removed default saved as absent, or the edit button missing on a subscription.
  test("an edited subscription saves only what differs from the default headers", async ({
    page,
  }) => {
    const { daemon, tunnels } = await saved(page);
    await tunnels.sourceRow("a", "Provider").getByRole("button", { name: "Edit" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: /Request headers/ }).click();
    const values = dialog.getByRole("textbox", { name: /^(Value of|Header value)/ });
    await expect(values).toHaveCount(5);
    await values.nth(4).fill("Mine");
    await dialog.getByRole("button", { name: "Do not send" }).nth(1).click();
    await expect(values.nth(1)).toBeDisabled();
    await dialog.getByRole("button", { name: "Add header" }).click();
    await dialog.getByRole("textbox", { name: "Header name" }).nth(5).fill("Authorization");
    await values.nth(5).fill("Bearer x");
    await expect(dialog.getByRole("button", { name: /Request headers/ })).toContainText(
      "changed: 3",
    );
    await dialog.getByRole("button", { name: "Apply" }).click();
    await expect(tunnels.sourceRow("a", "Provider")).toContainText("own headers");
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].sources[0].headers).toEqual({
      "X-HWID": "",
      "X-Device-Model": "Mine",
      Authorization: "Bearer x",
    });
  });

  // Catches Reset to defaults leaving an empty headers object in the save, or the badge staying.
  test("Reset to defaults drops the subscription's own headers", async ({ page }) => {
    const { daemon, tunnels } = await saved(page, {
      sources: [{ ...SUB, headers: { "X-HWID": "" } }, LINK],
    });
    await expect(tunnels.sourceRow("a", "Provider")).toContainText("own headers");
    await tunnels.sourceRow("a", "Provider").getByRole("button", { name: "Edit" }).click();
    const dialog = page.getByRole("dialog");
    await expect(
      dialog.getByRole("textbox", { name: /^(Value of|Header value)/ }).nth(1),
    ).toBeDisabled();
    await dialog.getByRole("button", { name: "Reset to defaults" }).click();
    await dialog.getByRole("button", { name: "Apply" }).click();
    await expect(tunnels.sourceRow("a", "Provider")).not.toContainText("own headers");
    await tunnels.save.click();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect("headers" in daemon.puts[0].tunnels[0].sources[0]).toBe(false);
  });

  // Catches the phone layout squeezing a header's name and value into one line.
  test("on a phone a header's name sits above its value", async ({ page }) => {
    const { tunnels } = await saved(page);
    await page.setViewportSize({ width: 390, height: 844 });
    await tunnels.sourceRow("a", "Provider").getByRole("button", { name: "Edit" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: /Request headers/ }).click();
    const name = await dialog.getByRole("textbox", { name: "Header name" }).first().boundingBox();
    const value = await dialog
      .getByRole("textbox", { name: /^(Value of|Header value)/ })
      .first()
      .boundingBox();
    expect(name).not.toBeNull();
    expect(value).not.toBeNull();
    expect(value!.y).toBeGreaterThanOrEqual(name!.y + name!.height - 1);
  });
});
