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

  // Catches probe latencies not shown, or "By latency" not ordering by them.
  test("checking nodes fills latencies and By latency sorts by them", async ({ page }) => {
    const { daemon, tunnels } = await saved(page);
    daemon.probeAnswer = (_body, route) =>
      route.fulfill({
        json: {
          nodes: [
            { key: "0000000a:A", ok: true, handshakeMs: 90, firstByteMs: 120, why: "" },
            { key: "0000000a:B", ok: false, handshakeMs: null, firstByteMs: null, why: "timeout" },
            { key: "0000000a:C", ok: true, handshakeMs: 30, firstByteMs: 50, why: "" },
          ],
        },
      });
    const card = tunnels.card("a");
    await card.locator("button", { hasText: "Check nodes" }).click();
    await expect(tunnels.nodeRows("a").nth(0).locator(".lat")).toHaveText("90 ms");
    await expect(tunnels.nodeRows("a").nth(2).locator(".lat")).toHaveText("30 ms");
    expect(daemon.probes[0].tunnel.id).toBe("a");

    await card.locator("button", { hasText: "By latency" }).click();
    await expect(tunnels.nodeNames("a")).toHaveText(["C", "A", "B"]);
    await tunnels.save.click();
    await expect(page.getByText("Saved")).toBeVisible();
    expect(daemon.puts[0].tunnels[0].order).toEqual(["0000000a:C", "0000000a:A", "0000000a:B"]);
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
    await expect(tunnels.nodeRows("a").nth(0).locator(".lat")).toHaveText("90 ms");

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
});
