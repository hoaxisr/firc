import { expect, test } from "@playwright/test";

import { state, stubDaemon, tunnel, TunnelsPage } from "./pages/TunnelsPage";

const LINK = { id: "l1", kind: "link", link: "vless://u@h.example:443#Solo" };
const ROUTER = { name: "OpkgTun2", state: "ready", saved: false, error: "" };

test.describe("OpkgTun tunnels", () => {
  // Catches the OpkgTun name or the unsaved tag missing on an opkg card, shown on a tunvless card, or kept after the router saved.
  test("an opkg card names its OpkgTun and says while the router has not saved it", async ({
    page,
  }) => {
    const daemon = await stubDaemon(page, {
      tunnels: [
        tunnel("a", "opkgtun2", { sources: [LINK] }),
        tunnel("b", "tunvless1", { sources: [LINK] }),
      ],
      states: [state("a", "opkgtun2", { router: ROUTER }), state("b", "tunvless1")],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    const a = tunnels.card("a");
    const b = tunnels.card("b");
    await expect(a.locator("[data-router-name]")).toHaveText("OpkgTun2");
    await expect(a.locator("[data-router-unsaved]")).toHaveText("not saved in the router");
    await expect(b.locator("[data-router-name]")).toHaveCount(0);
    await expect(b.locator("[data-router-unsaved]")).toHaveCount(0);

    daemon.states = [
      state("a", "opkgtun2", { router: { ...ROUTER, saved: true } }),
      state("b", "tunvless1"),
    ];
    await expect(a.locator("[data-router-unsaved]")).toHaveCount(0);
    await expect(a.locator("[data-router-name]")).toHaveText("OpkgTun2");
  });

  // Catches a refused record shown as still waiting, or NDM's text hidden from the card.
  test("a refused record shows the router's error on the card", async ({ page }) => {
    await stubDaemon(page, {
      tunnels: [tunnel("a", "opkgtun2", { sources: [LINK] })],
      states: [
        state("a", "opkgtun2", {
          status: "router",
          why: "description length exceeds 256 bytes",
          router: { ...ROUTER, state: "failed", error: "description length exceeds 256 bytes" },
        }),
      ],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    const a = tunnels.card("a");
    await expect(a.locator(".badge").first()).toHaveText("Router refused the interface");
    await expect(a).toContainText("description length exceeds 256 bytes");
  });

  // Catches the save hint on a tunvless tunnel, missing on an opkg tunnel whose record a save writes, or shown when nothing reaches the router.
  test("the hint says a save writes the router, only for an opkg record that changes", async ({
    page,
  }) => {
    await stubDaemon(page, {
      tunnels: [
        tunnel("a", "opkgtun2", { sources: [LINK] }),
        tunnel("b", "tunvless1", { sources: [LINK] }),
      ],
      states: [
        state("a", "opkgtun2", { router: { ...ROUTER, saved: true } }),
        state("b", "tunvless1"),
      ],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    const a = tunnels.card("a");
    const b = tunnels.card("b");
    await expect(a.locator("[data-router-name]")).toBeVisible();
    await expect(page.locator("[data-router-hint]")).toHaveCount(0);
    await b.getByRole("textbox", { name: "Description" }).fill("DE");
    await expect(page.locator("[data-router-hint]")).toHaveCount(0);
    await a.getByRole("textbox", { name: "Description" }).fill("NL");
    await expect(a.locator("[data-router-hint]")).toContainText(
      "firc writes OpkgTun2 to the router and saves the router's configuration",
    );
    await expect(b.locator("[data-router-hint]")).toHaveCount(0);
  });

  // Catches a new opkg tunnel taking an OpkgTun the router already lists, its number not editable, or a typed number not saved.
  test("a new tunnel's number is typed, and opkgtun skips the router's interfaces", async ({
    page,
  }) => {
    const daemon = await stubDaemon(page, {
      interfaces: ["wg0", "opkgtun0", "opkgtun1", "tunvless2"],
      tunnels: [tunnel("x", "tunvless2", { sources: [LINK] })],
      states: [state("x", "tunvless2")],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.addTunnel();
    const card = tunnels.card("tunnel1");
    const num = card.getByRole("textbox", { name: "Device number" });
    await expect(num).toHaveValue("0");
    await expect(card.locator("[data-router-hint]")).toHaveCount(0);

    await card.getByRole("button", { name: "Device prefix" }).click();
    await page.locator('[data-select-item][data-value="opkgtun"]').click();
    await expect(num).toHaveValue("3");
    await expect(card.locator("[data-router-hint]")).toContainText("OpkgTun3");

    await num.fill("1");
    await expect(card.locator("[data-device-error]")).toHaveText(
      "The router already has this interface",
    );
    await num.fill("2");
    await expect(card.locator("[data-device-error]")).toHaveText("Another tunnel uses this device");
    await num.fill("5");
    await expect(card.locator("[data-device-error]")).toHaveCount(0);
    await expect(card.locator("[data-router-hint]")).toContainText("OpkgTun5");

    await tunnels.addLink("tunnel1", "vless://u@h.example:443?security=tls#Solo");
    await tunnels.save.click();
    await expect(page.getByText("Saved", { exact: true })).toBeVisible();
    expect(daemon.puts[0].tunnels[1].device).toBe("opkgtun5");
    await expect(card.getByRole("textbox", { name: "Device number" })).toHaveCount(0);
    await expect(card.locator("[data-router-hint]")).toHaveCount(0);
  });

  // Catches a save sent, or the router hint promised, while the typed device is refused.
  test("a refused device hides the hint and blocks the save", async ({ page }) => {
    const daemon = await stubDaemon(page, {
      interfaces: ["wg0", "opkgtun0"],
      tunnels: [tunnel("x", "tunvless2", { sources: [LINK] })],
      states: [state("x", "tunvless2")],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await tunnels.addTunnel();
    const card = tunnels.card("tunnel1");
    await card.getByRole("button", { name: "Device prefix" }).click();
    await page.locator('[data-select-item][data-value="opkgtun"]').click();
    const num = card.getByRole("textbox", { name: "Device number" });
    await expect(num).toHaveValue("1");
    await expect(tunnels.save).not.toHaveClass(/inactive/);
    await num.fill("0");
    await expect(card.locator("[data-device-error]")).toHaveText(
      "The router already has this interface",
    );
    await expect(card.locator("[data-router-hint]")).toHaveCount(0);
    await expect(tunnels.save).toHaveClass(/inactive/);
    await page.keyboard.press("Control+s");
    await tunnels.save.click({ force: true });
    await num.fill("x");
    await expect(card.locator("[data-device-error]")).toBeVisible();
    await expect(card.locator("[data-router-hint]")).toHaveCount(0);
    await expect(tunnels.save).toHaveClass(/inactive/);
    expect(daemon.puts).toHaveLength(0);
    await num.fill("4");
    await expect(card.locator("[data-router-hint]")).toContainText("OpkgTun4");
    await expect(tunnels.save).not.toHaveClass(/inactive/);
  });

  // Catches the delete prompt promising a router removal and save for a record that is not firc's or does not exist.
  test("the delete prompt promises the router save only for a record of ours in place", async ({
    page,
  }) => {
    await stubDaemon(page, {
      tunnels: [
        tunnel("a", "opkgtun2", { sources: [LINK] }),
        tunnel("b", "opkgtun3", { sources: [LINK] }),
        tunnel("c", "opkgtun4", { sources: [LINK] }),
      ],
      states: [
        state("a", "opkgtun2", { router: { ...ROUTER, saved: true } }),
        state("b", "opkgtun3", {
          status: "router",
          router: { ...ROUTER, name: "OpkgTun3", state: "foreign", error: "taken" },
        }),
        state("c", "opkgtun4", {
          status: "router",
          router: { ...ROUTER, name: "OpkgTun4", state: "failed", saved: true, error: "x" },
        }),
      ],
    });
    const tunnels = new TunnelsPage(page);
    await tunnels.open();
    await expect(tunnels.card("a").locator("[data-router-name]")).toBeVisible();
    const prompt = async (id: string) => {
      await tunnels.card(id).getByRole("button", { name: "Delete", exact: true }).click();
      const dialog = page.getByRole("alertdialog").or(page.getByRole("dialog")).first();
      await expect(dialog).toBeVisible();
      const text = (await dialog.textContent()) ?? "";
      await dialog.getByRole("button", { name: "Cancel" }).click();
      await expect(dialog).toBeHidden();
      return text;
    };
    expect(await prompt("a")).toContain("removes OpkgTun2 from the router");
    expect(await prompt("b")).not.toContain("from the router");
    expect(await prompt("c")).not.toContain("from the router");
  });
});
