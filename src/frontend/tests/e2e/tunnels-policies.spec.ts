import { expect, test, type Page } from "@playwright/test";

import { state, stubDaemon, tunnel, TunnelsPage } from "./pages/TunnelsPage";

const LINK = { id: "l1", kind: "link", link: "vless://u@h.example:443#Solo" };
const ROUTER = {
  name: "OpkgTun2",
  state: "ready",
  saved: true,
  error: "",
  policies: { state: "off", error: "" },
};

async function cards(page: Page, on = false, policies = ROUTER.policies, expand = "Expand") {
  const daemon = await stubDaemon(page, {
    tunnels: [
      tunnel("a", "opkgtun2", { sources: [LINK], routerPolicies: on }),
      tunnel("b", "tunvless1", { sources: [LINK] }),
    ],
    states: [state("a", "opkgtun2", { router: { ...ROUTER, policies } }), state("b", "tunvless1")],
  });
  const tunnels = new TunnelsPage(page);
  const ru = expand !== "Expand";
  await page.goto("/");
  if ((page.viewportSize()?.width ?? 1280) < 700) {
    await page.getByRole("button", { name: "Open menu" }).click();
  }
  await page.getByRole("tab", { name: ru ? "Туннели" : "Tunnels" }).click();
  for (const id of ["a", "b"]) {
    await tunnels.card(id).getByRole("button", { name: expand, exact: true }).click();
  }
  await expect(tunnels.card("a").locator("[data-router-policies]")).toBeVisible();
  return { daemon, tunnels };
}

const sizes = [
  { name: "desk", width: 1280, height: 900 },
  { name: "phone", width: 390, height: 844 },
];

test.describe("Router policies", () => {
  for (const size of sizes) {
    // Catches the switch shown for a tunvless tunnel, missing for an opkg one, its permit warning missing, or the flag not saved.
    test(`the switch is only on an opkg tunnel and writes routerPolicies (${size.name})`, async ({
      page,
    }) => {
      await page.setViewportSize({ width: size.width, height: size.height });
      const { daemon, tunnels } = await cards(page);
      const a = tunnels.card("a");
      const b = tunnels.card("b");
      await expect(a.locator("[data-router-policies]")).toBeVisible();
      await expect(b.locator("[data-router-policies]")).toHaveCount(0);
      await expect(a.locator("[data-policies-permits]")).toHaveCount(0);
      await a.getByRole("switch", { name: "Router policies" }).click();
      await expect(a.locator("[data-policies-permits]")).toContainText(
        "takes OpkgTun2 out of them, and the router does not put it back",
      );
      await expect(a.locator("[data-policies-leaving]")).toHaveCount(0);
      await tunnels.save.click();
      await expect(page.getByText("Saved", { exact: true })).toBeVisible();
      expect(daemon.puts[0].tunnels[0].routerPolicies).toBe(true);
      expect(daemon.puts[0].tunnels[1].routerPolicies).toBe(false);
    });
  }

  // Catches turning the switch off without saying the tunnel leaves the router's policies.
  test("turning it off says the record leaves every policy", async ({ page }) => {
    const { tunnels } = await cards(page, true, { state: "on", error: "" });
    const a = tunnels.card("a");
    await expect(a.locator("[data-policies-leaving]")).toHaveCount(0);
    await a.getByRole("switch", { name: "Router policies" }).click();
    await expect(a.locator("[data-policies-leaving]")).toHaveText(
      "On save, OpkgTun2 leaves every router policy that uses it",
    );
  });

  // Catches a failed policies state hidden from the card, as it is when the switch is already off.
  test("a failed policies state shows the daemon's reason with the switch off", async ({
    page,
  }) => {
    const { tunnels } = await cards(page, false, {
      state: "failed",
      error:
        "OpkgTun2 is still in a router policy; remove it there to finish turning router policies off",
    });
    await expect(tunnels.card("a").locator("[data-policies-error]")).toContainText(
      "OpkgTun2 is still in a router policy",
    );
  });

  // Catches the delete prompt not saying the router's policies lose the tunnel, or saying it with the switch off.
  test("the delete prompt says policies lose the record", async ({ page }) => {
    await stubDaemon(page, {
      tunnels: [
        tunnel("a", "opkgtun2", { sources: [LINK], routerPolicies: true }),
        tunnel("c", "opkgtun3", { sources: [LINK] }),
      ],
      states: [
        state("a", "opkgtun2", { router: ROUTER }),
        state("c", "opkgtun3", { router: { ...ROUTER, name: "OpkgTun3" } }),
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
    expect(await prompt("a")).toContain("Router policies that use OpkgTun2 lose it");
    expect(await prompt("c")).not.toContain("Router policies");
  });

  for (const size of sizes) {
    // Catches the switch and its warnings left untranslated.
    test(`the switch reads in Russian (${size.name})`, async ({ page }) => {
      await page.setViewportSize({ width: size.width, height: size.height });
      await page.addInitScript(() =>
        localStorage.setItem("locale", JSON.stringify({ value: "ru" })),
      );
      const { tunnels } = await cards(page, true, { state: "on", error: "" }, "Развернуть");
      const a = tunnels.card("a");
      await expect(a.locator("[data-router-policies]")).toContainText("Политики роутера");
      await expect(a.locator("[data-policies-permits]")).toContainText(
        "пропадёт из этих политик, и роутер не вернёт его сам",
      );
    });
  }
});
