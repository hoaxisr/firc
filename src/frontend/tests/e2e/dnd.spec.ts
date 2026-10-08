import { expect, test, type Page } from "@playwright/test";

import {
  centerOf,
  dragTo,
  frame,
  glide,
  hover,
  mousePointer,
  pick,
  touchPointer,
} from "./pages/drag";
import { signedIn } from "./pages/session";

type Seed = { id: string; name: string; rules: string[] };

const rule = (pattern: string) => ({
  id: `r-${pattern}`,
  enable: true,
  rule: pattern,
  type: "domain",
});

const groupOf = (seed: Seed) => ({
  id: seed.id,
  name: seed.name,
  interface: "wg0",
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: seed.rules.map(rule),
  live: true,
});

const SEEDS: Seed[] = [
  { id: "0a000001", name: "Alpha", rules: ["a0.example", "a1.example", "a2.example"] },
  { id: "0a000002", name: "Beta", rules: ["b0.example", "b1.example"] },
  { id: "0a000003", name: "Gamma", rules: ["g0.example"] },
];

async function setup(page: Page, seeds: Seed[] = SEEDS, open: string[] = ["Alpha", "Beta"]) {
  await signedIn(page);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.route("**/system/interfaces", (route) =>
    route.fulfill({ json: { interfaces: [{ id: "wg0", name: "WireGuard" }] } }),
  );
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) =>
    route.fulfill({ json: { ok: true, error: "", since: 0 } }),
  );
  await page.route(/\/groups(\?.*)?$/, (route) =>
    route.fulfill({ json: { groups: seeds.map(groupOf) } }),
  );
  await page.goto("/");
  await expect(page.locator(".group")).toHaveCount(seeds.length);
  for (const name of open) {
    await groupById(page, name).locator("[data-collapsible-trigger]").click();
  }
}

const groupById = (page: Page, name: string) =>
  page.locator(`.group[data-uuid="${SEEDS.find((s) => s.name === name)?.id}"]`);

const rowOf = (page: Page, pattern: string) => page.locator(`.rule[data-uuid="r-${pattern}"]`);

const patterns = (page: Page, name: string) =>
  groupById(page, name)
    .locator(".rule .pattern-input")
    .evaluateAll((els) => els.map((el) => (el as HTMLInputElement).value));

const groupNames = (page: Page) =>
  page
    .locator(".group-wrapper input.group-name")
    .evaluateAll((els) => els.map((el) => (el as HTMLInputElement).value));

const handleOf = (page: Page, pattern: string) => rowOf(page, pattern).locator(".grip");

const leftovers = (page: Page) =>
  page.evaluate(() => ({
    slots: document.querySelectorAll(".dnd-slot").length,
    chips: document.querySelectorAll(".dnd-chip").length,
    origins: document.querySelectorAll(".dnd-origin").length,
    dragging: document.documentElement.classList.contains("dnd-dragging"),
  }));

const CLEAN = { slots: 0, chips: 0, origins: 0, dragging: false };

test.describe("Drag and drop", () => {
  // Catches a downward drop landing before the target instead of after it.
  test("a rule dragged below a later one lands after it", async ({ page }) => {
    await setup(page);
    await dragTo(page, handleOf(page, "a0.example"), rowOf(page, "a2.example"), "after");
    await expect
      .poll(() => patterns(page, "Alpha"))
      .toEqual(["a1.example", "a2.example", "a0.example"]);
  });

  // Catches an upward drop landing after the target instead of before it.
  test("a rule dragged above an earlier one lands before it", async ({ page }) => {
    await setup(page);
    await dragTo(page, handleOf(page, "a2.example"), rowOf(page, "a0.example"), "before");
    await expect
      .poll(() => patterns(page, "Alpha"))
      .toEqual(["a2.example", "a0.example", "a1.example"]);
  });

  // Catches a cross-group drop that copies the rule, or inserts it in its old group.
  test("a rule dropped among another group's rules moves into that group", async ({ page }) => {
    await setup(page);
    await dragTo(page, handleOf(page, "a0.example"), rowOf(page, "b0.example"), "after");
    await expect.poll(() => patterns(page, "Alpha")).toEqual(["a1.example", "a2.example"]);
    await expect
      .poll(() => patterns(page, "Beta"))
      .toEqual(["b0.example", "a0.example", "b1.example"]);
  });

  // Catches a header that is not a target, or a drop on it that lands anywhere but first.
  test("a rule dropped on a collapsed group's header lands first in it", async ({ page }) => {
    await setup(page);
    const header = groupById(page, "Gamma").locator(".group-header");
    await dragTo(page, handleOf(page, "a1.example"), header, "after");
    await expect.poll(() => patterns(page, "Alpha")).toEqual(["a0.example", "a2.example"]);
    await groupById(page, "Gamma").locator("[data-collapsible-trigger]").click();
    await expect.poll(() => patterns(page, "Gamma")).toEqual(["a1.example", "g0.example"]);
  });

  // Catches group drops resolving before/after the wrong way.
  test("groups reorder above and below", async ({ page }) => {
    await setup(page, SEEDS, []);
    const grip = (name: string) => groupById(page, name).locator(".group-grip");
    const wrapper = (name: string) =>
      page.locator(".group-wrapper", { has: groupById(page, name) });

    await dragTo(page, grip("Gamma"), wrapper("Alpha"), "before");
    await expect.poll(() => groupNames(page)).toEqual(["Gamma", "Alpha", "Beta"]);

    await dragTo(page, grip("Alpha"), wrapper("Beta"), "after");
    await expect.poll(() => groupNames(page)).toEqual(["Gamma", "Beta", "Alpha"]);
  });

  // Catches a missing slot, a slot on the wrong side, an unfaded origin, a chip without the rule, or any of them left behind.
  test("mid-drag the slot opens at the drop point and the origin fades, both go after the drop", async ({
    page,
  }) => {
    await setup(page);
    const pointer = mousePointer(page);
    await pick(page, pointer, handleOf(page, "a0.example"));
    await hover(page, pointer, rowOf(page, "a1.example"), "after");

    const slot = page.locator(".dnd-slot");
    await expect(slot).toHaveCount(1);
    expect(
      await slot.evaluate((el) => [
        (el.previousElementSibling as HTMLElement | null)?.dataset.uuid,
        (el.nextElementSibling as HTMLElement | null)?.dataset.uuid,
      ]),
    ).toEqual(["r-a1.example", "r-a2.example"]);
    const origin = rowOf(page, "a0.example");
    await expect(origin).toHaveClass(/\bdnd-origin\b/);
    expect(Number(await origin.evaluate((el) => getComputedStyle(el).opacity))).toBeLessThan(0.5);
    await expect(page.locator(".dnd-chip")).toContainText("a0.example");
    await expect(page.locator(".dnd-chip")).toContainText("Domain");

    await pointer.up();
    await expect.poll(() => leftovers(page)).toEqual(CLEAN);
    await expect
      .poll(() => patterns(page, "Alpha"))
      .toEqual(["a1.example", "a0.example", "a2.example"]);
  });

  // Catches Escape not cancelling, or the release after it still dropping.
  test("Escape cancels the drag and the release drops nothing", async ({ page }) => {
    await setup(page);
    const pointer = mousePointer(page);
    await pick(page, pointer, handleOf(page, "a0.example"));
    await hover(page, pointer, rowOf(page, "a2.example"), "after");
    await expect(page.locator(".dnd-slot")).toHaveCount(1);

    await page.keyboard.press("Escape");
    await expect.poll(() => leftovers(page)).toEqual(CLEAN);
    await pointer.up();
    await frame(page);
    expect(await patterns(page, "Alpha")).toEqual(["a0.example", "a1.example", "a2.example"]);
  });

  // Catches a pointercancel (a browser taking the gesture) leaving the drag alive.
  test("a pointercancel ends the drag without a drop", async ({ page }) => {
    await setup(page);
    const pointer = mousePointer(page);
    const handle = handleOf(page, "a0.example");
    await page.evaluate(() =>
      window.addEventListener("pointerdown", (e) => ((window as any).__pid = e.pointerId), true),
    );
    await pick(page, pointer, handle);
    await hover(page, pointer, rowOf(page, "a2.example"), "after");
    await expect(page.locator(".dnd-slot")).toHaveCount(1);
    await handle.evaluate((el) =>
      el.dispatchEvent(
        new PointerEvent("pointercancel", { bubbles: true, pointerId: (window as any).__pid }),
      ),
    );
    await expect.poll(() => leftovers(page)).toEqual(CLEAN);
    await pointer.up();
    await frame(page);
    expect(await patterns(page, "Alpha")).toEqual(["a0.example", "a1.example", "a2.example"]);
  });

  // Catches a release outside every target dropping onto the last one hovered.
  test("a release outside every target drops nothing", async ({ page }) => {
    await setup(page);
    const pointer = mousePointer(page);
    await pick(page, pointer, handleOf(page, "a0.example"));
    await hover(page, pointer, rowOf(page, "a2.example"), "after");
    const order = await centerOf(page.locator(".order-hint"));
    await glide(page, pointer, { x: pointer.at().x, y: order.y });
    await expect(page.locator(".dnd-slot")).toHaveCount(0);
    await pointer.up();
    await expect.poll(() => leftovers(page)).toEqual(CLEAN);
    expect(await patterns(page, "Alpha")).toEqual(["a0.example", "a1.example", "a2.example"]);
  });

  // Catches a drag starting on press or on a jitter below the threshold.
  test("a press on the handle with a 2px jitter starts no drag", async ({ page }) => {
    await setup(page);
    const at = await centerOf(handleOf(page, "a0.example"));
    await page.mouse.move(at.x, at.y);
    await page.mouse.down();
    await page.mouse.move(at.x + 1, at.y + 2, { steps: 2 });
    await frame(page);
    expect(await leftovers(page)).toEqual(CLEAN);
    await page.mouse.up();
    await frame(page);
    expect(await leftovers(page)).toEqual(CLEAN);
    expect(await patterns(page, "Alpha")).toEqual(["a0.example", "a1.example", "a2.example"]);
  });

  // Catches a group chip without the name, or a count not in the locale's plural form.
  test("a dragged group's chip shows its name and a plural rule count", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
    await setup(page, SEEDS, []);
    const pointer = mousePointer(page);
    await pick(page, pointer, groupById(page, "Alpha").locator(".group-grip"));
    await hover(page, pointer, page.locator(".group-wrapper").nth(2), "after");
    await expect(page.locator(".dnd-chip")).toHaveText(/Alpha\s*3 правила/);
    await expect(groupById(page, "Alpha")).toHaveClass(/\bdnd-origin\b/);
    await page.keyboard.press("Escape");
    await pointer.up();
  });

  // Catches a drop on page 2 using the on-page position instead of the rule's own index.
  test("a rule reorders on the second page of a paged group", async ({ page }) => {
    const many = Array.from({ length: 60 }, (_, i) => `p${String(i).padStart(2, "0")}.example`);
    await setup(page, [{ id: "0a000001", name: "Alpha", rules: many }], ["Alpha"]);
    await page.locator(".pagination").getByTitle("Next Page").click();
    await expect(rowOf(page, "p50.example")).toBeVisible();

    await dragTo(page, handleOf(page, "p50.example"), rowOf(page, "p52.example"), "after");
    await expect
      .poll(async () => (await patterns(page, "Alpha")).slice(0, 4))
      .toEqual(["p51.example", "p52.example", "p50.example", "p53.example"]);
  });

  // Catches a search-filtered drop that drops or reorders the rules the search hides.
  test("a reorder in a search-filtered view keeps the hidden rules in place", async ({ page }) => {
    await setup(
      page,
      [
        {
          id: "0a000001",
          name: "Alpha",
          rules: ["keep-1.ex", "hide-1.ex", "keep-2.ex", "keep-3.ex"],
        },
      ],
      ["Alpha"],
    );
    const search = page.locator(
      '[data-tabs-content][data-state="active"] .group-controls-search .search-input',
    );
    await page
      .locator('[data-tabs-content][data-state="active"] .group-controls-search .search-container')
      .click();
    await search.fill("keep");
    await expect(rowOf(page, "hide-1.ex")).toHaveCount(0);

    await dragTo(page, handleOf(page, "keep-1.ex"), rowOf(page, "keep-2.ex"), "after");
    await expect
      .poll(() => patterns(page, "Alpha"))
      .toEqual(["keep-2.ex", "keep-1.ex", "keep-3.ex"]);

    await search.fill("");
    await expect
      .poll(() => patterns(page, "Alpha"))
      .toEqual(["hide-1.ex", "keep-2.ex", "keep-1.ex", "keep-3.ex"]);
  });

  // Catches no auto-scroll near the viewport's bottom edge during a drag.
  test("holding a drag near the bottom edge scrolls the page", async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 600 });
    const many = Array.from({ length: 45 }, (_, i) => `s${String(i).padStart(2, "0")}.example`);
    await setup(page, [{ id: "0a000001", name: "Alpha", rules: many }], ["Alpha"]);
    await rowOf(page, "s00.example").scrollIntoViewIfNeeded();
    const before = await page.evaluate(() => window.scrollY);

    const pointer = mousePointer(page);
    await pick(page, pointer, handleOf(page, "s00.example"));
    await glide(page, pointer, { x: pointer.at().x, y: 590 });
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(before + 200);
    await page.keyboard.press("Escape");
    await pointer.up();
    await expect.poll(() => leftovers(page)).toEqual(CLEAN);
  });
});

test.describe("Drag and drop by touch", () => {
  test.skip(({ browserName }) => browserName !== "chromium", "CDP touch input is Chromium-only");
  test.use({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });

  // Catches a handle that ignores touch, or a touch drag that never becomes a pointer drag.
  test("a rule reorders by a touch drag on its handle", async ({ page }) => {
    await setup(page);
    await page.evaluate(() => {
      (window as any).__types = [];
      window.addEventListener(
        "pointerdown",
        (e) => (window as any).__types.push(e.pointerType),
        true,
      );
    });
    const pointer = await touchPointer(page);
    await pick(page, pointer, handleOf(page, "a0.example"));
    await hover(page, pointer, rowOf(page, "a2.example"), "after");
    await expect(page.locator(".dnd-slot")).toHaveCount(1);
    await pointer.up();

    await expect
      .poll(() => patterns(page, "Alpha"))
      .toEqual(["a1.example", "a2.example", "a0.example"]);
    expect(await page.evaluate(() => (window as any).__types)).toEqual(["touch"]);
    await expect.poll(() => leftovers(page)).toEqual(CLEAN);
  });

  // Catches the group grip hidden or inert on a phone.
  test("groups reorder by a touch drag on a phone", async ({ page }) => {
    await setup(page, SEEDS, []);
    const pointer = await touchPointer(page);
    await pick(page, pointer, groupById(page, "Alpha").locator(".group-grip"));
    await hover(page, pointer, page.locator(".group-wrapper").nth(1), "after");
    await pointer.up();
    await expect.poll(() => groupNames(page)).toEqual(["Beta", "Alpha", "Gamma"]);
  });

  // Catches a drag taking a touch that starts off the handle, or the page no longer scrolling under it.
  test("a touch swipe off the handle scrolls the page and starts no drag", async ({ page }) => {
    const many = Array.from({ length: 30 }, (_, i) => `t${String(i).padStart(2, "0")}.example`);
    await setup(page, [{ id: "0a000001", name: "Alpha", rules: many }], ["Alpha"]);
    const pointer = await touchPointer(page);
    const row = rowOf(page, "t05.example");
    const start = await centerOf(row.locator(".pattern"));
    await pointer.down(start);
    for (let i = 1; i <= 12; i++) {
      await pointer.move({ x: start.x, y: start.y - i * 25 });
      expect((await leftovers(page)).dragging).toBe(false);
    }
    await pointer.up();
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(50);
    expect(await leftovers(page)).toEqual(CLEAN);
    expect((await patterns(page, "Alpha")).slice(0, 3)).toEqual([
      "t00.example",
      "t01.example",
      "t02.example",
    ]);
  });
});
