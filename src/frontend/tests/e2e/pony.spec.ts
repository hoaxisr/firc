import { expect, test, type Page } from "@playwright/test";

async function startPony(page: Page) {
  await page.route("**/pony-fixture", (route) =>
    route.fulfill({ contentType: "text/html", body: '<body style="margin:0"></body>' }),
  );
  await page.goto("/pony-fixture");
  await page.clock.install({ time: 0 });
  await page.clock.pauseAt(1000);
  await page.addScriptTag({ url: "/pony.js" });
  await page.evaluate(() => {
    Math.random = () => 0.73;
    const { UnicornPony } = window as typeof window & {
      UnicornPony: { start(options: { page: string; platforms: string }): void };
    };
    UnicornPony.start({ page: "firc", platforms: ".group" });
  });
  await page.clock.runFor(32);
}

async function play(page: Page, action: string) {
  await page.evaluate((name) => {
    const { UnicornPony } = window as typeof window & { UnicornPony: { play(name: string): void } };
    UnicornPony.play(name);
  }, action);
  await page.clock.runFor(32);
}

async function ponyBox(page: Page) {
  const box = await page.locator('[data-pony-action] > svg:has([data-part="body"])').boundingBox();
  if (!box) throw new Error("Pony is missing");
  return box;
}

async function advanceUntil(page: Page, selector: string, timeout: number) {
  const match = page.locator(selector);
  for (let elapsed = 0; !(await match.count()) && elapsed < timeout; elapsed += 160) {
    await page.clock.runFor(160);
  }
  await expect(match).toHaveCount(1);
}

async function addWideGroupCard(page: Page) {
  await page.evaluate(() => {
    const card = document.createElement("div");
    card.className = "group";
    card.style.cssText = "position:fixed;left:20px;right:20px;bottom:0;height:200px";
    document.body.append(card);
  });
}

async function expectOnGroupCard(page: Page, box: { y: number; height: number }) {
  const card = await page.locator(".group").boundingBox();
  if (!card) throw new Error("Group card is missing");
  expect(Math.abs(box.y + box.height - card.y)).toBeLessThan(10);
}

test("the pony eats an apple dropped nearby", async ({ page }) => {
  await startPony(page);
  const box = await ponyBox(page);
  await page.mouse.dblclick(box.x + box.width / 2 + 65, box.y + box.height - 15);
  const apple = page.locator("[data-pony-apple]");
  await expect(apple).toBeVisible();
  await page.clock.runFor(6000);
  await expect(apple).toBeHidden();
});

test("the pony peeks from behind a card while a dialog is open", async ({ page }) => {
  await startPony(page);
  await page.evaluate(() => {
    const card = document.createElement("div");
    card.className = "group";
    card.style.cssText = "position:fixed;left:35%;width:30%;top:50%;height:150px";
    const dialog = document.createElement("div");
    dialog.setAttribute("data-dialog-content", "");
    dialog.dataset.state = "open";
    document.body.append(card, dialog);
  });
  await page.clock.runFor(1800);
  const peek = page.locator("[data-pony-peek]");
  await expect(peek).toHaveCount(1);
  await page.locator("[data-dialog-content]").evaluate((el) => el.remove());
  await page.clock.runFor(500);
  await expect(peek).toHaveCount(0);
});

test("the runner jumps over a stationary mouse pointer and resumes running", async ({ page }) => {
  await startPony(page);
  await play(page, "rest");
  const resting = await ponyBox(page);
  await page.mouse.move(resting.x + resting.width + 75, resting.y + resting.height - 12);
  await page.clock.runFor(200);
  await play(page, "run");
  await page.clock.runFor(420);
  const pony = page.locator("[data-pony-action]");
  await expect(pony).toHaveAttribute("data-pony-reaction", "cursor");
  await expect(pony).toHaveAttribute("data-pony-action", "jump");
  await page.clock.runFor(800);
  await expect(pony).toHaveAttribute("data-pony-action", "run");
});

test("the pony sneezes and shakes its mane after stopping in its dust", async ({ page }) => {
  await startPony(page);
  await play(page, "run");
  await page.clock.runFor(200);
  await play(page, "rest");
  const pony = page.locator("[data-pony-action]");
  await expect(pony).toHaveAttribute("data-pony-action", "sneeze");
  await page.clock.runFor(750);
  await expect(pony).toHaveAttribute("data-pony-action", "shake");
});

test("the pony starts a hurdle run on its own with a wide group card", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await startPony(page);
  await addWideGroupCard(page);
  await page.mouse.move(640, 400);
  const pony = page.locator("[data-pony-action]");
  const hurdles = page.locator("[data-pony-hurdle]");
  await advanceUntil(page, '[data-pony-action="jump"][data-pony-reaction="hurdle"]', 16000);
  await expect(hurdles.first()).toBeVisible();
  const barrier = await hurdles.first().boundingBox();
  if (!barrier) throw new Error("Hurdle is missing");
  await expectOnGroupCard(page, barrier);
  const race = page.locator('[data-pony-reaction="hurdle"]');
  for (let elapsed = 0; (await race.count()) && elapsed < 6000; elapsed += 32) {
    await page.clock.runFor(32);
  }
  await expect(race).toHaveCount(0);
  await expect(pony).toHaveAttribute("data-pony-action", /^(run|gallop)$/);
  for (let elapsed = 0; (await hurdles.count()) && elapsed < 6500; elapsed += 32) {
    await page.clock.runFor(32);
  }
  await expect(hurdles).toHaveCount(0);
});

test("the pony chases a butterfly and lets it land on its nose", async ({ page }) => {
  await startPony(page);
  await addWideGroupCard(page);
  await advanceUntil(page, "[data-pony-butterfly]", 60000);
  const butterfly = page.locator("[data-pony-butterfly]");
  await expect(butterfly).toBeVisible();
  await advanceUntil(page, '[data-pony-reaction="butterfly"][data-pony-action="jump"]', 6000);
  await advanceUntil(page, '[data-pony-butterfly="nose"]', 4000);
  const nose = await butterfly.boundingBox();
  const pony = await ponyBox(page);
  if (!nose) throw new Error("Butterfly is missing");
  await expectOnGroupCard(page, pony);
  const center = nose.x + nose.width / 2;
  expect(center).toBeGreaterThan(pony.x);
  expect(center).toBeLessThan(pony.x + pony.width);
  await page.clock.runFor(4000);
  await expect(butterfly).toHaveCount(0);
});

test("the pony hides outside the viewport, peeks, and comes back", async ({ page }) => {
  await startPony(page);
  await advanceUntil(page, '[data-pony-edge="hidden"]', 75000);
  const hidden = await ponyBox(page);
  const viewport = page.viewportSize()!;
  const left = hidden.x < 0;
  expect(left ? hidden.x + hidden.width : viewport.width - hidden.x).toBeLessThanOrEqual(2);
  await advanceUntil(page, '[data-pony-edge="ears"]', 3000);
  await advanceUntil(page, '[data-pony-edge="head"]', 3000);
  await page.clock.runFor(4000);
  await expect(page.locator("[data-pony-edge]")).toHaveCount(0);
  const returned = await ponyBox(page);
  expect(returned.x + returned.width).toBeGreaterThan(0);
  expect(returned.x).toBeLessThan(viewport.width);
});

test("moving the mouse brings the hidden pony back smoothly", async ({ page }) => {
  await startPony(page);
  await advanceUntil(page, '[data-pony-edge="hidden"]', 75000);
  const hidden = await ponyBox(page);
  await page.mouse.move(640, 250);
  await page.clock.runFor(48);
  await expect(page.locator("[data-pony-edge]")).toHaveAttribute("data-pony-edge", "return");
  const returning = await ponyBox(page);
  expect(Math.abs(returning.x - hidden.x)).toBeLessThan(hidden.width / 3);
  await page.clock.runFor(500);
  await expect(page.locator("[data-pony-edge]")).toHaveCount(0);
});

test("the pony leaves a rainbow that fades away", async ({ page }) => {
  await startPony(page);
  await addWideGroupCard(page);
  const rainbow = page.locator("[data-pony-rainbow]");
  const scene = '[data-pony-reaction="rainbow"]';
  await advanceUntil(page, scene, 60000);
  await expect(rainbow).toHaveCount(0);
  await page.keyboard.press("Shift");
  await page.clock.runFor(64);
  await expect(page.locator(scene)).toHaveCount(0);
  await advanceUntil(page, "[data-pony-rainbow]", 10000);
  await expect(rainbow).toBeVisible();
  await expect(rainbow.locator("path")).toHaveCount(6);
  await expect(page.locator("[data-pony-action]")).toHaveAttribute("data-pony-reaction", "rainbow");
  await page.clock.runFor(900);
  const opacity = await rainbow.evaluate((element) => Number(getComputedStyle(element).opacity));
  expect(opacity).toBeGreaterThan(0);
  expect(opacity).toBeLessThan(1);
  await page.clock.runFor(1500);
  await expect(rainbow).toHaveCount(0);
});

test("a hurdle rises and retracts while the next hurdle stays up", async ({ page }) => {
  await startPony(page);
  await play(page, "gallop");
  const hurdles = page.locator("[data-pony-hurdle]");
  await page.clock.runFor(240);
  await expect(hurdles).toHaveCount(2);
  const first = hurdles.first();
  const opening = await first.locator("path").first().boundingBox();
  await page.clock.runFor(320);
  const raised = await first.locator("path").first().boundingBox();
  const next = hurdles.nth(1);
  const nextRaised = await next.locator("path").first().boundingBox();
  if (!opening || !raised || !nextRaised) throw new Error("Hurdle is missing");
  expect(opening.y).toBeGreaterThan(raised.y);
  const retractingSelector = '[data-pony-hurdle-phase="retracting"]';
  await advanceUntil(page, retractingSelector, 2400);
  const retracting = page.locator(retractingSelector);
  await page.clock.runFor(64);
  const closing = await retracting.locator("path").first().boundingBox();
  if (!closing) throw new Error("Retracting hurdle is missing");
  expect(closing.y).toBeGreaterThan(raised.y);
  await expect(next).toBeVisible();
  await expect(next).toHaveAttribute("data-pony-hurdle-phase", "visible");
  expect(await next.locator("path").first().boundingBox()).toEqual(nextRaised);
  await page.clock.runFor(350);
  await expect(retracting).toHaveCount(0);
  await expect(hurdles).toHaveCount(1);
});

test("the pony knocks down a hurdle, snorts, and resumes running", async ({ page }) => {
  await startPony(page);
  await page.evaluate(() => {
    Math.random = () => 0.97;
  });
  await play(page, "gallop");
  await advanceUntil(page, '[data-pony-hurdle-phase="fallen"]', 4500);
  await advanceUntil(page, '[data-pony-action="snort"]', 2400);
  await advanceUntil(page, '[data-pony-action="gallop"]', 1800);
});

test("the pony taps a puddle before jumping in and splashing", async ({ page }) => {
  await startPony(page);
  await addWideGroupCard(page);
  await advanceUntil(page, '[data-pony-puddle="tap"]', 75000);
  await expect(page.locator("[data-pony-puddle]")).toBeVisible();
  await advanceUntil(page, '[data-pony-reaction="puddle"][data-pony-action="jump"]', 5000);
  await advanceUntil(page, '[data-pony-puddle="splash"]', 3000);
  const puddle = page.locator('[data-pony-puddle="splash"]');
  const water = await puddle.boundingBox();
  const pony = await ponyBox(page);
  if (!water) throw new Error("Puddle is missing");
  await expectOnGroupCard(page, water);
  await expectOnGroupCard(page, pony);
  expect(Math.abs(water.x + water.width / 2 - pony.x - pony.width / 2)).toBeLessThan(
    pony.width / 4,
  );
  await page.clock.runFor(120);
  await expect(puddle.locator("g")).toBeVisible();
  await page.clock.runFor(4500);
  await expect(page.locator("[data-pony-puddle]")).toHaveCount(0);
});

for (const [width, chance, count] of [
  [1280, 0.73, 2],
  [1280, 0.05, 2],
  [2400, 0.05, 3],
]) {
  test(`the pony clears ${count} race hurdles at ${width}px with roll ${chance}`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 720 });
    await startPony(page);
    await page.evaluate((roll) => {
      Math.random = () => roll;
      const pony = document.querySelector("[data-pony-action]")!;
      let jumping = false;
      let jumps = 0;
      new MutationObserver(() => {
        const next = pony.getAttribute("data-pony-action") === "jump";
        if (next && !jumping) pony.setAttribute("data-test-jumps", String(++jumps));
        jumping = next;
      }).observe(pony, { attributes: true, attributeFilter: ["data-pony-action"] });
      function checkClearance() {
        const hooves = pony.querySelectorAll('polygon[fill="#0A5FC8"]');
        const hurdles = pony.querySelectorAll("[data-pony-hurdle]");
        for (const hurdle of hurdles) {
          const bar = hurdle.getBoundingClientRect();
          for (const hoof of hooves) {
            const box = hoof.getBoundingClientRect();
            if (box.right > bar.left && box.left < bar.right && box.bottom > bar.top + 1) {
              pony.setAttribute("data-test-hit-hurdle", "");
            }
          }
        }
        requestAnimationFrame(checkClearance);
      }
      requestAnimationFrame(checkClearance);
    }, chance);
    await play(page, "gallop");
    const hurdles = page.locator("[data-pony-hurdle]");
    await page.clock.runFor(400);
    await expect(hurdles).toHaveCount(count);
    await expect(hurdles.first()).toBeVisible();
    for (let elapsed = 0; (await hurdles.count()) && elapsed < 6500; elapsed += 32) {
      await page.clock.runFor(32);
    }
    await expect(hurdles).toHaveCount(0);
    const pony = page.locator("[data-pony-action]");
    await expect(pony).toHaveAttribute("data-test-jumps", String(count));
    await expect(pony).not.toHaveAttribute("data-test-hit-hurdle");
    await expect(pony).toHaveAttribute("data-pony-action", "gallop");
  });
}
