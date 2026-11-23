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
