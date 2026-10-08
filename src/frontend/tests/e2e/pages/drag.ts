import type { CDPSession, Locator, Page } from "@playwright/test";

export type Point = { x: number; y: number };

export type Pointer = {
  down(at: Point): Promise<void>;
  move(to: Point): Promise<void>;
  up(): Promise<void>;
  at(): Point;
};

export function mousePointer(page: Page): Pointer {
  let here: Point = { x: 0, y: 0 };
  return {
    async down(at) {
      await page.mouse.move(at.x, at.y);
      await page.mouse.down();
      here = at;
    },
    async move(to) {
      await page.mouse.move(to.x, to.y);
      here = to;
    },
    async up() {
      await page.mouse.up();
    },
    at: () => here,
  };
}

export async function touchPointer(page: Page): Promise<Pointer> {
  const cdp: CDPSession = await page.context().newCDPSession(page);
  let here: Point = { x: 0, y: 0 };
  const send = (type: string, points: Point[]) =>
    cdp.send("Input.dispatchTouchEvent", {
      type: type as "touchStart",
      touchPoints: points.map((p) => ({ x: p.x, y: p.y })),
    });
  return {
    async down(at) {
      await send("touchStart", [at]);
      here = at;
    },
    async move(to) {
      await send("touchMove", [to]);
      here = to;
    },
    async up() {
      await send("touchEnd", []);
    },
    at: () => here,
  };
}

export async function frame(page: Page) {
  await page.evaluate(async () => {
    const tick = () => new Promise<void>((r) => requestAnimationFrame(() => r()));
    await tick();
    await tick();
    const moving = () =>
      document
        .getAnimations()
        .some((a) =>
          ((a.effect as KeyframeEffect | null)?.target as Element | null)?.classList?.contains(
            "dnd-slot",
          ),
        );
    for (let i = 0; i < 60 && moving(); i++) await tick();
  });
}

export async function glide(page: Page, pointer: Pointer, to: Point, steps = 8) {
  const from = pointer.at();
  for (let i = 1; i <= steps; i++) {
    await pointer.move({
      x: from.x + ((to.x - from.x) * i) / steps,
      y: from.y + ((to.y - from.y) * i) / steps,
    });
  }
  await frame(page);
}

export async function centerOf(locator: Locator): Promise<Point> {
  const box = await locator.boundingBox();
  if (!box) throw new Error("no box");
  return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
}

export async function pick(page: Page, pointer: Pointer, handle: Locator) {
  const start = await centerOf(handle);
  await pointer.down(start);
  await glide(page, pointer, { x: start.x, y: start.y + 6 }, 3);
}

export async function hover(
  page: Page,
  pointer: Pointer,
  target: Locator,
  where: "before" | "after",
) {
  for (let i = 0; i < 6; i++) {
    const box = await target.boundingBox();
    if (!box) throw new Error("no target box");
    const to = { x: pointer.at().x, y: box.y + box.height * (where === "before" ? 0.25 : 0.75) };
    if (Math.abs(to.y - pointer.at().y) < 1) return;
    await glide(page, pointer, to);
  }
}

export async function dragTo(
  page: Page,
  handle: Locator,
  target: Locator,
  where: "before" | "after",
  pointer: Pointer = mousePointer(page),
) {
  await pick(page, pointer, handle);
  await hover(page, pointer, target, where);
  await pointer.up();
}
