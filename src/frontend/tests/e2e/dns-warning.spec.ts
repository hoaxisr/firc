import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

const busy = {
  listening: false,
  port: 3553,
  proto: "udp",
  error: "[::]:3553/udp: address already in use by socat (pid 812)",
  holder: { name: "socat", pid: 812 },
};
const free = { listening: true, port: 3553, proto: "", error: "", holder: null };

async function open(page: Page, answers: () => unknown) {
  await signedIn(page);
  await page.clock.install();
  await page.route("**/groups?with_rules=true", (route) => route.fulfill({ json: { groups: [] } }));
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/dnsproxy", (route) => route.fulfill({ json: answers() }));
  await page.goto("/");
}

const warning = (page: Page) => page.getByTestId("dns-warning");

// Catches a busy port that goes unnoticed, or a warning without the port, protocol, program and pid.
test("a taken DNS port puts a warning over the page that names who holds it", async ({ page }) => {
  await open(page, () => busy);
  await expect(page.getByRole("dialog")).toContainText("DNS is not working");
  await expect(warning(page)).toContainText("Port 3553/udp is taken by socat (pid 812).");
  await expect(warning(page)).toContainText("Stop socat, or give firc another DNS proxy port");
  await expect(warning(page)).toContainText(busy.error);
});

// Catches no warning when /proc did not show the holder, or "undefined" in its place.
test("an unknown holder is another program", async ({ page }) => {
  await open(page, () => ({ ...busy, holder: null, error: "[::]:3553/udp: address in use" }));
  await expect(warning(page)).toContainText("Port 3553/udp is taken by another program.");
  await expect(warning(page)).not.toContainText("undefined");
});

// Catches a warning that Escape dismisses for good, or one that is back before its minute is up.
test("Escape hides it for a minute only", async ({ page }) => {
  await open(page, () => busy);
  await expect(warning(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(warning(page)).toHaveCount(0);
  await page.clock.runFor(30_000);
  await expect(warning(page)).toHaveCount(0);
  await page.clock.runFor(31_000);
  await expect(warning(page)).toBeVisible();
});

// Catches Open Settings that does not lead there, or a warning that stays away on the next page.
test("Open Settings goes there, and the warning comes back over it", async ({ page }) => {
  await open(page, () => busy);
  await page.getByRole("button", { name: "Open Settings" }).click();
  await expect(warning(page)).toHaveCount(0);
  await expect(page).toHaveURL(/\/settings/);
  await page.clock.runFor(61_000);
  await expect(warning(page)).toBeVisible();
  await expect(page).toHaveURL(/\/settings/);
});

// Catches a warning left up after the daemon took its port, which would need a reload to clear.
test("it goes away once the daemon has the port", async ({ page }) => {
  let state: unknown = busy;
  await open(page, () => state);
  await expect(warning(page)).toBeVisible();
  state = free;
  await page.clock.runFor(10_000);
  await expect(warning(page)).toHaveCount(0);
});

// Catches a warning shown while the proxy listens.
test("no warning while the proxy listens", async ({ page }) => {
  await open(page, () => free);
  await expect(page.getByRole("tab", { name: "Groups" })).toBeVisible();
  await page.clock.runFor(10_000);
  await expect(warning(page)).toHaveCount(0);
});

// Catches the 10 s poll left running while the proxy listens, which costs every open tab a request forever.
test("a listening proxy is asked once a minute, a down one every ten seconds", async ({ page }) => {
  let asked = 0;
  let state: unknown = free;
  await open(page, () => {
    asked++;
    return state;
  });
  await expect(page.getByRole("tab", { name: "Groups" })).toBeVisible();
  await expect.poll(() => asked).toBe(1);
  await page.clock.runFor(50_000);
  expect(asked).toBe(1);
  await page.clock.runFor(11_000);
  await expect.poll(() => asked).toBe(2);
  state = busy;
  await page.clock.runFor(61_000);
  await expect(warning(page)).toBeVisible();
  const down = asked;
  await page.clock.runFor(10_500);
  await expect.poll(() => asked).toBe(down + 1);
});
