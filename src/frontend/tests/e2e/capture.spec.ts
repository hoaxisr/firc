import { expect, test, type Page, type Route } from "@playwright/test";

import { signedIn } from "./pages/session";

type Win = Record<string, unknown>;
type Refusal = { status: number; error: string };
type Handler = (method: string, query: URLSearchParams) => Win | number | Refusal;

function isRefusal(v: Win | number | Refusal): v is Refusal {
  return typeof v === "object" && typeof v.status === "number" && typeof v.error === "string";
}

const KERNEL_REFUSAL =
  "this kernel will not take the capture rules: they need xt_conntrack, xt_mark, xt_limit, " +
  "xt_string, xt_length, xt_connbytes and xt_NFLOG. The line it refused is in the daemon's log";

async function shell(page: Page, onCapture: Handler) {
  await signedIn(page);
  await page.route("**/groups?with_rules=true", (route) => route.fulfill({ json: { groups: [] } }));
  await page.route(/\/subscriptions(\?.*)?$/, (route) =>
    route.fulfill({ json: { subscriptions: [] } }),
  );
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route(/\/system\/events(\?.*)?$/, (route) =>
    route.fulfill({ json: { events: [], next: 0, dropped: 0, level: "info" } }),
  );
  await page.route(/\/system\/capture(\?.*)?$/, (route) => {
    const req = route.request();
    const query = new URL(req.url()).searchParams;
    const answer = onCapture(req.method(), query);
    if (typeof answer === "number") {
      route.fulfill({ status: answer, json: { error: KERNEL_REFUSAL } });
      return;
    }
    if (isRefusal(answer)) {
      route.fulfill({ status: answer.status, json: { error: answer.error } });
      return;
    }
    route.fulfill({ json: answer });
  });

  await page.addInitScript(() => localStorage.removeItem("capture_token"));
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();
}

test("the capture button starts a capture and counts down from the daemon's answer", async ({
  page,
}) => {
  let started = false;
  await shell(page, (method) => {
    if (method === "POST") {
      started = true;
      return {
        running: true,
        endsAt: 1789591253 + 300,
        secondsLeft: 300,
        token: "0123456789abcdef",
      };
    }
    return started
      ? { running: true, endsAt: 1789591253 + 298, secondsLeft: 298 }
      : { running: false };
  });

  await expect(page.getByRole("button", { name: "Capture 5 min" })).toBeVisible();
  await page.getByRole("button", { name: "Capture 5 min" }).click();

  await expect(page.locator(".capturing")).toHaveText("5:00");
  await expect(page.getByRole("button", { name: "Stop" })).toBeEnabled();

  await expect(page.locator(".capturing")).toHaveText("4:58", { timeout: 5000 });
});

test("a capture started elsewhere is shown without a stop button", async ({ page }) => {
  await shell(page, () => ({ running: true, endsAt: 1789591253 + 120, secondsLeft: 120 }));

  await expect(page.locator(".capturing")).toHaveText("2:00");
  await expect(page.getByRole("button", { name: "Stop" })).toHaveCount(0);
});

// Catches the refusal notice fading on the next idle GET; only a successful POST may clear it.
test("a kernel that refuses the rules is quoted, and stays quoted past the next poll", async ({
  page,
}) => {
  await shell(page, (method) => (method === "POST" ? 501 : { running: false }));

  await page.getByRole("button", { name: "Capture 5 min" }).click();

  const notice = page.locator(".status .err").filter({ hasText: "cannot capture" });
  await expect(notice).toContainText("xt_string");
  await expect(page.getByText("did not answer for the log")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Capture 5 min" })).toBeDisabled();

  // Idle polling runs every 10 s; wait past it.
  await page.waitForTimeout(11000);
  await expect(notice).toContainText("xt_string");
  await expect(page.getByRole("button", { name: "Capture 5 min" })).toBeDisabled();
});

// Catches the button keeping a countdown for a capture the daemon says has ended.
test("a capture the daemon no longer has stops counting down", async ({ page }) => {
  let started = false;
  let stillRunning = true;
  await shell(page, (method) => {
    if (method === "POST") {
      started = true;
      return {
        running: true,
        endsAt: 1789591253 + 300,
        secondsLeft: 300,
        token: "0123456789abcdef",
      };
    }
    if (!started) return { running: false };
    return stillRunning
      ? { running: true, endsAt: 1789591253 + 298, secondsLeft: 298 }
      : { running: false };
  });

  await page.getByRole("button", { name: "Capture 5 min" }).click();
  await expect(page.locator(".capturing")).toHaveText("5:00");

  stillRunning = false;
  await expect(page.getByRole("button", { name: "Capture 5 min" })).toBeVisible({ timeout: 5000 });
  await expect(page.locator(".capturing")).toHaveCount(0);
});

// Catches Stop not sending back the token the start returned.
test("Stop sends the token the start returned, and the button returns", async ({ page }) => {
  let deleteToken: string | null = null;
  let started = false;
  let stopped = false;
  await shell(page, (method, query) => {
    if (method === "POST") {
      started = true;
      return {
        running: true,
        endsAt: 1789591253 + 300,
        secondsLeft: 300,
        token: "0123456789abcdef",
      };
    }
    if (method === "DELETE") {
      deleteToken = query.get("token");
      stopped = true;
      return { running: false };
    }
    if (stopped) return { running: false };
    return started
      ? { running: true, endsAt: 1789591253 + 300, secondsLeft: 300 }
      : { running: false };
  });

  await page.getByRole("button", { name: "Capture 5 min" }).click();
  await expect(page.getByRole("button", { name: "Stop" })).toBeEnabled();
  await page.getByRole("button", { name: "Stop" }).click();

  await expect.poll(() => deleteToken).toBe("0123456789abcdef");
  await expect(page.getByRole("button", { name: "Capture 5 min" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Stop" })).toHaveCount(0);
});

// Catches a 409 on Stop leaving the token held and a Stop button that fails forever.
test("a stop the daemon no longer recognizes drops the token and the button returns", async ({
  page,
}) => {
  let started = false;
  await shell(page, (method) => {
    if (method === "POST") {
      started = true;
      return {
        running: true,
        endsAt: 1789591253 + 300,
        secondsLeft: 300,
        token: "0123456789abcdef",
      };
    }
    if (method === "DELETE") {
      return { status: 409, error: "the running capture is not the one this token names" };
    }
    return started
      ? { running: true, endsAt: 1789591253 + 300, secondsLeft: 300 }
      : { running: false };
  });

  await page.getByRole("button", { name: "Capture 5 min" }).click();
  await expect(page.getByRole("button", { name: "Stop" })).toBeEnabled();
  await page.getByRole("button", { name: "Stop" }).click();

  await expect(page.getByRole("button", { name: "Stop" })).toHaveCount(0);
  await expect(page.locator(".capturing")).toBeVisible();
});

// Catches a stale poll answered after the start undoing it with "nothing is running".
test("a slow poll from before the start does not undo it", async ({ page }) => {
  let started = false;
  let firstGetSeen = false;

  await signedIn(page);
  await page.route("**/groups?with_rules=true", (route) => route.fulfill({ json: { groups: [] } }));
  await page.route(/\/subscriptions(\?.*)?$/, (route) =>
    route.fulfill({ json: { subscriptions: [] } }),
  );
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route(/\/system\/events(\?.*)?$/, (route) =>
    route.fulfill({ json: { events: [], next: 0, dropped: 0, level: "info" } }),
  );
  await page.route(/\/system\/capture(\?.*)?$/, async (route: Route) => {
    const req = route.request();
    if (req.method() === "POST") {
      started = true;
      await route.fulfill({
        json: {
          running: true,
          endsAt: 1789591253 + 300,
          secondsLeft: 300,
          token: "0123456789abcdef",
        },
      });
      return;
    }
    if (req.method() === "GET" && !started && !firstGetSeen) {
      firstGetSeen = true;
      // Hold the mount's first poll open past the click, then answer it stale: that hold is the race.
      await new Promise((resolve) => setTimeout(resolve, 1500));
      await route.fulfill({ json: { running: false } });
      return;
    }
    await route.fulfill({
      json: started
        ? { running: true, endsAt: 1789591253 + 300, secondsLeft: 300 }
        : { running: false },
    });
  });

  await page.addInitScript(() => localStorage.removeItem("capture_token"));
  await page.goto("/");
  await page.getByRole("tab", { name: "Journal" }).click();

  await page.getByRole("button", { name: "Capture 5 min" }).click();
  await expect(page.locator(".capturing")).toHaveText("5:00");

  await page.waitForTimeout(1800);
  await expect(page.locator(".capturing")).toHaveText("5:00");
  await expect(page.getByRole("button", { name: "Stop" })).toBeEnabled();
});
