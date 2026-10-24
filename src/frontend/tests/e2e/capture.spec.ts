import { expect, test, type Page, type Route } from "@playwright/test";

import { signedIn } from "./pages/session";

test.use({ timezoneId: "UTC" });

type Win = Record<string, unknown>;
type Refusal = { status: number; error: string };
type Handler = (method: string, query: URLSearchParams) => Win | number | Refusal;
type Events = (since: number) => { events: unknown[]; next: number };

function isRefusal(v: Win | number | Refusal): v is Refusal {
  return typeof v === "object" && typeof v.status === "number" && typeof v.error === "string";
}

const KERNEL_REFUSAL =
  "this kernel will not take the capture rules: they need xt_conntrack, xt_mark, xt_limit, " +
  "xt_string, xt_length, xt_connbytes and xt_NFLOG. The daemon's log names what it lacks";

const BLIND_PROBE =
  "the kernel could not be asked which capture extensions it has; " +
  "the daemon's log names the error. Routing is not affected";

const T0 = 1790000000;

const STARTED = { running: true, endsAt: T0 + 300, secondsLeft: 300, token: "0123456789abcdef" };

function leak(seq: number, at: number, name: string) {
  return {
    seq,
    at,
    kind: "bypass",
    client: "192.168.1.42",
    dst: `104.21.0.${seq}`,
    port: 443,
    proto: "udp",
    how: "sni",
    name,
    group: { id: "g1", name: "media" },
    repeats: 0,
  };
}

function once(events: unknown[]): Events {
  return (since) => (since === 0 ? { events, next: events.length } : { events: [], next: since });
}

async function routes(page: Page, onCapture: Handler, events: Events = once([])) {
  await signedIn(page);
  await page.route("**/groups?with_rules=true", (route) => route.fulfill({ json: { groups: [] } }));
  await page.route(/\/subscriptions(\?.*)?$/, (route) =>
    route.fulfill({ json: { subscriptions: [] } }),
  );
  await page.route("**/interfaces", (route) => route.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route(/\/system\/events(\?.*)?$/, (route) => {
    const since = Number(new URL(route.request().url()).searchParams.get("since") ?? 0);
    route.fulfill({ json: { ...events(since), dropped: 0, boot: "b1" } });
  });
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
}

async function shell(page: Page, onCapture: Handler, events?: Events) {
  await routes(page, onCapture, events);
  await page.goto("/journal/capture");
}

async function inRussian(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("locale", JSON.stringify({ value: "ru" }));
  });
}

// Catches the idle card missing its explanation or start button, or a timer or rows shown before any run.
test("Захват shows what capture does before any run", async ({ page }) => {
  await inRussian(page);
  await shell(page, () => ({ running: false }));

  await expect(page.getByText("Захват утечек на 5 минут")).toBeVisible();
  await expect(page.getByText("на диск ничего не пишется")).toBeVisible();
  await expect(page.getByRole("button", { name: "Начать захват" })).toBeEnabled();
  await expect(page.getByRole("timer")).toHaveCount(0);
  await expect(page.getByRole("progressbar")).toHaveCount(0);
  await expect(page.locator(".cap-pane")).toHaveCount(0);
  await expect(page.getByRole("tab", { name: "Захват", exact: true })).toHaveText("Захват");
});

// Catches the start not counting down from the daemon's answer, or the progress bar not following it.
test("the start button starts a capture and counts down from the daemon's answer", async ({
  page,
}) => {
  let started = false;
  await shell(page, (method) => {
    if (method === "POST") {
      started = true;
      return STARTED;
    }
    return started ? { running: true, endsAt: T0 + 298, secondsLeft: 298 } : { running: false };
  });

  await page.getByRole("button", { name: "Start capture" }).click();

  const timer = page.locator(".cap-clock");
  await expect(timer).toHaveText("5:00");
  await expect(page.getByText("Capturing", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Stop" })).toBeEnabled();
  await expect(page.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "0");
  await expect(page.getByText("No leaks yet.")).toBeVisible();

  await expect(timer).toHaveText("4:58", { timeout: 5000 });
  await expect(page.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "2");
});

// Catches the label clock shown only on the Capture tab, hidden or spilling at 360 px, renaming the tab, or kept after the capture ends.
test("a running capture counts down on its tab label from any tab", async ({ page }) => {
  let running = true;
  await shell(page, () =>
    running
      ? { running: true, endsAt: T0 + 170, secondsLeft: 170 }
      : {
          running: false,
          last: {
            startedAt: T0 - 130,
            endedAt: T0 + 170,
            ended: "reached-end",
            leaks: 3,
            summary: [],
          },
        },
  );
  const tab = page.getByRole("tab", { name: "Capture", exact: true });
  const label = tab.locator(".tab-clock");

  await expect(label).toHaveText("2:50");
  await page.getByRole("tab", { name: "Events", exact: true }).click();
  await expect(label).toHaveText("2:50");
  await expect(tab.locator(".cdot")).toBeVisible();
  await page.getByRole("tab", { name: "DNS stats", exact: true }).click();
  await expect(label).toHaveText("2:50");
  await expect(label).toHaveCSS("color", "rgb(248, 81, 73)");
  await page.setViewportSize({ width: 360, height: 740 });
  await expect(label).toHaveText("2:50");
  await expect(label).toBeVisible();
  expect((await label.boundingBox())!.x + (await label.boundingBox())!.width).toBeLessThanOrEqual(
    360,
  );
  await page.setViewportSize({ width: 1280, height: 720 });

  running = false;
  await expect(label).toHaveCount(0, { timeout: 5000 });
  await expect(tab).toHaveText("Capture3");
});

// Catches the summary read from log lines or lost on a reload, rows from outside the span shown, a row at its first second or one second past its end dropped, or the Leaks chip kept.
test("a finished capture shows its span, leaks and summary after a reload", async ({ page }) => {
  const last = {
    startedAt: T0,
    endedAt: T0 + 300,
    ended: "reached-end",
    leaks: 4,
    summary: ["159 packets read, 4 bypasses reported.", "3 packets carried no server name."],
  };
  await shell(
    page,
    () => ({ running: false, last }),
    once([
      leak(1, T0 - 1, "before.example.org"),
      leak(2, T0, "first.example.org"),
      leak(6, T0 + 20, "bank.example.org"),
      {
        seq: 3,
        at: T0 + 30,
        kind: "log",
        level: "info",
        source: "fircd",
        message: "Not the summary.",
      },
      leak(4, T0 + 300, "cdn.example.net"),
      leak(5, T0 + 301, "late.example.org"),
      leak(7, T0 + 302, "after.example.org"),
    ]),
  );

  const check = async () => {
    await expect(page.getByText("Capture finished")).toBeVisible();
    await expect(page.locator(".cap-sub")).toHaveText("14:13–14:18 · leaks: 4");
    await expect(page.locator(".cap-sum p")).toHaveText([
      "159 packets read, 4 bypasses reported.",
      "3 packets carried no server name.",
    ]);
    const rows = page.locator(".cap-pane .row");
    await expect(rows).toHaveCount(4);
    await expect(rows.nth(0)).toContainText("first.example.org");
    await expect(rows.nth(1)).toContainText("bank.example.org");
    await expect(rows.nth(2)).toContainText("cdn.example.net");
    await expect(rows.nth(3)).toContainText("late.example.org");
    await expect(page.locator(".cap-pane")).not.toContainText("Leaks");
    await expect(page.getByRole("button", { name: "Start again" })).toBeEnabled();
    await expect(page.getByRole("timer")).toHaveCount(0);
  };
  await check();
  await page.reload();
  await check();
});

// Catches a finished capture without leaks shown as idle, or with a leak count.
test("a capture that found nothing says so", async ({ page }) => {
  await shell(page, () => ({
    running: false,
    last: { startedAt: T0, endedAt: T0 + 300, ended: "reached-end", leaks: 0, summary: [] },
  }));

  await expect(page.locator(".cap-sub")).toHaveText("14:13–14:18 · no leaks");
  await expect(page.getByText("This capture had no leaks.")).toBeVisible();
  await expect(page.locator(".cap-sum")).toHaveCount(0);
});

// Catches Stop without the start's token, or the stop's own answer ignored until the next idle poll.
test("Остановить stops it", async ({ page }) => {
  await inRussian(page);
  let deleteToken: string | null = null;
  let started = false;
  let stopped = false;
  const last = {
    startedAt: T0,
    endedAt: T0 + 40,
    ended: "stopped",
    leaks: 1,
    summary: ["12 packets read, 1 bypass reported."],
  };
  await shell(page, (method, query) => {
    if (method === "POST") {
      started = true;
      return STARTED;
    }
    if (method === "DELETE") {
      deleteToken = query.get("token");
      stopped = true;
      return { running: false, last };
    }
    if (stopped) return { running: false, last };
    return started ? { running: true, endsAt: T0 + 300, secondsLeft: 300 } : { running: false };
  });

  await page.getByRole("button", { name: "Начать захват" }).click();
  await expect(page.getByText("Идёт захват")).toBeVisible();
  await page.getByRole("button", { name: "Остановить" }).click();

  await expect.poll(() => deleteToken).toBe("0123456789abcdef");
  await expect(page.getByText("Захват завершён")).toBeVisible({ timeout: 1500 });
  await expect(page.locator(".cap-sub")).toHaveText("14:13–14:14 · утечек: 1 · остановлен");
  await expect(page.locator(".cap-sum")).toContainText("Итог от демона");
  await expect(page.getByRole("button", { name: "Начать заново" })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Остановить" })).toHaveCount(0);
});

// Catches a capture that failed shown as if it ran to its end.
test("a capture that failed says so", async ({ page }) => {
  await shell(page, () => ({
    running: false,
    last: { startedAt: T0, endedAt: T0 + 60, ended: "failed", leaks: 0, summary: [] },
  }));

  await expect(page.locator(".cap-sub")).toHaveText("14:13–14:14 · no leaks · ended with an error");
  await expect(page.locator(".cap-sub .err")).toHaveText("ended with an error");
});

// Catches a Stop offered for a capture this page did not start, or the reason left unsaid.
test("a capture started elsewhere says so and offers no stop", async ({ page }) => {
  await shell(page, () => ({ running: true, endsAt: T0 + 120, secondsLeft: 120 }));

  await expect(page.locator(".cap-clock")).toHaveText("2:00");
  await expect(page.getByText("Started elsewhere: only there can it be stopped.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Stop" })).toHaveCount(0);
});

// Catches Clear view on Events emptying the leak rows of a running capture, or a leak from before it started shown among them.
test("Clear view on Events leaves the capture's rows", async ({ page }) => {
  await shell(
    page,
    () => ({ running: true, endsAt: T0 + 300, secondsLeft: 200 }),
    once([
      leak(1, T0 - 10, "before.example.org"),
      leak(2, T0 + 5, "bank.example.org"),
      { seq: 3, at: T0 + 6, kind: "log", level: "info", source: "fircd", message: "group up" },
    ]),
  );
  const rows = page.locator(".cap-pane .row");
  await expect(rows).toHaveCount(1);
  await expect(page.locator(".cap-pane")).not.toContainText("before.example.org");

  await page.getByRole("tab", { name: "Events", exact: true }).click();
  await expect(page.locator(".pane .row")).toHaveCount(1);
  await page.getByRole("button", { name: "Clear view" }).click();
  await expect(page.locator(".pane .row")).toHaveCount(0);

  await page.getByRole("tab", { name: "Capture", exact: true }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("bank.example.org");
  await expect(page.locator(".cap-pane")).not.toContainText("before.example.org");
});

// Catches the leak list left at its top while new rows arrive below the fold.
test("the leak list follows new rows while a capture runs", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 600 });
  let batches = 1;
  const all = Array.from({ length: 60 }, (_, i) => leak(i + 1, T0 + i, `n${i + 1}.example.org`));
  await shell(
    page,
    () => ({ running: true, endsAt: T0 + 300, secondsLeft: 200 }),
    (since) => {
      const upto = Math.min(all.length, batches * 30);
      return { events: all.slice(since, upto), next: upto };
    },
  );
  const pane = page.locator(".cap-pane");
  await expect(pane.locator(".row")).toHaveCount(30);
  const atBottom = () =>
    pane.evaluate(
      (el) =>
        el.scrollHeight > el.clientHeight && el.scrollTop + el.clientHeight >= el.scrollHeight - 2,
    );
  await expect.poll(atBottom).toBe(true);

  batches = 2;
  await expect(pane.locator(".row")).toHaveCount(60, { timeout: 5000 });
  await expect.poll(atBottom).toBe(true);
  await expect(pane.locator(".row").last()).toBeInViewport();
});

// Catches the refusal notice fading on the next idle GET; only a successful POST may clear it.
test("a kernel that refuses the rules is quoted, and stays quoted past the next poll", async ({
  page,
}) => {
  await shell(page, (method) => (method === "POST" ? 501 : { running: false }));

  await page.getByRole("button", { name: "Start capture" }).click();

  const notice = page.locator(".cap-err").filter({ hasText: "cannot capture" });
  await expect(notice).toContainText("xt_string");
  await expect(page.getByText("did not answer for the log")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Start capture" })).toBeDisabled();

  await page.waitForTimeout(11000);
  await expect(notice).toContainText("xt_string");
  await expect(page.getByRole("button", { name: "Start capture" })).toBeDisabled();
});

// Catches a blind kernel probe shown as a missing extension, or not shown at all.
test("a probe that could not ask the kernel is quoted as its own refusal", async ({ page }) => {
  await shell(page, (method) =>
    method === "POST" ? { status: 503, error: BLIND_PROBE } : { running: false },
  );

  await page.getByRole("button", { name: "Start capture" }).click();

  await expect(page.locator(".cap-err").filter({ hasText: "could not be asked" })).toBeVisible();
  await expect(page.getByText("cannot capture")).toHaveCount(0);
});

// Catches the countdown kept for a capture the daemon says has ended.
test("a capture the daemon no longer has stops counting down", async ({ page }) => {
  let started = false;
  let stillRunning = true;
  await shell(page, (method) => {
    if (method === "POST") {
      started = true;
      return STARTED;
    }
    if (!started) return { running: false };
    return stillRunning
      ? { running: true, endsAt: T0 + 298, secondsLeft: 298 }
      : { running: false };
  });

  await page.getByRole("button", { name: "Start capture" }).click();
  await expect(page.locator(".cap-clock")).toHaveText("5:00");

  stillRunning = false;
  await expect(page.getByRole("button", { name: "Start capture" })).toBeVisible({ timeout: 5000 });
  await expect(page.getByRole("timer")).toHaveCount(0);
});

// Catches a 409 on Stop leaving the token held and a Stop button that fails forever.
test("a stop the daemon no longer recognizes drops the token and the button returns", async ({
  page,
}) => {
  let started = false;
  await shell(page, (method) => {
    if (method === "POST") {
      started = true;
      return STARTED;
    }
    if (method === "DELETE") {
      return { status: 409, error: "the running capture is not the one this token names" };
    }
    return started ? { running: true, endsAt: T0 + 300, secondsLeft: 300 } : { running: false };
  });

  await page.getByRole("button", { name: "Start capture" }).click();
  await expect(page.getByRole("button", { name: "Stop" })).toBeEnabled();
  await page.getByRole("button", { name: "Stop" }).click();

  await expect(page.getByRole("button", { name: "Stop" })).toHaveCount(0);
  await expect(page.locator(".cap-clock")).toBeVisible();
});

// Catches a stale poll answered after the start undoing it with "nothing is running".
test("a slow poll from before the start does not undo it", async ({ page }) => {
  let started = false;
  let firstGetSeen = false;
  await routes(page, () => ({ running: false }));
  await page.route(/\/system\/capture(\?.*)?$/, async (route: Route) => {
    const req = route.request();
    if (req.method() === "POST") {
      started = true;
      await route.fulfill({ json: STARTED });
      return;
    }
    if (req.method() === "GET" && !started && !firstGetSeen) {
      firstGetSeen = true;
      await new Promise((resolve) => setTimeout(resolve, 1500));
      await route.fulfill({ json: { running: false } });
      return;
    }
    await route.fulfill({
      json: started ? { running: true, endsAt: T0 + 300, secondsLeft: 300 } : { running: false },
    });
  });
  await page.goto("/journal/capture");

  await page.getByRole("button", { name: "Start capture" }).click();
  await expect(page.locator(".cap-clock")).toHaveText("5:00");

  await page.waitForTimeout(1800);
  await expect(page.locator(".cap-clock")).toHaveText("5:00");
  await expect(page.getByRole("button", { name: "Stop" })).toBeEnabled();
});
