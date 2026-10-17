import { t } from "../../data/locale.svelte";
import { ask } from "../../utils/confirm.svelte";
import { openRestartOverlay, POLL_MS, POLL_TIMEOUT_MS, settings, sleep } from "./settings.svelte";

import { toast } from "../../utils/events";
import { fetcher, HttpError } from "../../utils/fetcher";
import {
  running,
  UPDATE_LIMIT_MS,
  updatePhase,
  type RateLimited,
  type UpdateRelease,
  type UpdateRes,
} from "./update";

export const update = $state({
  res: null as UpdateRes | null,
  checking: false,
  checkError: "",
  installing: false,
});

let generation = 0;

type Target = { version: string; revision: number };

export async function loadUpdate(): Promise<void> {
  const gen = generation;
  try {
    const res = await fetcher.get<UpdateRes>("/system/update", { quiet: true });
    if (gen !== generation) return;
    update.res = res;
    const latest = res.check?.latest;
    if (!running(res) || update.installing) return;
    if (latest) void followInstall(latest);
    else await (settling ??= settle().finally(() => (settling = null)));
  } catch {
    return;
  }
}

let settling: Promise<void> | null = null;

async function settle(): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < UPDATE_LIMIT_MS) {
    await sleep(POLL_MS);
    let res: UpdateRes;
    try {
      res = await poll();
    } catch (error) {
      if (unauthorized(error)) return;
      continue;
    }
    generation++;
    update.res = res;
    if (!running(res)) return;
  }
}

function bodyOf(error: HttpError): RateLimited {
  try {
    return JSON.parse(error.message) as RateLimited;
  } catch {
    return { error: error.message };
  }
}

function failure(error: unknown): string {
  if (!(error instanceof HttpError)) return t("No answer from the daemon");
  const body = bodyOf(error);
  if (error.status === 429 && typeof body.resetAt === "number") {
    const time = new Date(body.resetAt * 1000).toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    });
    return t("GitHub refuses more checks for now, try again after {time}").replace(
      "{time}",
      () => time,
    );
  }
  return body.error || error.message;
}

const unauthorized = (error: unknown) => error instanceof Error && error.message === "Unauthorized";

export async function checkUpdate(): Promise<void> {
  if (update.checking || update.installing || running(update.res)) return;
  update.checking = true;
  update.checkError = "";
  try {
    update.res = await fetcher<UpdateRes>("/system/update/check", { method: "POST", quiet: true });
  } catch (error) {
    update.checkError = failure(error);
  } finally {
    generation++;
    update.checking = false;
  }
}

const poll = () =>
  fetcher.get<UpdateRes>("/system/update", {
    quiet: true,
    signal: AbortSignal.timeout(POLL_TIMEOUT_MS),
  });

export async function installUpdate(): Promise<void> {
  const latest = update.res?.check?.latest;
  if (!latest || update.checking || update.installing || running(update.res)) return;
  const ok = await ask({
    tone: "warn",
    title: t("Install {version}?").replace("{version}", () => latest.version),
    message: t(
      "DNS, the WebUI and every tunnel stop for the restart, tens of seconds on mipsel. Settings saved and waiting for a restart take effect.",
    ),
    confirm: t("Install"),
  });
  if (!ok || update.checking || update.installing) return;
  update.installing = true;
  try {
    await fetcher.post("/system/update/install", { version: latest.tag }, { quiet: true });
  } catch (error) {
    update.installing = false;
    if (!unauthorized(error)) toast.error(`${t("Request failed")}: ${failure(error)}`);
    return;
  }
  await followInstall(latest);
}

const DROPPED_POLLS = 3;

async function followInstall(latest: UpdateRelease): Promise<void> {
  update.installing = true;
  const target = { version: latest.version, revision: latest.revision };
  if (await followProgress()) await waitForUpdate(target, latest.tag);
  else update.installing = false;
}

async function followProgress(): Promise<boolean> {
  const started = Date.now();
  let dropped = 0;
  while (Date.now() - started < UPDATE_LIMIT_MS) {
    await sleep(POLL_MS);
    let res: UpdateRes;
    try {
      res = await poll();
    } catch (error) {
      if (unauthorized(error)) return false;
      if (++dropped >= DROPPED_POLLS) return true;
      continue;
    }
    dropped = 0;
    generation++;
    update.res = res;
    if (res.state === "downloading" || res.state === "verifying") continue;
    return res.state !== "failed";
  }
  return false;
}

export async function waitForUpdate(
  target: { version: string; revision: number },
  tag: string,
): Promise<void> {
  openRestartOverlay();
  const started = Date.now();
  while (Date.now() - started < UPDATE_LIMIT_MS) {
    await sleep(POLL_MS);
    let res: UpdateRes | null = null;
    let phase;
    try {
      res = await poll();
      phase = updatePhase(target, res);
    } catch (error) {
      if (unauthorized(error)) {
        settings.overlay = false;
        settings.restarting = false;
        update.installing = false;
        return;
      }
      phase =
        error instanceof HttpError
          ? updatePhase(target, null, error.status, error.message)
          : updatePhase(target, null);
    }
    settings.restartPhase = phase;
    if (phase === "back") {
      location.reload();
      return;
    }
    if (phase === "failed" && res) {
      generation++;
      update.res = res;
      settings.updateExit = res.result?.version === tag ? res.result.opkgExit : null;
      settings.restartFailure = "not-installed";
      settings.restarting = false;
      update.installing = false;
      return;
    }
  }
  settings.restartPhase = "failed";
  settings.restartFailure = "timeout";
  settings.restarting = false;
  update.installing = false;
}
