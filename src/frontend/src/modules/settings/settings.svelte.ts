import { fetchInterfaces } from "../../data/interfaces.svelte";
import { t } from "../../data/locale.svelte";

import { toast } from "../../utils/events";
import { fetcher, HttpError } from "../../utils/fetcher";
import {
  changedKeys,
  followUrl,
  putBody,
  rebaseDraft,
  restartFailure,
  restartPhase,
  type PutRes,
  type RestartFailure,
  type RestartPhase,
  type SettingClass,
  type SettingsMap,
  type SettingsRes,
} from "./settings";

export const settings = $state({
  loaded: false,
  failed: false,
  saved: {} as SettingsMap,
  draft: {} as SettingsMap,
  classes: {} as Record<string, SettingClass>,
  pendingRestart: [] as string[],
  saving: false,
  /* The daemon's 400: which setting it refused, and why. */
  fieldError: null as { field: string; error: string } | null,
  restarting: false,
  restartPhase: "requested" as RestartPhase,
  restartStartedAt: 0,
  restartFailure: null as RestartFailure | null,
  overlay: false,
  boot: "",
});

export let generation = 0;
export const nextGeneration = () => ++generation;

const clone = (m: SettingsMap): SettingsMap => JSON.parse(JSON.stringify(m)) as SettingsMap;

export function take(res: SettingsRes) {
  settings.draft = rebaseDraft(settings.saved, settings.draft, res.settings);
  settings.saved = clone(res.settings);
  settings.classes = res.classes;
  settings.boot = res.boot;
  settings.pendingRestart = res.pendingRestart;
  settings.fieldError = null;
  settings.loaded = true;
  settings.failed = false;
}

export async function loadSettings(): Promise<void> {
  const gen = nextGeneration();
  try {
    const res = await fetcher.get<SettingsRes>("/system/settings", { quiet: true });
    if (gen !== generation) return;
    take(res);
  } catch (error) {
    if (gen !== generation) return;
    console.error("Failed to load settings:", error);
    settings.failed = true;
  }
}

export function resetDraft() {
  settings.draft = clone(settings.saved);
  settings.fieldError = null;
}

/* The daemon's own {error, field} on a 400, or null for anything else. */
function refusal(error: unknown): { field: string; error: string } | null {
  if (!(error instanceof HttpError) || error.status !== 400) return null;
  try {
    const body = JSON.parse(error.message) as { error?: string; field?: string };
    return { field: body.field ?? "", error: body.error ?? error.message };
  } catch {
    return { field: "", error: error.message };
  }
}

function reason(error: unknown): string {
  if (error instanceof HttpError) {
    try {
      const body = JSON.parse(error.message) as { error?: string };
      if (body.error) return body.error;
    } catch {
      /* not JSON */
    }
    return error.message;
  }
  return error instanceof Error ? error.message : String(error);
}

export async function saveSettings(): Promise<boolean> {
  const keys = changedKeys(settings.saved, settings.draft);
  if (keys.length === 0) return true;
  settings.saving = true;
  settings.fieldError = null;
  const gen = nextGeneration();
  try {
    const res = await fetcher.put<PutRes>("/system/settings", putBody(keys, settings.draft), {
      quiet: true,
    });
    if (gen !== generation) return false;
    for (const k of keys) settings.saved[k] = JSON.parse(JSON.stringify(settings.draft[k]));
    settings.pendingRestart = res.pendingRestart;
    if (res.applied.includes("app.showAllInterfaces")) void fetchInterfaces();
    toast.success(t("Settings saved"));
    return true;
  } catch (error) {
    if (gen !== generation) return false;
    const refused = refusal(error);
    if (refused) {
      settings.fieldError = refused;
      return false;
    }
    toast.error(`${t("Request failed")}: ${reason(error)}`);
    await refreshSaved();
    return false;
  } finally {
    settings.saving = false;
  }
}

async function refreshSaved(): Promise<void> {
  const gen = nextGeneration();
  try {
    const res = await fetcher.get<SettingsRes>("/system/settings", { quiet: true });
    if (gen !== generation) return;
    take(res);
  } catch (error) {
    console.error("Failed to re-read settings after a failed save:", error);
  }
}

const POLL_MS = 1000;
const POLL_TIMEOUT_MS = 3000;
/* S99firc gives a stop 60 s and a start 60 s; past both, it is not coming. */
export const restartLimit = { ms: 120_000 };
const OVERLAY_LINGER_MS = 800;
let lingerTimer: ReturnType<typeof setTimeout> | undefined;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForDaemon(bootBefore: string): Promise<void> {
  const started = Date.now();
  let sawPending = false;
  while (Date.now() - started < restartLimit.ms) {
    await sleep(POLL_MS);
    let res: SettingsRes | null = null;
    try {
      res = await fetcher.get<SettingsRes>("/system/settings", {
        quiet: true,
        signal: AbortSignal.timeout(POLL_TIMEOUT_MS),
      });
    } catch (error) {
      if (error instanceof Error && error.message === "Unauthorized") {
        settings.restarting = false;
        settings.overlay = false;
        return;
      }
      settings.restartPhase = "no-answer";
      continue;
    }
    const phase = restartPhase(bootBefore, res);
    if (phase === "old-daemon" && res.restarting) sawPending = true;
    settings.restartPhase = phase;
    if (phase === "back") {
      nextGeneration();
      take(res);
      settings.restarting = false;
      lingerTimer = setTimeout(() => {
        if (!settings.restarting) settings.overlay = false;
      }, OVERLAY_LINGER_MS);
      return;
    }
    if (phase === "failed") {
      settings.restartFailure = restartFailure(sawPending);
      settings.restarting = false;
      return;
    }
  }
  settings.restartPhase = "failed";
  settings.restartFailure = "timeout";
  settings.restarting = false;
}

export function closeRestartOverlay() {
  settings.overlay = false;
}

async function waitForPage(url: string): Promise<void> {
  settings.restartPhase = "moving";
  const started = Date.now();
  while (Date.now() - started < restartLimit.ms) {
    await sleep(POLL_MS);
    try {
      await fetch(url, {
        mode: "no-cors",
        cache: "no-store",
        signal: AbortSignal.timeout(POLL_TIMEOUT_MS),
      });
      location.assign(url);
      return;
    } catch {
      /* not up yet */
    }
  }
  settings.restartPhase = "failed";
  settings.restartFailure = "timeout";
  settings.restarting = false;
}

export async function restartDaemon(): Promise<void> {
  const target = followUrl(location, settings.saved, settings.pendingRestart);
  const bootBefore = settings.boot;
  clearTimeout(lingerTimer);
  settings.restarting = true;
  settings.restartPhase = "requested";
  settings.restartStartedAt = Date.now();
  settings.restartFailure = null;
  settings.overlay = true;
  try {
    await fetcher.post("/system/restart", undefined, { quiet: true });
  } catch (error) {
    if (!(error instanceof HttpError && error.status === 409)) {
      settings.restarting = false;
      settings.overlay = false;
      toast.error(`${t("Request failed")}: ${reason(error)}`);
      return;
    }
  }
  if (target !== null) {
    await waitForPage(target);
    return;
  }
  await waitForDaemon(bootBefore);
}
