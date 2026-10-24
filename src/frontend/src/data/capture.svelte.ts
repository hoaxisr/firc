import { persistedState } from "../utils/persisted-state.svelte";

import { fetcher, HttpError } from "../utils/fetcher";

export type CaptureLast = {
  startedAt: number;
  endedAt: number;
  ended: "reached-end" | "stopped" | "failed";
  leaks: number;
  summary: string[];
};

type CaptureRes = {
  running: boolean;
  endsAt?: number;
  secondsLeft?: number;
  token?: string;
  last?: CaptureLast;
};

export const CAPTURE_SECONDS = 300;

const mine = persistedState<{ token: string } | null>("capture_token", null);

export const capture = $state({
  running: false,
  endsAt: 0,
  secondsLeft: 0,
  last: null as CaptureLast | null,
  busy: false,
  failed: false,
  error: "",
  unsupported: "",
});

let generation = 0;

function reason(body: string): string {
  try {
    const parsed = JSON.parse(body) as { error?: string };
    if (typeof parsed.error === "string" && parsed.error !== "") return parsed.error;
  } catch {
    /* not JSON: a proxy in the way, or the daemon dying mid-answer */
  }
  return body;
}

function note(error: unknown) {
  if (error instanceof HttpError) {
    capture.failed = false;
    if (error.status === 501) {
      capture.unsupported = reason(error.message);
      capture.error = "";
      return;
    }
    capture.error = reason(error.message);
    return;
  }
  capture.failed = true;
  capture.error = "";
}

function take(data: CaptureRes, gen: number) {
  if (gen !== generation) return;
  capture.failed = false;
  capture.error = "";
  capture.running = data.running;
  capture.endsAt = data.endsAt ?? 0;
  capture.secondsLeft = data.secondsLeft ?? 0;
  capture.last = data.last ?? null;
  if (!data.running) mine.current = null;
}

export async function pollCapture(): Promise<void> {
  const gen = generation;
  try {
    const data = await fetcher.get<CaptureRes>("/system/capture", { quiet: true });
    take(data, gen);
  } catch (error) {
    if (gen !== generation) return;
    console.error("Failed to read the capture:", error);
    note(error);
  }
}

export async function startCapture(): Promise<void> {
  capture.busy = true;
  const gen = ++generation;
  try {
    const data = await fetcher.post<CaptureRes>("/system/capture", undefined, { quiet: true });
    if (gen !== generation) return;
    capture.unsupported = "";
    if (data.token) mine.current = { token: data.token };
    take(data, gen);
  } catch (error) {
    if (gen !== generation) return;
    console.error("Failed to start the capture:", error);
    note(error);
  } finally {
    capture.busy = false;
  }
}

export async function stopCapture(): Promise<void> {
  const held = mine.current;
  if (held === null) return;
  capture.busy = true;
  const gen = ++generation;
  try {
    const data = await fetcher.delete<CaptureRes>(
      `/system/capture?token=${encodeURIComponent(held.token)}`,
      { quiet: true },
    );
    if (gen !== generation) return;
    mine.current = null;
    take(data, gen);
  } catch (error) {
    if (gen !== generation) return;
    if (error instanceof HttpError && error.status === 409) mine.current = null;
    console.error("Failed to stop the capture:", error);
    note(error);
  } finally {
    capture.busy = false;
  }
}

export function isOurs(): boolean {
  return mine.current !== null && capture.running;
}
