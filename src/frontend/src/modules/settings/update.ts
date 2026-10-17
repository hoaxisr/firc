import type { RestartPhase } from "./settings";

export type UpdateState =
  | "idle"
  | "checking"
  | "downloading"
  | "verifying"
  | "installing"
  | "failed";

export type UpdateRelease = {
  version: string;
  revision: number;
  tag: string;
  publishedAt: string;
  notes: string;
  asset: { name: string; size: number } | null;
};

export type UpdateCheck = {
  checkedAt: number;
  ageS: number;
  latest: UpdateRelease | null;
  newer: boolean;
  installable: boolean;
  reason: string | null;
  error: string | null;
};

export type UpdateRes = {
  installed: { version: string; revision: number; target: string };
  canInstall: boolean;
  reason: string | null;
  check: UpdateCheck | null;
  state: UpdateState;
  progress: { bytes: number; total: number } | null;
  error: string | null;
  result: { version: string; opkgExit: number; finishedAt: number } | null;
};

export type RateLimited = { error?: string; resetAt?: number | null };

export const CHECK_MAX_AGE_S = 3600;
export const UPDATE_POLL_MS = 600_000;

export function needsCheck(res: UpdateRes | null): boolean {
  return res !== null && (res.check === null || res.check.ageS >= CHECK_MAX_AGE_S);
}

export function hasNewer(res: UpdateRes | null): boolean {
  return res?.check?.newer === true;
}

export function reasonText(reason: string | null, t: (key: string) => string): string {
  switch (reason) {
    case null:
      return "";
    case "no-target":
      return t("This build has no target to fetch a package for");
    case "unknown-version":
      return t("The version is not a release version (X.Y.Z)");
    case "dev-build":
      return t("A development build does not update itself");
    case "no-asset":
      return t("The release has no package for this router");
    case "many-assets":
      return t("The release has more than one package for this router");
    case "not-uploaded":
      return t("The release's package is not fully uploaded yet");
    case "no-digest":
      return t("The release's package has no checksum");
    case "bad-size":
      return t("The release's package has an implausible size");
    case "bad-url":
      return t("The release's package link is not the expected one");
    case "prerelease":
      return t("The latest release is a draft or a prerelease");
    default:
      return reason;
  }
}

export const UPDATE_LIMIT_MS = 300_000;

type Release = { version: string; revision: number };

const TAG = /^v?(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-rev(\d{1,9}))?$/;

export function tagRelease(tag: string): Release | null {
  const m = TAG.exec(tag);
  if (!m) return null;
  const revision = m[4] === undefined ? 1 : Number(m[4]);
  if (revision === 0) return null;
  return { version: [m[1], m[2], m[3]].map(Number).join("."), revision };
}

const sameRelease = (installed: Release, target: Release | null) =>
  target !== null && installed.version === target.version && installed.revision === target.revision;

export function landed(res: UpdateRes): boolean {
  return (
    res.result !== null &&
    res.result.opkgExit === 0 &&
    sameRelease(res.installed, tagRelease(res.result.version))
  );
}

const RELEASE = /^(\d{1,9})\.(\d{1,9})\.(\d{1,9})$/;

export function resultCurrent(res: UpdateRes): boolean {
  const target = res.result === null ? null : tagRelease(res.result.version);
  const installed = RELEASE.exec(res.installed.version);
  if (target === null || installed === null) return true;
  const have = [...installed.slice(1).map(Number), res.installed.revision];
  const want = [...target.version.split(".").map(Number), target.revision];
  const i = want.findIndex((n, k) => n !== have[k]);
  return i === -1 || want[i] > have[i];
}

export function running(res: UpdateRes | null): boolean {
  return res?.state === "downloading" || res?.state === "verifying" || res?.state === "installing";
}

function daemonBody(body: string | undefined): boolean {
  try {
    const parsed = JSON.parse(body ?? "") as { error?: unknown };
    return typeof parsed?.error === "string";
  } catch {
    return false;
  }
}

export function updatePhase(
  target: Release,
  res: UpdateRes | null,
  status?: number,
  body?: string,
): RestartPhase {
  if (status !== undefined)
    return status === 404 || (status === 503 && daemonBody(body)) ? "back" : "no-answer";
  if (res === null) return "no-answer";
  if (sameRelease(res.installed, target)) return "back";
  return res.state === "idle" || res.state === "failed" ? "failed" : "old-daemon";
}

export type UpdateStatus =
  | { kind: "running"; state: UpdateState; version: string; percent: number | null }
  | { kind: "checking" }
  | { kind: "install-failed"; error: string }
  | { kind: "not-installed"; version: string; code: number }
  | { kind: "check-failed"; error: string }
  | { kind: "newer"; version: string; offered: boolean }
  | { kind: "up-to-date"; minutes: number }
  | { kind: "unchecked" };

export function offered(res: UpdateRes | null): boolean {
  const check = res?.check;
  return !!res?.canInstall && !!check?.newer && !!check.installable && !!check.latest;
}

export function progressPercent(res: UpdateRes | null): number | null {
  return res?.progress && res.progress.total > 0
    ? Math.min(100, Math.floor((res.progress.bytes * 100) / res.progress.total))
    : null;
}

export function updateStatus(
  res: UpdateRes,
  ui: { checking: boolean; checkError: string },
): UpdateStatus {
  const check = res.check;
  if (running(res)) {
    return {
      kind: "running",
      state: res.state,
      version: check?.latest?.version ?? "",
      percent: progressPercent(res),
    };
  }
  if (ui.checking) return { kind: "checking" };
  if (res.state === "failed" && res.error) return { kind: "install-failed", error: res.error };
  if (res.result !== null && resultCurrent(res) && !landed(res)) {
    return { kind: "not-installed", version: res.result.version, code: res.result.opkgExit };
  }
  if (ui.checkError) return { kind: "check-failed", error: ui.checkError };
  if (check?.error) return { kind: "check-failed", error: check.error };
  if (check?.newer && check.latest) {
    return { kind: "newer", version: check.latest.version, offered: offered(res) };
  }
  if (check) return { kind: "up-to-date", minutes: Math.floor(check.ageS / 60) };
  return { kind: "unchecked" };
}

const RELEASES = "https://github.com/hoaxisr/firc/releases/";

const linkedRelease = (res: UpdateRes) => (res.check?.newer ? res.check.latest : null);

export function releaseLinkText(res: UpdateRes, t: (key: string) => string): string {
  const latest = linkedRelease(res);
  if (latest) return `${latest.version} · ${t("What's new")}`;
  if (!RELEASE.test(res.installed.version)) return t("All releases");
  return `${res.installed.version} · ${t("What's new")}`;
}

export function releaseUrl(res: UpdateRes): string {
  const latest = linkedRelease(res);
  if (latest) return RELEASES + "tag/" + latest.tag;
  const { version, revision } = res.installed;
  if (!RELEASE.test(version)) return RELEASES.slice(0, -1);
  return RELEASES + "tag/" + (revision > 1 ? `${version}-rev${revision}` : version);
}

export function runningText(
  state: UpdateState,
  version: string,
  t: (key: string) => string,
): string {
  if (state === "downloading")
    return t("Downloading {version}…").replace("{version}", () => version);
  return state === "verifying" ? t("Checking the package…") : t("Installing…");
}
