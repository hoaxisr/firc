export type SettingValue = string | number | boolean | string[];
export type SettingsMap = Record<string, SettingValue>;
export type SettingClass = "live" | "restart";

export type SettingsRes = {
  settings: SettingsMap;
  classes: Record<string, SettingClass>;
  pendingRestart: string[];
  boot: string;
  restarting: boolean;
};

export type PutRes = { applied: string[]; pendingRestart: string[] };

export const WEB_PORT = "app.httpWeb.host.port";

export function sameValue(a: SettingValue | undefined, b: SettingValue | undefined): boolean {
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => v === b[i]);
  }
  return a === b;
}

export function changedKeys(saved: SettingsMap, draft: SettingsMap): string[] {
  return Object.keys(saved).filter((k) => k in draft && !sameValue(saved[k], draft[k]));
}

export function groupChanges(
  keys: string[],
  classes: Record<string, SettingClass>,
): { live: string[]; restart: string[] } {
  return {
    live: keys.filter((k) => classes[k] === "live"),
    restart: keys.filter((k) => classes[k] !== "live"),
  };
}

export function rebaseDraft(
  oldSaved: SettingsMap,
  draft: SettingsMap,
  newSaved: SettingsMap,
): SettingsMap {
  const edited = new Set(changedKeys(oldSaved, draft));
  const next = Object.fromEntries(
    Object.keys(newSaved).map((k) => [k, edited.has(k) ? draft[k] : newSaved[k]]),
  );
  return JSON.parse(JSON.stringify(next)) as SettingsMap;
}

export function putBody(keys: string[], draft: SettingsMap): { settings: SettingsMap } {
  return { settings: Object.fromEntries(keys.map((k) => [k, draft[k]])) };
}

export { pluralForm, type PluralForm } from "../../utils/plural";

export type RestartPhase = "requested" | "old-daemon" | "no-answer" | "back" | "failed" | "moving";

export type RestartFailure = "not-started" | "not-restarted" | "timeout";

export function restartPhase(bootBefore: string, res: SettingsRes | null): RestartPhase {
  if (res === null) return "no-answer";
  if (typeof res.boot !== "string") return "old-daemon";
  if (res.boot !== bootBefore) return "back";
  return res.restarting ? "old-daemon" : "failed";
}

export function restartFailure(sawPending: boolean): RestartFailure {
  return sawPending ? "not-restarted" : "not-started";
}

export function restartSettled(bootBefore: string, res: SettingsRes | null): boolean {
  return restartPhase(bootBefore, res) === "back";
}

export function followUrl(
  loc: { protocol: string; hostname: string; port: string; pathname: string },
  saved: SettingsMap,
  pending: string[],
): string | null {
  if (!pending.includes(WEB_PORT)) return null;
  const port = saved[WEB_PORT];
  if (typeof port !== "number") return null;
  const current = loc.port !== "" ? Number(loc.port) : loc.protocol === "https:" ? 443 : 80;
  if (port === current) return null;
  const host = loc.hostname.includes(":") ? `[${loc.hostname}]` : loc.hostname;
  return `${loc.protocol}//${host}:${port}${loc.pathname}`;
}
