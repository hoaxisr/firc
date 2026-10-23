import { isSink } from "../../data/iface-choices";
import type { GroupLive } from "./live-state";

export type IfaceState = {
  name: string;
  state: "alive" | "dead" | "unknown";
  since: number;
  error: string;
};

const IFACES_MAX = 4;

export function ifaceList(group: { interface: string | string[] }): string[] {
  return Array.isArray(group.interface) ? [...group.interface] : [group.interface];
}

export function ifaceValue(list: string[]): string | string[] {
  return list.length === 1 ? list[0] : [...list];
}

export function canBackup(list: string[], name: string): boolean {
  if (isSink(name) || list.some(isSink)) return false;
  return list.includes(name) || list.length < IFACES_MAX;
}

export function toggleEntry(list: string[], name: string): string[] {
  if (!canBackup(list, name)) return [...list];
  if (!list.includes(name)) return [...list, name];
  return list.length <= 1 ? [...list] : list.filter((n) => n !== name);
}

export function entryNumber(list: string[], name: string): number | null {
  const i = list.indexOf(name);
  return i < 0 ? null : i + 1;
}

export function chainLabel(list: string[]): string {
  return list.join(" → ");
}

export type BackupNote = { active: string; first: string; since: number };

export function backupNote(list: string[], live: GroupLive | undefined): BackupNote | null {
  const active = live?.active;
  if (list.length < 2 || !active || active === list[0]) return null;
  if (live?.live === false && live.liveReason === "no-interface") return null;
  const first = live?.interfaces?.find((s) => s.name === list[0]);
  return { active, first: list[0], since: first?.since ?? 0 };
}

export function backupText(
  note: BackupNote,
  t: (key: string) => string,
  clock: (unix: number) => string,
): string {
  const text =
    note.since > 0
      ? t("Running on backup {active} · first {first} down since {time}").replace("{time}", () =>
          clock(note.since),
        )
      : t("Running on backup {active} · first {first} down");
  return text.replace("{active}", () => note.active).replace("{first}", () => note.first);
}
