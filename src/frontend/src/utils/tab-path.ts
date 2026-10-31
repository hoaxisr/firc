const PATHS: Record<string, string> = {
  groups: "/groups",
  tunnels: "/tunnels",
  logs: "/journal",
  settings: "/settings",
};

export type JournalView = "events" | "stats" | "unopened" | "capture";

const JOURNAL_VIEWS: Record<JournalView, string> = {
  events: "/journal",
  stats: "/journal/stats",
  unopened: "/journal/unopened",
  capture: "/journal/capture",
};

export function pathOfTab(tab: string, view: JournalView = "events"): string {
  if (tab === "logs") return JOURNAL_VIEWS[view] ?? PATHS.logs;
  return PATHS[tab] ?? PATHS.groups;
}

export function journalViewFromPath(path: string): JournalView {
  const views = Object.keys(JOURNAL_VIEWS) as JournalView[];
  return views.find((v) => JOURNAL_VIEWS[v] === path) ?? "events";
}

export function tabFromPath(path: string): string {
  if (Object.values(JOURNAL_VIEWS).includes(path)) return "logs";
  return Object.keys(PATHS).find((tab) => PATHS[tab] === path) ?? "groups";
}
