import type { JournalView } from "../utils/tab-path";

export type TabRequest = {
  tab: "groups" | "settings" | "logs";
  search: string;
  view: JournalView | null;
  seq: number;
};

let current = $state<TabRequest | null>(null);
let seq = 0;

export const tabRequest = {
  get request() {
    return current;
  },
  open(tab: TabRequest["tab"], search = "", view: JournalView | null = null) {
    current = { tab, search, view, seq: ++seq };
  },
};
