import type { Host } from "../utils/device-picker";
import { fetcher } from "../utils/fetcher";

export type { Host };

export const hosts = $state({
  list: [] as Host[],
  loaded: false,
});

export async function fetchHosts() {
  try {
    const data = await fetcher.get<{ hosts: Host[] }>("/system/hosts", { quiet: true });
    hosts.list = data.hosts ?? [];
  } catch (error) {
    console.error("Failed to fetch hosts:", error);
    hosts.list = [];
  } finally {
    hosts.loaded = true;
  }
}
