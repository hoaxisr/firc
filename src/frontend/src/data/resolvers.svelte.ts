import { type SystemResolvers } from "../types";
import { fetcher } from "../utils/fetcher";

export const resolvers = $state({
  list: [] as SystemResolvers["resolvers"],
});

export async function fetchResolvers() {
  try {
    const data = await fetcher.get<SystemResolvers>("/system/resolvers", { quiet: true });
    resolvers.list = data.resolvers ?? [];
  } catch {
    /* Keep the last list: an empty one would read as "the firmware has none". */
  }
}
