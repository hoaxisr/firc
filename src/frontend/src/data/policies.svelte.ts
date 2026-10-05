import { fetcher } from "../utils/fetcher";

export type Policy = {
  name: string;
  description?: string;
  devices: number;
};

export const policies = $state({
  list: [] as Policy[],
  loaded: false,
});

export async function fetchPolicies(quiet = false) {
  try {
    const data = await fetcher.get<{ policies: Policy[] }>("/system/policies", { quiet });
    policies.list = data.policies ?? [];
  } catch (error) {
    console.error("Failed to fetch policies:", error);
    policies.list = [];
  } finally {
    policies.loaded = true;
  }
}
