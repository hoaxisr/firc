import { fetcher } from "../utils/fetcher";

export type GroupRef = { id: string; name: string };

export const knownGroups = $state({
  list: [] as GroupRef[],
  loaded: false,
});

let pending: Promise<void> | null = null;

export function setKnownGroups(groups: GroupRef[]) {
  knownGroups.list = groups.map(({ id, name }) => ({ id, name }));
  knownGroups.loaded = true;
}

export function followGroupsLoad(request: Promise<GroupRef[]>) {
  const p: Promise<void> = request
    .then(setKnownGroups, () => {})
    .finally(() => {
      if (pending === p) pending = null;
    });
  pending = p;
}

export function ensureKnownGroups(): Promise<void> {
  if (knownGroups.loaded) return Promise.resolve();
  if (!pending) {
    followGroupsLoad(
      fetcher
        .get<{ groups?: GroupRef[] }>("/groups", { quiet: true })
        .then((data) => data?.groups ?? []),
    );
  }
  return pending ?? Promise.resolve();
}
