import { counted } from "../../utils/plural";

type WithId = { id: string };

/* A new array either way: a `$state` array only changes when reassigned. */
export function toggleId(ids: readonly string[], id: string): string[] {
  return ids.includes(id) ? ids.filter((value) => value !== id) : [...ids, id];
}

export function selectedInOrder(ids: readonly string[], groups: readonly WithId[]): string[] {
  if (!ids.length) return [];
  const wanted = new Set(ids);
  return groups.filter((group) => wanted.has(group.id)).map((group) => group.id);
}

export function selectableIds(
  groups: readonly WithId[],
  searchActive: boolean,
  visible: { has(index: number): boolean },
): string[] {
  return groups.filter((_, index) => !searchActive || visible.has(index)).map((group) => group.id);
}

export function selectionCountText(n: number, locale: string, t: (key: string) => string): string {
  return counted(
    n,
    locale,
    t("{n} group selected"),
    t("{n} groups selected (2-4)"),
    t("{n} groups selected"),
  );
}
